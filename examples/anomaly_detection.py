"""
Sender-level anomaly detection for AI agent pipelines.

Problem: if an agent has learned that "alice@example.com" always generates
"read" actions, but a new message from alice suddenly triggers "reply_urgent"
with "send $50,000 wire transfer" — that is statistically anomalous. It may
indicate:
  - The sender's account was compromised
  - A prompt injection attack in the message body
  - A social engineering attempt

This module implements a lightweight statistical check: if the current
action for a sender represents less than ANOMALY_THRESHOLD of that sender's
historical action distribution, the agent should block autonomous execution
and queue the action for human review.

The check is intentionally simple (no ML, no external dependencies) so it
can run synchronously in any agent pipeline without added latency.

Limitations:
  - Requires MIN_HISTORY_FOR_DETECTION interactions before activating.
    New senders pass through unchecked.
  - A sophisticated attacker who can send many low-stakes messages first
    can shift the distribution. Combine with other controls.
  - The check is per-sender, not per-sender×action-type combination.
    Future versions could use a 2D distribution.

Usage:
    from anomaly_detection import check_sender_anomaly, MIN_HISTORY_FOR_DETECTION

    # Build a distribution from your DB or message history
    distribution = {"read": 45, "archive": 30, "reply_normal": 20, "reply_urgent": 5}

    is_anomalous = check_sender_anomaly(
        distribution=distribution,
        current_action="reply_urgent",
        sender="alice@example.com",
    )
    if is_anomalous:
        # Do not auto-execute; route to human review queue
        ...
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum number of historical interactions before anomaly detection fires.
# Below this threshold we have too little data to judge what is "normal",
# so we skip the check rather than false-positive on new senders.
MIN_HISTORY_FOR_DETECTION = 10

# If the current action represents less than this fraction of historical
# actions for this sender, flag it as anomalous.
# 5% means "this action has occurred less than 1 in 20 times".
ANOMALY_THRESHOLD = 0.05


# ---------------------------------------------------------------------------
# Detection function
# ---------------------------------------------------------------------------

def check_sender_anomaly(
    distribution: dict[str, int],
    current_action: str,
    sender: str = "unknown",
) -> bool:
    """
    Check whether current_action is statistically anomalous for this sender.

    Args:
        distribution: Historical action counts for the sender, e.g.
                      {"read": 45, "archive": 30, "reply_normal": 20}.
                      Keys are action type strings; values are counts.
        current_action: The action type the agent is about to execute.
        sender: Sender identifier (email address, user ID, etc.) — used
                only in log messages for traceability.

    Returns:
        True if the action is anomalous and should be blocked from
        autonomous execution; False if within normal range or not enough
        history exists.
    """
    if not current_action:
        return False

    total = sum(distribution.values())

    # Not enough history — skip the check
    if total < MIN_HISTORY_FOR_DETECTION:
        logger.debug(
            "Anomaly check skipped for '%s': only %d interactions (need %d)",
            sender, total, MIN_HISTORY_FOR_DETECTION,
        )
        return False

    count_for_action = distribution.get(current_action, 0)
    fraction = count_for_action / total

    if fraction < ANOMALY_THRESHOLD:
        logger.warning(
            "Sender anomaly detected: sender='%s' action='%s' "
            "fraction=%.1f%% (threshold=%.0f%%)",
            sender, current_action, fraction * 100, ANOMALY_THRESHOLD * 100,
        )
        return True

    logger.debug(
        "No anomaly for sender='%s' action='%s' fraction=%.1f%%",
        sender, current_action, fraction * 100,
    )
    return False


def describe_distribution(distribution: dict[str, int]) -> str:
    """
    Return a human-readable summary of an action distribution.

    Useful for logging the context when an anomaly is detected.
    """
    total = sum(distribution.values())
    if total == 0:
        return "no history"

    parts = []
    for action, count in sorted(distribution.items(), key=lambda x: -x[1]):
        pct = count / total * 100
        parts.append(f"{action}={count} ({pct:.0f}%)")
    return f"total={total} [{', '.join(parts)}]"


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    print("=== Anomaly detection demo ===\n")

    # Representative distribution for an established sender
    typical_distribution = {
        "read": 45,
        "archive": 30,
        "reply_normal": 20,
        "reply_urgent": 4,
        "action_required": 1,
    }

    test_cases = [
        # (action, expected_anomaly, description)
        ("read",           False, "Most common action — should pass"),
        ("archive",        False, "Common action — should pass"),
        ("reply_normal",   False, "Moderately common — should pass"),
        ("reply_urgent",   True,  "4% — below 5% threshold, anomalous"),
        ("action_required",True,  "1% — well below 5% threshold"),
        ("wire_transfer",  True,  "Never seen before — fraction=0%"),
    ]

    print(f"Distribution: {describe_distribution(typical_distribution)}\n")

    for action, expected, desc in test_cases:
        result = check_sender_anomaly(
            distribution=typical_distribution,
            current_action=action,
            sender="alice@example.com",
        )
        status = "ANOMALOUS" if result else "normal   "
        match = "OK" if result == expected else "UNEXPECTED"
        print(f"  [{match}] {status}  action='{action}' — {desc}")

    print()

    # Edge case: not enough history
    print("Edge case — new sender with only 5 interactions:")
    sparse = {"read": 3, "archive": 2}
    result = check_sender_anomaly(sparse, "wire_transfer", "newuser@example.com")
    print(f"  wire_transfer anomalous: {result}  (expected False — insufficient history)")

    print()

    # Edge case: empty distribution
    print("Edge case — no history at all:")
    result = check_sender_anomaly({}, "reply_urgent", "nobody@example.com")
    print(f"  reply_urgent anomalous: {result}  (expected False)")
