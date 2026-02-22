"""
Trust graduation system for AI agents with autonomy levels.

Agents that auto-act on behalf of users (send emails, submit forms, approve
requests) should not start at full autonomy. This module implements a
progressive trust model where autonomy is earned through demonstrated
performance — and revoked if performance degrades.

Autonomy levels (lowest → highest):
  approval_required  — every action needs explicit human approval
  supervised         — actions execute but are logged and reviewable
  autonomous         — actions execute silently

Graduation rules (approval_required → supervised):
  - At least N drafts/actions attempted (volume gate)
  - Edit rate below X% (quality gate: how often humans correct the agent)
  - Send/approval rate above Y% (acceptance gate)
  - At least D days of tracking history (time gate: prevents gaming)

Graduation rules (supervised → autonomous):
  - At least M auto-executed actions since entering supervised
  - At least K days in supervised without a flagged issue
  - Zero issues recorded in the window

Demotion:
  If windowed metrics fall below the graduation floor (using a multiplier
  to add hysteresis), the category is demoted back to approval_required.
  Demotions are checked before graduations on every cycle.

This module is self-contained — the "database" is a plain dict so you can
run the examples without any infrastructure.

Usage:
    from trust_graduation import GraduationThresholds, GraduationManager
    from trust_graduation import InMemoryMetricsStore

    store = InMemoryMetricsStore()
    store.upsert("email_replies", total_drafts=25, send_rate=0.87,
                 avg_edit_distance=0.12, days_active=10)

    mgr = GraduationManager(store)
    new_level = mgr.check_graduation("email_replies")
    if new_level:
        mgr.graduate("email_replies", new_level)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

AUTONOMY_LEVELS = ["approval_required", "supervised", "autonomous"]


@dataclass
class GraduationThresholds:
    """Configuration for all graduation and demotion thresholds."""

    # approval_required → supervised
    approval_to_supervised_min_drafts: int = 20
    """Minimum number of completed drafts/actions before considering graduation."""

    approval_to_supervised_max_edit_rate: float = 0.20
    """Maximum acceptable edit distance (0.0 = never edited, 1.0 = always rewritten)."""

    approval_to_supervised_min_send_rate: float = 0.80
    """Minimum fraction of drafts that were sent/approved without being discarded."""

    # supervised → autonomous
    supervised_to_autonomous_min_auto_sent: int = 50
    """Auto-executed actions required since entering supervised mode."""

    supervised_to_autonomous_days_without_issues: int = 14
    """Consecutive days in supervised with zero issues before autonomous is granted."""

    # Time gate
    min_days_before_graduation: int = 7
    """Minimum calendar days of tracking history before any graduation is possible."""

    # Decay / windowing
    decay_window_days: int = 90
    """Only count activity within this rolling window for graduation/demotion checks.
    Set to 0 to use all-time totals (not recommended for long-running agents)."""


# ---------------------------------------------------------------------------
# In-memory metrics store — replace with your real persistence layer
# ---------------------------------------------------------------------------

@dataclass
class CategoryMetrics:
    """Snapshot of trust metrics for one category."""
    category: str
    current_autonomy: str = "approval_required"
    total_drafts: int = 0
    send_rate: float = 0.0
    avg_edit_distance: float = 1.0
    first_draft_at: datetime | None = None
    graduated_at: datetime | None = None
    # Windowed stats — populated by get_windowed_stats()
    windowed_total: int = 0
    windowed_send_rate: float = 0.0
    windowed_avg_edit: float = 1.0
    # Issue tracking — any human-flagged problem
    issues_since_graduation: int = 0
    auto_sent_since_graduation: int = 0


class InMemoryMetricsStore:
    """
    Dict-backed metrics store for standalone use and testing.

    In production, replace this with queries to your actual database
    and keep the same interface so GraduationManager doesn't need to change.
    """

    def __init__(self):
        self._data: dict[str, CategoryMetrics] = {}

    def get(self, category: str) -> CategoryMetrics | None:
        return self._data.get(category)

    def upsert(self, category: str, **kwargs) -> None:
        """Create or update metrics for a category."""
        if category not in self._data:
            self._data[category] = CategoryMetrics(category=category)
        m = self._data[category]
        for k, v in kwargs.items():
            if hasattr(m, k):
                setattr(m, k, v)
            else:
                raise ValueError(f"Unknown metric field: {k}")

    def all(self) -> list[CategoryMetrics]:
        return list(self._data.values())


# ---------------------------------------------------------------------------
# Graduation manager
# ---------------------------------------------------------------------------

class GraduationManager:
    """
    Evaluates trust metrics and promotes/demotes autonomy levels.

    Demotions are always checked before graduations on each cycle.
    This ensures safety takes priority: a category that is both
    eligible for promotion and overdue for demotion will be demoted.
    """

    def __init__(
        self,
        store: InMemoryMetricsStore,
        thresholds: GraduationThresholds | None = None,
    ):
        self.store = store
        self.thresholds = thresholds or GraduationThresholds()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_graduation(self, category: str) -> str | None:
        """
        Check whether a category should graduate to the next autonomy level.

        Args:
            category: Category identifier (e.g. "email_replies")

        Returns:
            Target autonomy level string if graduation is warranted, else None.
        """
        metrics = self.store.get(category)
        if not metrics:
            return None

        current = metrics.current_autonomy

        if current == "approval_required":
            if self._can_reach_supervised(metrics):
                return "supervised"
        elif current == "supervised":
            if self._can_reach_autonomous(metrics):
                return "autonomous"

        return None

    def graduate(self, category: str, new_level: str) -> None:
        """
        Execute a graduation: persist the new level and record the timestamp.

        Args:
            category: Category to promote
            new_level: Target autonomy level
        """
        if new_level not in AUTONOMY_LEVELS:
            raise ValueError(f"Invalid autonomy level: {new_level}")

        self.store.upsert(
            category,
            current_autonomy=new_level,
            graduated_at=datetime.now(),
        )
        logger.info("Graduated '%s' → %s", category, new_level)

    def check_demotion(self, category: str) -> str | None:
        """
        Check whether a category should be demoted due to degraded metrics.

        A demotion multiplier (1.5× the edit cap, 0.5× the send floor)
        provides hysteresis so minor fluctuations don't oscillate the level.

        Args:
            category: Category to inspect

        Returns:
            "approval_required" if demotion is warranted, else None.
        """
        metrics = self.store.get(category)
        if not metrics:
            return None

        if metrics.current_autonomy == "approval_required":
            return None  # Already at the floor

        t = self.thresholds
        if t.decay_window_days <= 0:
            return None

        # Use windowed stats for demotion decisions
        total = metrics.windowed_total
        if total < 5:
            return None  # Not enough recent data to demote

        avg_edit = metrics.windowed_avg_edit
        send_rate = metrics.windowed_send_rate

        # Hysteresis: thresholds are relaxed so a single bad week doesn't
        # trigger demotion, but sustained degradation does.
        edit_ceiling = t.approval_to_supervised_max_edit_rate * 1.5
        send_floor = t.approval_to_supervised_min_send_rate * 0.5

        if avg_edit > edit_ceiling or send_rate < send_floor:
            logger.warning(
                "Demotion triggered for '%s': edit=%.2f (ceil=%.2f), "
                "send_rate=%.2f (floor=%.2f)",
                category, avg_edit, edit_ceiling, send_rate, send_floor,
            )
            return "approval_required"

        return None

    def demote(self, category: str, new_level: str) -> None:
        """
        Execute a demotion: persist the lower autonomy level.

        Args:
            category: Category to demote
            new_level: Lower autonomy level
        """
        self.store.upsert(category, current_autonomy=new_level)
        logger.warning("Demoted '%s' → %s", category, new_level)

    def check_all(self) -> dict[str, str]:
        """
        Run demotion and graduation checks across all tracked categories.

        Returns:
            Dict of {category: new_level} for every category whose level changed.
        """
        changed = {}
        for metrics in self.store.all():
            cat = metrics.category

            # Safety first: demotions before promotions
            demote_to = self.check_demotion(cat)
            if demote_to:
                self.demote(cat, demote_to)
                changed[cat] = demote_to
                continue

            grad_to = self.check_graduation(cat)
            if grad_to:
                self.graduate(cat, grad_to)
                changed[cat] = grad_to

        return changed

    def get_level(self, category: str) -> str:
        """Return current autonomy level, defaulting to approval_required."""
        metrics = self.store.get(category)
        return metrics.current_autonomy if metrics else "approval_required"

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _can_reach_supervised(self, metrics: CategoryMetrics) -> bool:
        t = self.thresholds

        # Time gate
        if not metrics.first_draft_at:
            logger.debug("'%s': no first_draft_at, cannot graduate", metrics.category)
            return False

        days_active = (datetime.now() - metrics.first_draft_at).days
        if days_active < t.min_days_before_graduation:
            logger.debug(
                "'%s': only %d days active, need %d",
                metrics.category, days_active, t.min_days_before_graduation,
            )
            return False

        # Use windowed stats when available
        if t.decay_window_days > 0 and metrics.windowed_total > 0:
            total = metrics.windowed_total
            avg_edit = metrics.windowed_avg_edit
            send_rate = metrics.windowed_send_rate
        else:
            total = metrics.total_drafts
            avg_edit = metrics.avg_edit_distance
            send_rate = metrics.send_rate

        result = (
            total >= t.approval_to_supervised_min_drafts
            and avg_edit <= t.approval_to_supervised_max_edit_rate
            and send_rate >= t.approval_to_supervised_min_send_rate
        )

        if result:
            logger.info(
                "'%s' ready for supervised: drafts=%d, edit=%.2f, send_rate=%.2f",
                metrics.category, total, avg_edit, send_rate,
            )
        return result

    def _can_reach_autonomous(self, metrics: CategoryMetrics) -> bool:
        t = self.thresholds

        if not metrics.graduated_at:
            return False

        days_since = (datetime.now() - metrics.graduated_at).days
        auto_sent = metrics.auto_sent_since_graduation
        issues = metrics.issues_since_graduation

        result = (
            auto_sent >= t.supervised_to_autonomous_min_auto_sent
            and days_since >= t.supervised_to_autonomous_days_without_issues
            and issues == 0
        )

        if result:
            logger.info(
                "'%s' ready for autonomous: auto_sent=%d, days=%d, issues=%d",
                metrics.category, auto_sent, days_since, issues,
            )
        return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    store = InMemoryMetricsStore()
    mgr = GraduationManager(store)

    print("=== Trust graduation demo ===\n")

    # Category 1: not enough history yet
    store.upsert(
        "calendar_invites",
        total_drafts=5,
        send_rate=0.90,
        avg_edit_distance=0.05,
        first_draft_at=datetime.now() - timedelta(days=3),  # only 3 days
    )
    level = mgr.check_graduation("calendar_invites")
    print(f"calendar_invites: graduation → {level or 'none (time gate)'}")

    # Category 2: ready for supervised
    store.upsert(
        "meeting_summaries",
        total_drafts=30,
        send_rate=0.88,
        avg_edit_distance=0.10,
        first_draft_at=datetime.now() - timedelta(days=14),
        windowed_total=28,
        windowed_send_rate=0.88,
        windowed_avg_edit=0.10,
    )
    level = mgr.check_graduation("meeting_summaries")
    print(f"meeting_summaries: graduation → {level or 'none'}")
    if level:
        mgr.graduate("meeting_summaries", level)

    # Category 3: supervised, metrics degrade → demotion
    store.upsert(
        "email_replies",
        current_autonomy="supervised",
        windowed_total=20,
        windowed_send_rate=0.30,   # well below 80% floor * 0.5 = 40%
        windowed_avg_edit=0.50,    # well above 20% cap * 1.5 = 30%
        graduated_at=datetime.now() - timedelta(days=5),
    )
    demote_to = mgr.check_demotion("email_replies")
    print(f"email_replies:    demotion → {demote_to or 'none'}")
    if demote_to:
        mgr.demote("email_replies", demote_to)

    print()
    print("Final levels:")
    for m in store.all():
        print(f"  {m.category}: {m.current_autonomy}")
