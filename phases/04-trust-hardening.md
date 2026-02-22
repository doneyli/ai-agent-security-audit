# Phase 4: Trust Hardening

## What you're checking

The integrity of any trust or reputation system your agent uses to weight inputs, prioritize sources, or make access decisions. If your agent treats certain users, data sources, or prior interactions as more credible than others, this phase verifies that the trust system itself cannot be manipulated into granting undeserved elevation.

## Why it matters

Trust systems are an attractive attack target because they are often treated as business logic rather than security-critical code. An attacker does not need to break encryption or bypass authentication if they can slowly cultivate trust through benign interactions, then use elevated trust to trigger privileged operations.

The attack pattern is patient and hard to detect in real time: establish trust through a series of normal-looking interactions, then exploit it. Systems that weight recent interactions heavily, that lack velocity checks, or that fail to use atomic operations for score updates are especially vulnerable. Organizations with over-privileged AI systems experienced a 4.5x higher incident rate than those enforcing least-privilege (Teleport, Feb 2026). Trust manipulation is one of the mechanisms that creates over-privilege at runtime, even when the initial configuration looked correct.

## Checklist

- [ ] Implement diversity gates: no single source, user, or data channel should contribute more than a defined maximum percentage to any trust or weighting calculation
- [ ] Add cooling periods for new trust signals: a minimum of 48 hours before a new source can accumulate meaningful trust weight
- [ ] Use atomic operations for all trust score reads and writes to prevent race conditions
- [ ] Test race conditions in trust update paths: submit concurrent updates and verify the final score is consistent and correct
- [ ] Implement trust score bounds: define a minimum and maximum, and verify scores cannot exceed them regardless of input volume
- [ ] Add anomaly detection on trust score changes: flag large or rapid changes for review
- [ ] Implement trust decay for stale signals: trust accumulated from interactions older than a defined threshold should decrease over time
- [ ] Test trust score rollback: verify you can revert a trust score to a prior state if manipulation is detected
- [ ] Audit what actions or permissions are gated on trust thresholds: these are the targets an attacker would aim to reach

## How to test

**Trust cultivation simulation:**
Submit a series of benign interactions at high volume over a short period and observe whether the trust score rises faster than your cooling period should allow. If a new source can reach a high-trust threshold in under 48 hours through volume alone, the cooling period is not enforced correctly.

**Diversity gate test:**
Configure one source to be the sole input for a trust calculation and verify that it cannot push the score beyond your defined maximum contribution ceiling, regardless of interaction count or quality signals.

**Race condition test:**
Submit concurrent trust update requests for the same entity and verify the resulting score equals exactly one of the valid outcomes — not an inconsistent intermediate state or an inflated value that reflects both updates additively.

```python
import threading
import requests

def submit_trust_update(entity_id, score_delta):
    # Submit trust update via your agent's internal API
    requests.post("/internal/trust/update", json={
        "entity": entity_id,
        "delta": score_delta
    })

# Submit two concurrent updates and verify final score
threads = [
    threading.Thread(target=submit_trust_update, args=("user_123", 10)),
    threading.Thread(target=submit_trust_update, args=("user_123", 10)),
]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Query final score — should be +10 (atomic) not +20 (double-apply)
```

**Bounds test:**
Push trust score inputs beyond your defined maximum. Verify the score does not exceed the ceiling regardless of how many updates are submitted.

**Decay test:**
Set a signal timestamp to a date beyond your stale threshold and verify the associated trust contribution is reduced in the next calculation cycle.

## Example vulnerability

An agent's trust system weighted recent interactions heavily to prioritize responsive, engaged sources. An attacker identified a low-friction input channel and submitted 20 benign, well-formed interactions over two hours. The interactions were legitimate in content — no policy violations, no suspicious patterns in any individual message.

After establishing an elevated trust score, the attacker submitted a request that would normally require higher authorization. The trust system evaluated the score against the threshold and granted access. No cooling period existed. No velocity check flagged the interaction rate. The trust score was not bounded against rapid accumulation.

The fix required three changes: a minimum 48-hour cooling period before any source's trust contribution becomes active, a velocity cap limiting the rate at which trust can accumulate within a rolling window, and a maximum contribution ceiling so no single source could reach a decision-relevant threshold through volume alone.

## Tools

- **Locust** (https://locust.io) — load testing framework useful for simulating high-volume trust signal submission and testing velocity controls
- **pytest-race** / custom threading tests — for race condition validation in trust update paths (no single established tool; write targeted tests)
- **Redis with atomic operations** (https://redis.io/docs/latest/develop/use/patterns/distributed-locks/) — if you are using a cache layer for trust scores, Redis MULTI/EXEC or Lua scripts enforce atomicity
- **Apache JMeter** (https://jmeter.apache.org) — alternative to Locust for concurrent request testing against trust update endpoints
