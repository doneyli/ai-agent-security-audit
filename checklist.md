# AI Agent Security Audit Checklist

> Fork this repo and check items as you complete your audit. Work through phases in order — Phase 1 addresses the highest-severity vulnerabilities first.

---

## Phase 1: Stop the Bleeding — Human-in-the-Loop Gates

- [ ] List every action your agent can take that modifies external state (send email, create calendar event, write file, execute query, call API with side effects)
- [ ] Add explicit human confirmation gates to every state-changing action before shipping to production
- [ ] Apply least-privilege access: revoke permissions your agent does not actively use
- [ ] Confirm your agent cannot execute a chain of state-changing actions without at least one human checkpoint
- [ ] Document the maximum blast radius if your agent is compromised — what can it touch?
- [ ] Verify that permission scope is narrower than any human in an equivalent role
- [ ] Test that human-in-the-loop gates cannot be bypassed via prompt injection (see Phase 2)

---

## Phase 2: Prompt Injection Defense

- [ ] Test inputs containing Unicode homoglyphs (look-alike characters that evade string matching)
- [ ] Test inputs containing invisible Unicode characters (zero-width spaces, directional overrides)
- [ ] Test inputs containing encoded payloads (base64, URL encoding, HTML entities)
- [ ] Attempt system prompt extraction: ask the agent to repeat, summarize, or translate its instructions
- [ ] Test instruction injection via external data sources (emails, documents, database content) that the agent reads
- [ ] Run automated adversarial testing with Garak or PyRIT against your agent's endpoints
- [ ] Confirm your content filters operate on decoded, normalized text — not raw input
- [ ] Add system prompt leakage detection and log any extraction attempts

---

## Phase 3: Defense in Depth

- [ ] Audit every path where external content can enter your agent's memory store
- [ ] Test for memory poisoning: inject crafted content and verify it cannot alter the agent's persistent behavior
- [ ] Apply parameterized queries or equivalent on all structured data operations — no string interpolation with agent-derived values
- [ ] Validate inputs at every trust boundary, not just the entry point (API gateway, UI, webhook, tool output)
- [ ] Confirm tool outputs are treated as untrusted data before being passed back into the agent's context
- [ ] Test for indirect prompt injection via third-party tool responses (search results, calendar data, email content)
- [ ] Verify that sanitization cannot be bypassed by double-encoding or nested encoding schemes

---

## Phase 4: Trust Hardening

- [ ] If your agent uses trust or reputation scores, document every source that can influence them
- [ ] Add diversity gates: no single source should be able to dominate trust score calculations
- [ ] Enforce minimum cooling periods (48 hours recommended) before new trust signals affect agent behavior
- [ ] Audit token handling for race conditions — use atomic operations where multiple processes share state
- [ ] Confirm that trust signals from agent-readable external sources (email, documents) are weighted appropriately
- [ ] Test that a malicious actor controlling one data source cannot escalate trust unilaterally
- [ ] Add rate limits on sensitive operations to limit damage from a compromised trust boundary
- [ ] Review and test rollback procedures if trust data is poisoned

---

## Phase 5: Observability

- [ ] Confirm every agent decision is logged with: timestamp, input, reasoning summary, and output
- [ ] Confirm every state-changing action is logged with: what was changed, who initiated it, and approval status
- [ ] Log all rejected inputs and blocked actions — these are your earliest attack signal
- [ ] Extend traces to include security events: permission checks, approval flows, anomalous inputs
- [ ] Verify logs are written to an append-only or tamper-evident store (not a location the agent can modify)
- [ ] Test that your logs contain enough detail to reconstruct a full incident timeline post-hoc
- [ ] Set up alerting on anomalous patterns: high rejection rates, unusual action sequences, off-hours activity
- [ ] Review your observability stack (Langfuse, LangSmith, Helicone, or equivalent) for coverage gaps

---

## Audit Summary

After completing all phases, record your findings:

- Total vulnerabilities found: ___
- Critical: ___ | High: ___ | Medium: ___ | Low: ___
- Phase 1 gates added: ___
- Security tests written: ___
- Remaining open items: ___

Ship a security test for every vulnerability you close. Your test suite is the guarantee that fixed issues stay fixed.
