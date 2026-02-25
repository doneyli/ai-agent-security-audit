# AI Agent Security Audit Checklist

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A 5-phase framework for auditing AI agent security. Born from a real audit that found 18 vulnerabilities.**

> **Building with AI agents?** Subscribe to [Signal over Noise](https://doneyli.substack.com/) — weekly frameworks for production AI systems, including security patterns you won't find in docs. From 20+ years of building enterprise AI.

---

## Quick Start

1. Fork this repository
2. Copy `checklist.md` into your project or audit workspace
3. Work through the 5 phases in order
4. Check off items as you complete them
5. Budget roughly 30 minutes per phase for a first pass

No tooling required to get started. The checklist is a flat Markdown file designed to be forked and owned.

---

## Why This Exists

In February 2026, Teleport published a report finding that **88% of enterprises had a confirmed or suspected AI agent security incident in the past year**. Organizations with over-privileged AI systems experienced a **4.5x higher incident rate** than those enforcing least-privilege access. Perhaps most striking: **70% of AI systems have more access rights than a human in the same role**.

At the same time, NIST launched its AI Agent Standards Initiative, signaling that compliance expectations for production agent deployments are tightening. Microsoft reports that 80% of Fortune 500 companies are already running active AI agents. The Model Context Protocol (MCP) has crossed 97 million SDK downloads.

The gap between agent deployment and agent security is the widest it has ever been. Only 14.4% of organizations have full security approval for their agent fleet.

This checklist was born from a personal audit of a production AI agent — one that managed email, scheduling, project tracking, and file operations. The audit found 18 vulnerabilities: 4 critical, 6 high, 7 medium, 1 low. The most dangerous was a design failure: every state-changing action executed without human confirmation.

The 5-phase framework here is the remediation methodology that came out of that audit.

---

## The 5-Phase Framework

| Phase | Focus | Key Checks | Reference |
|-------|-------|------------|-----------|
| 1. Stop the Bleeding | Human-in-the-loop gates | State-changing action approval, permission scope, least-privilege enforcement | [phases/01-stop-the-bleeding.md](phases/01-stop-the-bleeding.md) |
| 2. Prompt Injection Defense | Input hardening | Unicode/homoglyph bypasses, invisible characters, system prompt leakage, adversarial payloads | [phases/02-prompt-injection.md](phases/02-prompt-injection.md) |
| 3. Defense in Depth | Memory and data integrity | Memory poisoning prevention, SQL injection on structured queries, input validation at every boundary | [phases/03-defense-in-depth.md](phases/03-defense-in-depth.md) |
| 4. Trust Hardening | Trust model robustness | Diversity gates, cooling periods for new signals, atomic token operations, race condition prevention | [phases/04-trust-hardening.md](phases/04-trust-hardening.md) |
| 5. Observability | Audit trail completeness | Decision logging, action logging, input logging, security event instrumentation, forensic readiness | [phases/05-observability.md](phases/05-observability.md) |

Run phases in order. Phase 1 blocks the highest-severity attack vectors first.

---

## Adversarial Test Cases

The `adversarial-tests/` directory contains prompt injection payloads, encoding bypass attempts, and trust manipulation scenarios you can use to test your agent's defenses.

See [adversarial-tests/](adversarial-tests/) for the full collection.

---

## Tools Referenced

| Tool | Purpose | Link |
|------|---------|------|
| Garak | LLM vulnerability scanner (automated adversarial testing) | https://github.com/NVIDIA/garak |
| PyRIT | Python Risk Identification Toolkit for AI systems | https://github.com/Azure/PyRIT |
| Langfuse | Open-source LLM observability and tracing | https://langfuse.com |
| LangSmith | LLM tracing and evaluation platform | https://smith.langchain.com |
| Helicone | LLM observability with security event support | https://www.helicone.ai |
| ClickHouse | Columnar database for high-throughput log storage and SQL-based forensic queries | https://clickhouse.com |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add attack vectors, test cases, or tool recommendations.

---

## Resources

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS: Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf)
- [NIST AI Agent Standards Initiative (Feb 2026)](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure)
- [Google Secure AI Framework (SAIF)](https://safety.google/cybersecurity-advancements/saif/)
- [Teleport: State of AI in Enterprise Infrastructure Security (Feb 2026)](https://www.globenewswire.com/news-release/2026/02/17/3239200/0/en/New-Teleport-Research-Reveals-AI-Security-Crisis-in-the-Enterprise-Over-Privileged-AI-Systems-Drive-4.5x-Higher-Incident-Rates.html)

---

## Next Steps

Found vulnerabilities in your agents? Here's how to go deeper:

- **[Subscribe to Signal over Noise](https://doneyli.substack.com/)** — Weekly AI security patterns, implementation frameworks, and "I Built X" tutorials
- **[Take the AI Readiness Quiz](https://doneyli.substack.com/)** — 5 questions, 2 minutes. See where your team stands on AI implementation readiness *(coming soon)*
- **[Read: 18 Vulnerabilities Found in 4 Hours](https://doneyli.substack.com/)** — The newsletter deep-dive on what this audit uncovered

## About the Author

**Don De Jesus** — Principal AI Architect at ClickHouse. 20+ years building data and AI systems at Deutsche Bank, Verizon, Cloudera, Elastic, and Snowflake. I build AI security frameworks because I've seen what happens when teams skip the audit.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://www.linkedin.com/in/doneyli/)
[![Substack](https://img.shields.io/badge/Substack-Subscribe-orange)](https://doneyli.substack.com/)

---

## License

MIT License. See [LICENSE](LICENSE).
