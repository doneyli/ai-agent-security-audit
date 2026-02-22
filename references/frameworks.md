# Security Frameworks and References

A curated list of frameworks, standards, and resources for AI agent security.

---

## Standards and Frameworks

### OWASP Top 10 for LLM Applications

The most widely adopted classification of LLM-specific vulnerabilities. Covers prompt injection, insecure output handling, training data poisoning, model denial of service, supply chain vulnerabilities, and more.

- Website: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- GitHub: https://github.com/OWASP/www-project-top-10-for-large-language-model-applications

### MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

A knowledge base of adversarial tactics and techniques against AI systems. Modeled after MITRE ATT&CK, it maps real-world attack patterns against ML and AI systems.

- Website: https://atlas.mitre.org/
- Matrices: https://atlas.mitre.org/matrices/ATLAS

### NIST AI Risk Management Framework (AI RMF)

A voluntary framework for managing AI risks across the AI lifecycle. Provides a structured approach to identifying, assessing, and mitigating AI-related risks.

- Website: https://www.nist.gov/artificial-intelligence/ai-risk-management-framework
- AI Agent Standards Initiative (Feb 2026): https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure

### Google Secure AI Framework (SAIF)

Google's conceptual framework for securing AI systems. Covers six core elements: expanding security foundations to AI, extending detection and response, automating defenses, harmonizing platform-level controls, adapting controls for AI, and contextualizing AI system risks.

- Website: https://safety.google/cybersecurity-advancements/saif/

---

## Testing Tools

### NVIDIA Garak

LLM vulnerability scanner. Probes for prompt injection, data leakage, hallucination, and other LLM-specific vulnerabilities. Supports multiple model providers.

- GitHub: https://github.com/NVIDIA/garak
- Documentation: https://docs.garak.ai/

### Microsoft PyRIT (Python Risk Identification Toolkit)

An open-source framework for red-teaming generative AI systems. Automates adversarial prompt generation and evaluates model responses against safety criteria.

- GitHub: https://github.com/Azure/PyRIT

### Rebuff

A self-hardening prompt injection detector. Uses a multi-layered approach combining heuristics, LLM-based detection, and a vector database of known attacks.

- GitHub: https://github.com/protectai/rebuff

---

## Observability Platforms

### Langfuse

Open-source LLM observability platform. Provides tracing, evaluation, and prompt management for LLM applications. Self-hostable.

- Website: https://langfuse.com
- GitHub: https://github.com/langfuse/langfuse

### LangSmith

Tracing, evaluation, and monitoring platform from LangChain. Captures full execution traces of LLM chains and agents.

- Website: https://smith.langchain.com

### Helicone

Open-source LLM observability platform with a focus on cost tracking, latency monitoring, and request logging.

- Website: https://helicone.ai
- GitHub: https://github.com/Helicone/helicone

---

## Log Storage and Analytics

### ClickHouse

High-performance columnar database built for real-time analytics. Relevant to agent security as a log storage backend: append-only MergeTree tables handle high-throughput log ingestion, and SQL-based queries enable fast forensic analysis across millions of agent interactions. Supports parameterized queries and read-only user profiles for least-privilege agent access.

- Website: https://clickhouse.com
- GitHub: https://github.com/ClickHouse/ClickHouse
- Documentation: https://clickhouse.com/docs

---

## Research and Reports

- [Teleport: State of AI in Enterprise Infrastructure Security (Feb 2026)](https://www.globenewswire.com/news-release/2026/02/17/3239200/0/en/New-Teleport-Research-Reveals-AI-Security-Crisis-in-the-Enterprise-Over-Privileged-AI-Systems-Drive-4.5x-Higher-Incident-Rates.html) — 88% of enterprises reported AI agent security incidents; 4.5x higher incident rate for over-privileged systems.
- [NIST Artificial Intelligence](https://www.nist.gov/artificial-intelligence) — Ongoing standards and guidelines for AI safety and security.
- [OWASP AI Security and Privacy Guide](https://owasp.org/www-project-ai-security-and-privacy-guide/) — Broader AI security guidance beyond LLM-specific risks.
