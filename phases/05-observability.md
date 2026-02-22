# Phase 5: Observability

## What you're checking

The completeness and integrity of your agent's logging and monitoring infrastructure. Every decision, action, tool call, input, and output should be recorded with enough fidelity that any action can be reconstructed from logs alone. This phase verifies that your logging is complete, tamper-resistant, and operationally useful — not just present.

## Why it matters

Observability is the control that makes every other control auditable. Without it, you cannot verify that your Phase 1 approval gates are working. You cannot confirm that Phase 2 injection attempts were blocked. You cannot reconstruct the sequence of events that led to an incident.

Only 14.4% of organizations have full security approval for their agent fleet (Teleport, Feb 2026). For the rest, observability is the minimum viable safety net — the capability that distinguishes "we detected and contained this in hours" from "we pieced together what happened over three weeks." Incomplete logging does not just slow incident response; it makes accurate root cause analysis impossible and regulatory compliance untenable. When your agent acts autonomously at scale, logs are the only witness.

## Checklist

- [ ] Log all agent decisions with the reasoning trace or rationale, not just the final output
- [ ] Log all tool and function calls with full parameters and results (both successful and failed calls)
- [ ] Log all inputs: user messages, system prompt versions, retrieved context, API responses fed into the model
- [ ] Implement tamper-resistant log storage: append-only, externally stored, or cryptographically signed
- [ ] Add alerting for anomalous behavior patterns: unusual tool call frequency, access to high-sensitivity resources, rejected inputs above a threshold rate
- [ ] Set up dashboards for security-relevant metrics: approval gate trigger rate, rejection rate by input type, trust score distribution, latency outliers
- [ ] Test log completeness: given only your logs, verify you can reconstruct any agent action end-to-end
- [ ] Implement and document a log retention policy: define minimum retention period, storage location, and access controls
- [ ] Add security event classification in logs: distinguish routine operations from security-relevant events (approval requests, rejected inputs, permission denials, anomaly flags)
- [ ] Run a tabletop incident response exercise using only logs: simulate an incident and verify your team can identify root cause, scope, and timeline from the log record alone

## How to test

**Log completeness test:**
Pick any agent action from a test session. Starting from logs only, attempt to reconstruct: what input triggered it, what tools were called and with what parameters, what was returned, what decision was made, and what output was produced. If any step in this chain requires information not in the logs, you have a gap.

**Tamper-resistance test:**
Verify that logs cannot be modified or deleted through the same access paths available to the agent. If the agent can write to its own log store with the same credentials used to write logs, the logs are not tamper-resistant.

**Alerting test:**
Trigger a condition that should fire an alert (for example, submit 20 prompt injection attempts in rapid succession). Verify the alert fires within your defined SLA. Check that the alert includes enough context to act on without digging through raw logs.

**Retention and access control audit:**
```bash
# Verify log retention period
# Query your log storage for events older than your defined minimum retention
# If they are missing, retention policy is not enforced

# Verify access controls
# Attempt to read security logs with agent credentials
# Attempt to delete or overwrite a log entry
# Both should fail
```

**Incident reconstruction exercise:**
From a test session where you deliberately triggered a security event (prompt injection attempt, failed approval, rejected file access), write an incident timeline using only log data. If you cannot produce an accurate timeline in under 30 minutes, your logging is insufficient for operational incident response.

**OpenTelemetry instrumentation check:**
```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

tracer = trace.get_tracer("agent.security")

with tracer.start_as_current_span("tool_call") as span:
    span.set_attribute("tool.name", tool_name)
    span.set_attribute("tool.parameters", str(parameters))
    span.set_attribute("security.event_type", "tool_execution")
    span.set_attribute("security.approval_required", approval_required)
    # Execute tool
    result = execute_tool(tool_name, parameters)
    span.set_attribute("tool.result_status", "success")
```
Verify security attributes are present on every span that represents an agent action.

## Example vulnerability

After a suspected prompt injection incident, the engineering team attempted to determine what instructions the agent had followed, what data it had accessed, and what actions it had taken. The agent logged only errors and final outputs. There were no reasoning traces, no tool call records, no logs of retrieved context.

The investigation took three weeks. Even after that, the team could not confirm with certainty whether sensitive data had been accessed, because there was no record of what the retrieval pipeline had returned to the model. The incident report was filed with the scope listed as "unknown."

The fix required instrumenting every agent operation with structured logging from the outset. Retro-fitting observability onto a production agent is significantly more expensive than building it in. The team estimated the incident cost 10x more in investigation time than the implementation cost of proper logging would have been.

## Tools

- **Langfuse** (https://langfuse.com) — open-source LLM observability platform with trace, span, and score tracking; self-hostable for data residency requirements
- **LangSmith** (https://smith.langchain.com) — LangChain's native observability and evaluation platform; strong integration for LangChain and LangGraph agents
- **Helicone** (https://helicone.ai) — proxy-based LLM observability with request logging, cost tracking, and custom property tagging
- **OpenTelemetry** (https://opentelemetry.io) — vendor-neutral instrumentation standard; use for building portable, standards-compliant agent traces
- **Grafana + Loki** (https://grafana.com/oss/loki/) — open-source log aggregation and dashboarding for teams that prefer a self-hosted observability stack
- **AWS CloudTrail / GCP Cloud Audit Logs / Azure Monitor** — cloud-native audit logging for agent infrastructure and API calls at the platform level
