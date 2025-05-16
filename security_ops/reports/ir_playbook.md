# Incident Response Playbook
## Northstar Research Agent

**Version:** 1.0  
**Owner:** Security Operations Center (SOC) & AI Governance Team  
**Completed by:** AI Security Engineer  
**Date:** October 18, 2026  

---

## When to Activate This Playbook

Activate this Incident Response Playbook immediately upon any of the following operational triggers:

- An alert fires from any of the automated monitoring rules defined in this playbook.
- The agent emits or attempts to execute an internal command (`EXPORT_ALL_DATA`, `GET_SYSTEM_INFO`, `SEARCH_EMPLOYEE`).
- Employee PII, salary bands, internal API keys, or infrastructure credentials appear in any agent completion or log file.
- The RAG pipeline flags a high-confidence indirect prompt injection pattern in a retrieved knowledge base document.
- An end-user or system administrator reports anomalous, aggressive, or hijacked behavior by the agent.

---

## Incident Severity Levels

| Level | Criteria | Examples |
|-------|----------|---------|
| **P1 — Critical** | Active breach, confirmed exfiltration of company-wide records, or exposure of production credentials/keys. | `EXPORT_ALL_DATA` executed in production; `GET_SYSTEM_INFO` exposing database passwords/admin JWT tokens; exfiltration of employee API keys (`sk-SUPER-SECRET-KEY-12345`). |
| **P2 — High** | Unauthorized tool invocation, role privilege bypass, or localized PII exposure without bulk exfiltration. | Agent calls `query_hr_database` during a general research task; successful extraction of individual executive record via `SEARCH_EMPLOYEE`. |
| **P3 — Medium** | Suspicious attack activity blocked by defenses; anomalous RAG poisoning detected in knowledge base. | Poisoned document (`malicious-001-override`) flagged and rejected by retrieval controls; persistent jailbreak/DAN prompts attempted by internal user without command execution. |
| **P4 — Low** | Policy violations, anomalous query volume, near-misses, or minor operational glitches. | Single input guardrail trip; benign query triggering low-confidence string pattern; minor rate limit threshold hit. |

---

## First 30 Minutes Response Procedure

### Critical Scenario: `EXPORT_ALL_DATA` or `GET_SYSTEM_INFO` Triggered in Production (P1)

```
+-------------------------------------------------------------------------------+
|                    FIRST 30 MINUTES INCIDENT TIMELINE (P1)                    |
+-------------------------------------------------------------------------------+
| [00:00 - 05:00]  CONFIRM & CLASSIFY                                           |
|                  - Pull session logs from agent_audit.jsonl                   |
|                  - Verify command exfiltration and assess severity P1         |
|                  - Page On-Call SOC Incident Commander & AI Security Lead     |
+-------------------------------------------------------------------------------+
| [05:00 - 15:00]  CONTAINMENT & ISOLATION                                      |
|                  - Kill active agent processes: pkill -9 -f northstar_agent   |
|                  - Revoke compromised API keys and session tokens             |
|                  - Block attacking IP / User Session at API Gateway           |
|                  - Snapshot chroma_data and audit logs for forensic custody   |
+-------------------------------------------------------------------------------+
| [15:00 - 30:00]  ASSESSMENT & STAKEHOLDER NOTIFICATION                        |
|                  - Determine impacted employee records and leaked secrets     |
|                  - Notify CISO, Legal Counsel, and Data Privacy Officer       |
|                  - Initiate database credential rotation and key revocation   |
+-------------------------------------------------------------------------------+
```

### Minutes 0–5: Confirm and Classify

- [ ] **Pull Session Logs:** Immediately retrieve the active session logs from the primary audit trail:
  - **Log location:** `security_ops/defenses/agent_audit.jsonl` (production: `/var/log/northstar/agent_audit.jsonl` and Datadog / CloudWatch stream `northstar-agent-audit`).
- [ ] **Identify Incident Scope:**
  - Which command or tool was invoked? (`EXPORT_ALL_DATA`, `GET_SYSTEM_INFO`, `query_hr_database`)
  - Was output returned to the client terminal / web session, or was it intercepted by the defensive gate?
  - Extract user identity, caller IP address, and session ID.
- [ ] **Assign Severity Level:** If production credentials, JWT tokens, or bulk employee records were returned, declare **P1 — Critical**.
- [ ] **Page On-Call:** Trigger automated PagerDuty escalation to SOC Incident Commander, AI Security Lead, and Systems Infrastructure On-Call.
  - **On-call contact:** PagerDuty escalation policy `#ai-agent-sev1` / Bridge Phone: `+1-800-555-0199`.

---

### Minutes 5–15: Contain

- [ ] **Halt Agent Processes:** Immediately terminate all active agent processes to prevent further autonomous loops or exfiltration:
  ```bash
  sudo pkill -9 -f northstar_agent
  ```
- [ ] **Isolate User & Network:**
  - Block caller User ID and originating IP in the API Gateway / Web Application Firewall.
  - Revoke active JWT session tokens in Redis token blacklist.
- [ ] **Preserve Forensic Evidence:**
  - Take an immediate read-only forensic snapshot of `agent_audit.jsonl`, ChromaDB vector directory (`./chroma_data`), and application memory dumps:
    ```bash
    mkdir -p /forensics/incidents/$(date +%Y%m%d_%H%M%S)
    cp security_ops/defenses/agent_audit.jsonl /forensics/incidents/$(date +%Y%m%d_%H%M%S)/
    cp -r ./chroma_data /forensics/incidents/$(date +%Y%m%d_%H%M%S)/
    ```
- [ ] **Revoke Compromised Secrets:**
  - If `GET_SYSTEM_INFO` was executed, immediately rotate the production database password (`NorthstarDB_Pr0d_2024!`) and regenerate all JWT signing keys.
  - If `EXPORT_ALL_DATA` or `query_hr_database` executed, revoke and re-issue all internal API keys for Alice Johnson (`sk-ALICE-KEY-7f3a9b2c1d`), Bob Martinez, Carol White, and the admin service account (`sk-SUPER-SECRET-KEY-12345`).

---

### Minutes 15–30: Assess and Notify

Answer these key forensic questions and document findings in the incident record:

| Question | Investigation Finding & Documentation |
|----------|---------------------------------------|
| Which records were accessed? | Identify specific employee IDs returned (EMP-001 through EMP-ADMIN, full salary bands, and clearance levels). |
| Were credentials exposed? | Record whether `db_password`, `admin_token`, or employee `internal_api_key` values were transmitted. |
| Was the knowledge base modified? | Check git commit hashes and ChromaDB collection modification timestamps for unauthorized document insertion. |
| Is the attack ongoing? | Verify whether additional sessions with identical input hashes or from related subnet ranges are active. |

**Stakeholder Notification Matrix:**
- **P1 / P2 Incidents:** Immediately notify CISO (`ciso@northstar-tech.com`), Legal Counsel (`legal@northstar-tech.com`), and Data Privacy Officer (`privacy@northstar-tech.com`) within 30 minutes of confirmation. Prepare regulatory disclosures if personal data was breached under GDPR / CCPA requirements.
- **P3 Incidents:** Notify AI Security Lead and SOC Operations Manager.
- **P4 Incidents:** Log in SIEM ticket tracker and review during weekly security triage.

---

## Remediation Before Restarting

Before the Northstar Research Agent is cleared to return to production service, engineering and security teams must complete the following remediation steps:

- [ ] **Audit and Purge Knowledge Base:** Verify all documents in `./chroma_data`. Purge any unverified or malicious files:
  ```bash
  python3 load_knowledge_base.py --reset
  python3 load_knowledge_base.py
  ```
- [ ] **Verify Hardened Defenses:** Ensure `northstar_agent_hardened.py` is active with:
  1. Hardened system prompt (`system_prompt_hardened.txt`) prohibiting instruction overrides and unauthorized commands.
  2. Input segregation delimiters (`== RETRIEVED CONTEXT ==` and `== USER REQUEST ==`).
  3. RAG distance threshold (`distance <= 0.5`) and content injection scanner.
  4. Least-privilege tool permission matrix (`TOOL_PERMISSIONS`).
  5. Human-in-the-loop approval gate enabled for high-risk operations.
- [ ] **Run Regression Verification:** Execute the automated test suite and require 100% pass rate before re-enabling traffic:
  ```bash
  python3 test_validation.py
  ```
- [ ] **Post-Mortem Review:** Schedule a post-incident review meeting within 48 hours to document root cause, timeline, and preventive actions.

---

## What to Log for Every Agent Interaction

The logging architecture must capture the following structured fields in JSON format (`agent_audit.jsonl` / SIEM) for complete forensic reconstruction:

| Field Name | Type | Description & Security Purpose |
|------------|------|--------------------------------|
| `timestamp` | ISO-8601 String (UTC) | Precise millisecond-accurate timestamp for chronological event correlation. |
| `session_id` | UUIDv4 String | Unique session identifier tracking multi-turn conversation context. |
| `user_id` / `caller_ip` | String | Caller identity, internal employee email, and network origin for attribution. |
| `input_hash` | SHA-256 Hex String | Cryptographic digest of the raw input text to detect replay attacks and deduplicate telemetry. |
| `user_input_preview` | String (Truncated) | Sanitized preview of the user request (max 256 chars) for fast analyst triage. |
| `retrieved_doc_ids` | List of Strings | Identifiers of all knowledge base documents retrieved from ChromaDB. |
| `retrieved_doc_distances`| List of Floats | Cosine/L2 similarity distance scores for each retrieved document. |
| `security_flags` | List of Strings | Triggered detection rules (e.g., `INPUT_GUARDRAIL_TRIGGERED`, `RAG_DOC_REJECTED_INJECTION`). |
| `tools_called` | List of Strings | Exact names of tools invoked by the agent (`fetch_url`, `save_note`, etc.). |
| `tool_execution_status`| Dict | Execution outcome for each tool call (`SUCCESS`, `BLOCKED`, `ERROR`). |
| `commands_detected` | List of Strings | Command tokens extracted from LLM completions prior to policy gating. |
| `commands_executed` | List of Strings | Privileged backend commands that passed authorization and were executed. |
| `response_time_ms` | Integer | Total inference and tool execution latency in milliseconds to detect DoS. |

---

## Alert Rules

The following production alert rules monitor agent telemetry and route alerts to the SOC SIEM and on-call responders:

| Alert ID | Alert Name | Trigger Condition | Severity | First Action |
|----------|------------|-------------------|----------|-------------|
| **ALT-001** | Bulk Data Export Attempt | `EXPORT_ALL_DATA` detected in LLM output or requested by user | **P1 — Critical** | Block command immediately, terminate agent session, page On-Call SOC Incident Commander. |
| **ALT-002** | System Infrastructure Reconnaissance | `GET_SYSTEM_INFO` emitted by LLM or database host/credential query detected | **P1 — Critical** | Intercept completion, rotate internal DB passwords, investigate calling session IP. |
| **ALT-003** | Unauthorized Tool Invocation (Task Hijacking) | Agent attempts to invoke `query_hr_database` outside an approved HR workflow (`task_type != 'hr'`) | **P2 — High** | Block tool execution at dispatcher, record audit event, suspend user session pending review. |
| **ALT-004** | Indirect RAG Injection Signature Detected | Knowledge base document retrieved contains string from `INJECTION_PATTERNS` ("system override", "ignore previous instructions") | **P2 — High** | Discard document from context, log document ID to SOC queue, quarantine document in ChromaDB. |
| **ALT-005** | Direct Jailbreak / Prompt Injection Detected | User prompt matches known jailbreak patterns ("you are dan", "ignore your instructions", "developer mode") | **P3 — Medium** | Return standard policy refusal response, log input SHA-256 hash, increment user threat score. |
| **ALT-006** | Agent Latency Spike / Potential ReDoS / DoS | Single query inference latency exceeds 120,000 ms (2 minutes) or recursive tool iterations hit `max_iterations` | **P3 — Medium** | Terminate stuck agent thread, return timeout notice, alert AI Engineering team for resource throttling. |

---

## Contacts & Incident Escalation Directory

| Role | Primary Contact | Email / Channel | SLA / Response Time |
|------|-----------------|-----------------|---------------------|
| Security Operations Center (SOC) | On-Call SOC Lead | soc@northstar-tech.com / #soc-alerts | < 5 minutes (24/7) |
| AI Security Engineering | Lead AI Security Engineer | ai-security@northstar-tech.com / #ai-sec | < 15 minutes |
| AI Enablement / Product Lead | Product Director | ai-team@northstar-tech.com / #agent-core | < 30 minutes |
| Data Privacy Officer (DPO) | Chief Privacy Officer | privacy@northstar-tech.com | < 1 hour |
| Legal Counsel | Senior Corporate Counsel | legal@northstar-tech.com | < 2 hours |
| Chief Information Security Officer | CISO | ciso@northstar-tech.com / Phone Direct | Immediate for P1 |
