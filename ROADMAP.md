# TSAGE Implementation Roadmap

## Purpose

TSAGE already has a working FastAPI backend, Next.js SOC console, deterministic
Wazuh ingestion and correlation, PostgreSQL persistence, Redis coordination,
Clerk authentication, a conversational SOC assistant, and a controlled MAPE-K
response workflow.

This roadmap continues that foundation without introducing a second
orchestrator or allowing an LLM to make security-sensitive state decisions.
PostgreSQL remains authoritative, Redis remains optional, and Wazuh response
actions remain behind separate approval and execution authorization.

## Existing Foundation

The following capabilities are already implemented and should be extended
rather than rebuilt:

- Bounded Wazuh Indexer and server API clients.
- Durable alert ingestion using ascending timestamp and document-ID sorting.
- OpenSearch `search_after` checkpoint persistence.
- Idempotent alert storage keyed by Wazuh index and document ID.
- Normalization, correlation, security findings, triage verdicts, and analyst
  feedback.
- Per-user alert cursors for conversational "new since my last check" results.
- `/ask`, slash-command autocomplete, Oxy intent routing, and observable tool
  activity.
- Typed MAPE-K playbooks, immutable plan binding, human approval, separate
  execution authorization, durable action claims, verification, and rollback.
- An Approval Center and investigation history in the frontend.
- Dry-run execution that does not call responder adapters.

## Delivery Order

1. Phase 2A: harden Monitor cursor semantics and add natural-language Indexer
   search.
2. Phase 2B: add RAG over runbooks and MITRE ATT&CK, then detection-gap
   analysis.
3. Add real AbuseIPDB enrichment, root documentation, and backend linting.
4. Clarify and expose the existing dry-run path as Phase 3 shadow mode.
5. Add CI and frontend smoke tests, then perform repository cleanup separately.

## Phase 2A: Monitor And Natural-Language Search

### Durable New-Alert Semantics

The LLM must never infer whether an alert is new. The Monitor and ingestion
services own that decision deterministically.

- Expand the ingestion checkpoint identity beyond the current single
  `source_name` key to include connection profile and index pattern. Retain a
  migration path for the current default Wazuh connection.
- Keep the main ingestion cursor independent from conversations. Alerts are
  ingested once and conversation/user cursors only control what each analyst
  has already viewed.
- Continue sorting deterministically by timestamp and document identity. Add an
  index-name tie breaker if searches span multiple indices.
- Search with a 60-second overlap before the saved timestamp to tolerate late
  Wazuh indexing.
- Deduplicate using `(index_name, document_id)`; never calculate deltas from
  count differences or only from `now - interval`.
- Persist and normalize a page in one transaction. Advance its checkpoint only
  after that transaction commits.
- Leave failed correlation rows pending so a later worker cycle can retry them
  without rereading or losing the raw alert.
- Use PostgreSQL for checkpoints and Redis only for a short ingestion lock.
- Return a typed monitor result containing:
  `checked_at`, `previous_check_at`, `new_alert_count`,
  `duplicate_alert_count`, `new_finding_count`, `new_incident_count`,
  `highest_new_rule_level`, `has_new_alerts`, `cursor_advanced`, and
  `truncated`.
- Add tests for equal timestamps, duplicate IDs in different indices,
  late-arriving events, page boundaries, process restarts, correlation failure,
  and concurrent workers.

### Natural-Language Indexer Queries

- Add `/search <request>` to the server-owned assistant command catalogue.
- Add a strict `IndexerQuery` schema covering:
  - source: alerts, archives, or vulnerabilities;
  - bounded time window;
  - limit and sort direction;
  - agent, rule, source IP, target user, severity, and text filters.
- Let Oxy extract only this typed query. Reject raw OpenSearch DSL, unknown
  fields, scripts, aggregations, index names, and excessive windows.
- Compile the validated query exclusively into the existing bounded Wazuh
  gateway methods.
- Return a concise answer with the selected source, effective time window,
  result count, evidence references, and whether the result came from live
  Wazuh or durable PostgreSQL memory.
- Report Wazuh unavailability explicitly. Do not present cached or persisted
  results as live Indexer data.
- Stream sanitized progress events for intent selection, query validation,
  Indexer search, normalization, and result synthesis.

## Phase 2B: Knowledge Retrieval And Detection Gaps

### RAG Over Runbooks And MITRE

- Replace the PostgreSQL image with `pgvector/pgvector:pg16` while retaining the
  existing data volume.
- Add an Alembic migration that enables the vector extension and creates
  application-owned knowledge document and chunk tables.
- Use `langchain-postgres` with Gemini `gemini-embedding-001` embeddings at 768
  dimensions.
- Store document source, title, version, content hash, section, MITRE technique
  IDs, chunk position, bounded text, and embedding.
- Add an idempotent ingestion command for:
  - repository-managed Markdown runbooks;
  - MITRE tactics, techniques, mitigations, groups, and software returned by
    the Wazuh MITRE API.
- Replace changed chunks by content hash and delete stale chunks for a source.
  Do not perform unannounced network ingestion during API startup.
- Add `/knowledge <question>` and allow `/ask` to retrieve knowledge when
  relevant.
- Require every knowledge-backed answer to include source title, source URI or
  identifier, section, and chunk reference.
- If embeddings or vector retrieval are unavailable, keep `/ask` operational
  with its existing bounded context and state clearly that knowledge retrieval
  was unavailable.

References:

- [LangChain PGVector RAG guidance](https://docs.langchain.com/oss/python/deepagents/rag#pgvector)
- [Gemini embedding model](https://ai.google.dev/gemini-api/docs/models/gemini-embedding-001)
- [pgvector PostgreSQL images](https://github.com/pgvector/pgvector)

### Detection-Gap Analysis

- Compare observed finding techniques and severities with Wazuh rule-to-MITRE
  mappings, available telemetry, and analyst false-positive feedback.
- Detect these bounded gap types:
  - `missing_coverage`: an observed technique has no mapped enabled rule;
  - `weak_coverage`: only low-fidelity or low-level rules cover repeated
    malicious findings;
  - `telemetry_gap`: evidence required by the relevant runbook is absent;
  - `noisy_rule`: sufficient analyst feedback demonstrates a repeated
    false-positive pattern.
- Create deterministic gap IDs and persist severity, status, analysis window,
  technique IDs, rule IDs, evidence references, affected assets, supporting
  metrics, and recommendations.
- Use the LLM only to explain an already validated gap. It cannot create an
  unsupported gap, edit a Wazuh rule, or deploy a detection.
- Add:
  - `POST /api/v1/detection-gaps/analyze`;
  - `GET /api/v1/detection-gaps`;
  - `GET /api/v1/detection-gaps/{gap_id}`;
  - `PATCH /api/v1/detection-gaps/{gap_id}` for acknowledge, dismiss, and
    resolve transitions;
  - `/gaps [--hours N]` in the assistant.
- Add a Detection Gaps frontend workspace with filters, evidence, MITRE and
  runbook references, status controls, and analysis history.

## Threat-Intelligence Enrichment

- Replace the AbuseIPDB stub with a read-only adapter for
  `GET /api/v2/check`.
- Add server-only settings for API key, base URL, timeout, maximum report age,
  and cache TTL.
- Skip invalid, internal, protected, and allowlisted IP addresses.
- Cache sanitized results in Redis to protect the daily quota; continue without
  enrichment when Redis is unavailable.
- Interpret the confidence score conservatively:
  - 75-100: malicious supporting evidence;
  - 25-74: suspicious supporting evidence;
  - below 25: unknown, not proof that the address is clean.
- Persist only bounded provider facts such as score, report count, country,
  usage type, last report time, and lookup status. Never persist the API key or
  the complete vendor response.
- Handle missing credentials, timeouts, malformed payloads, HTTP 429,
  `Retry-After`, and upstream errors without failing triage.
- Treat threat intelligence as evidence only. It cannot directly approve or
  execute a response action.

Reference:

- [AbuseIPDB API v2 documentation](https://docs.abuseipdb.com/)

## Phase 3: Playbooks, Approval Center, And Shadow Mode

Phase 3 is structurally present. The remaining work is to expose and clarify
the existing controls.

- Expand `MAPEK_EXECUTION_MODE` to `disabled`, `shadow`, and `enabled`.
- Preserve existing `dry_run` action statuses for API and database
  compatibility while displaying them as Shadow Mode.
- Shadow mode must create durable simulated actions, audit events, and
  simulated verification without calling any Wazuh responder.
- Keep enabled execution behind all existing gates:
  - `MAPEK_REAL_EXECUTION_ENABLED`;
  - executor user authorization;
  - immutable approval and plan binding;
  - protected-target policy;
  - responder credentials;
  - Wazuh read/write safety flags.
- Add `GET /api/v1/playbooks` backed by the real playbook registry.
- Replace assistant command cards on the Playbooks page with registered
  playbooks, actions, rollback actions, verification checks, versions, roles,
  and supported incident types.
- Expand the Approval Center into:
  - pending decisions;
  - approved and awaiting execution;
  - execution and verification history.
- Display evidence references, plan hash, expiry, required role, execution
  mode, action state, verification, and rollback state.
- Do not add a new mutating playbook until its executor, rollback handler,
  policy rules, and post-action verification checks all exist.

## Documentation And Backend Quality

### Root Documentation

Add a root `README.md` that explains:

- `Backend`, `Frontend/agent-ui`, and `dataset` ownership;
- which processes run locally and which run in Docker;
- PostgreSQL, Redis, FastAPI, Next.js, Clerk, Oxy, Gemini, and Wazuh
  configuration;
- SSH tunnel requirements for the Wazuh manager and Indexer;
- startup, migration, ingestion-worker, test, lint, and build commands;
- read-only defaults and the approval/execution safety boundary;
- links to the backend, frontend, MAPE-K, and normalization documentation.

### Ruff

- Configure Ruff in `Backend/pyproject.toml` for Python 3.11.
- Enable formatting and the `E`, `F`, `I`, `UP`, and `B` rule families.
- Add non-rewriting `lint` and `format-check` Make targets.
- Apply any mechanical fixes separately from feature changes and verify the
  complete backend test suite afterward.

## CI And Cleanup

- Add GitHub Actions jobs for:
  - Ruff check and format check;
  - backend pytest;
  - Alembic upgrade and downgrade verification against PostgreSQL with
    pgvector;
  - frontend pnpm install, typecheck, ESLint, and production build;
  - frontend component tests.
- Add Vitest and Testing Library coverage for the findings workflow: load
  findings, select one, inspect evidence, and submit analyst feedback.
- Keep `SocConsole.tsx` intact until its size causes a concrete maintenance or
  testing problem.
- After CI is green, remove the confirmed obsolete Jenkins tree and invalid or
  unused requirements such as `httpx2` in a separate cleanup change.
- Do not add submodule work: this repository currently has no `.gitmodules`.

## Acceptance Tests

### Monitor And Search

- A repeated ingestion page inserts no duplicate alert.
- Equal timestamps and rolling Wazuh indices cannot skip or repeat an event.
- A late-arriving alert inside the overlap window is ingested exactly once.
- A failed database transaction does not advance the checkpoint.
- A correlation failure leaves persisted alerts retryable.
- Two workers cannot process and advance the same cursor concurrently.
- Natural-language searches use only allowlisted read methods and reject raw
  DSL.

### Knowledge And Detection Gaps

- Reindexing unchanged documents creates no duplicate chunks.
- Changed and deleted source documents update the vector index correctly.
- RAG answers contain valid stored citations and cannot cite missing chunks.
- Cross-user knowledge and detection-gap records remain isolated.
- Mapped, missing, weak, noisy, dismissed, and resolved gap cases are covered
  with deterministic evidence fixtures.

### Enrichment And Response Safety

- AbuseIPDB tests cover public and private IPs, score boundaries, caching,
  timeout, malformed response, missing key, and rate limiting.
- Shadow mode never invokes an external responder.
- Approval permission alone cannot execute an action.
- Enabled execution still requires the executor role and all safety flags.
- PostgreSQL restart preserves alerts, findings, knowledge, gaps, approvals,
  actions, and checkpoints.
- Redis failure degrades caching and live coordination without losing durable
  state.

### End-To-End Verification

- Run backend tests and Alembic upgrade/downgrade.
- Run frontend tests, typecheck, lint, and production build.
- Confirm Docker health for PostgreSQL and Redis.
- Complete a Clerk-authenticated Wazuh lab smoke test covering ingestion,
  search, triage, investigation, approval, shadow execution, and verification.

## Defaults And Constraints

- Oxy remains the conversational and structured-inference provider.
- Gemini is used only for embeddings.
- Personal Clerk user scope remains authoritative; Clerk Organizations are not
  restored.
- FastAPI and Next.js run locally. Only PostgreSQL and Redis run in Docker.
- PostgreSQL is required for ingestion and production workflows. Redis is
  optional.
- Wazuh remains read-only and dangerous tools remain disabled throughout
  Phase 2.
- No arbitrary shell, OpenSearch DSL, Wazuh write API, or responder credentials
  are exposed to an LLM.
- Cleanup stays separate from behavior-changing feature work.
