# CyberSentinel AI

CyberSentinel AI is a local-first cybersecurity incident triage and investigation project. It combines deterministic SSH log parsing and detection, PostgreSQL-backed incident records, a React SOC dashboard, optional local Ollama investigation, local ATT&CK/RAG context, evidence verification, and synthetic evaluation tools.

The current implementation is intended for local development and demonstration. It is not a production incident-response platform and does not automatically block, quarantine, disable accounts, or make infrastructure changes.

## Architecture

```text
React + TypeScript dashboard (Vite)
        │ HTTP / JSON
        ▼
FastAPI backend ───────── PostgreSQL
        │
        ├── SSH/CSV parsing and deterministic SSH rules
        ├── On-demand investigation via local Ollama (Qwen 2.5 3B)
        ├── Bundled local MITRE ATT&CK SSH catalog and local RAG knowledge
        ├── Independent event-evidence verification
        ├── Internal typed multi-agent orchestrator
        └── Incident report and local evaluation services
```

### Source layout

- `backend/app/routers/`: FastAPI incident, detection/log-upload, report, RAG, investigation, and evaluation-result endpoints.
- `backend/app/agents/`: shared typed case state, reusable typed tools, investigation adapter, sequential orchestrator, deterministic reconstruction/risk/response planning, and local knowledge adapter.
- `backend/app/security/`: parsing, ingestion/detection, Ollama client, deterministic pipeline, verification, reporting, local RAG and bundled ATT&CK data.
- `backend/app/evaluation/` and `backend/evaluation/`: evaluation schemas/runner, controlled synthetic dataset, and generated JSON/Markdown results.
- `backend/tests/`: backend `unittest` suite.
- `frontend/src/`: dashboard, SOC panels, evaluation results section, API service, shared TypeScript types and styling.

The production incident investigation route is on-demand at `POST /api/incidents/{incident_id}/investigate`. The Central Orchestrator is an internal service and is not exposed as an API route. Its full workflow is:

**Triage → Correlation → Investigation → Attack Reconstruction → Threat Intelligence/Knowledge → Risk Assessment → Response Planning → Independent Verification → Report Handoff**

The current incident endpoint preserves its established investigation, verification and persistence behavior. It does not imply that a separate multi-agent orchestration run has occurred.

## Requirements

- Windows PowerShell instructions are shown below; equivalent local tools can be used on other platforms.
- Python 3.10 or newer.
- Node.js 20.19+ or 22.12+ and npm.
- PostgreSQL (the project has been set up/tested with PostgreSQL 18).
- Ollama installed separately, and the configured model downloaded locally, for on-demand LLM investigation. Ollama is not needed for deterministic log detection, dashboard use, API health, or deterministic evaluation.

No cloud AI or external threat-intelligence service is configured. MITRE ATT&CK references and RAG knowledge come from bundled local files. The Ollama client accepts loopback URLs only.

## Quick start (Windows PowerShell)

Run these steps from the project root (`CYBERSENTINEL-AI`). PostgreSQL must be installed and its service running before starting the backend. Create the `cybersentinel` database once using pgAdmin or `psql`; for example, in PowerShell where `psql` is on `PATH`:

```powershell
psql -U postgres -h localhost -c "CREATE DATABASE cybersentinel;"
```

If the database already exists, do not create it again.

### 1. Configure the backend

Copy the example only if a local backend environment file does not already exist; preserve any existing local credentials:

```powershell
if (-not (Test-Path backend\.env)) { Copy-Item backend\.env.example backend\.env }
```

Edit `backend\.env` locally and set `DATABASE_URL` to your PostgreSQL username, local password and database, for example:

```dotenv
DATABASE_URL=postgresql+psycopg://postgres:CHANGE_ME@localhost:5432/cybersentinel
ENVIRONMENT=development
```

`CHANGE_ME` is a placeholder, not a usable credential. URL-encode reserved characters in the password (for example, `@` as `%40`). Never commit `.env` files.

### 2. Start the backend

In a PowerShell terminal at the project root:

```powershell
Set-Location backend
if (-not (Test-Path .venv)) { py -3 -m venv .venv }
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The dependency install is needed for a new environment; it can be skipped when dependencies are already installed. If PowerShell prevents environment activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal and activate again. The backend initializes missing tables and applies its existing idempotent PostgreSQL column adjustments at startup; it does not drop existing tables.

### 3. Start the frontend

In a second PowerShell terminal at the project root:

```powershell
Set-Location frontend
if (-not (Test-Path node_modules)) { npm install }
npm run dev
```

Open the local URL printed by Vite (normally `http://127.0.0.1:5173`). The frontend defaults to `http://127.0.0.1:8000` for the API. To override it, copy `frontend\.env.example` to `frontend\.env`, set `VITE_API_URL`, and restart Vite.

### 4. Verify PostgreSQL and API

- API process health: `http://127.0.0.1:8000/api/health`
- PostgreSQL connectivity: `http://127.0.0.1:8000/api/db-health`
- Evaluation result file: `http://127.0.0.1:8000/api/evaluation/results`
- Interactive API documentation: `http://127.0.0.1:8000/docs`

`/api/health` only confirms FastAPI responds. `/api/db-health` performs a PostgreSQL connectivity check and reports `{"status":"ok","database":"connected"}` when successful.

## Environment configuration

The backend reads `backend/.env` (`backend/.env.example` lists supported example values). Important settings:

| Setting | Default / purpose |
|---|---|
| `DATABASE_URL` | Local PostgreSQL URL for database `cybersentinel`; supply your own local credential. |
| `SSH_BRUTEFORCE_THRESHOLD` | 5 failures. |
| `SSH_BRUTEFORCE_WINDOW_SECONDS` | 300 seconds. |
| `SSH_SUCCESS_FAILURE_THRESHOLD` | 5 preceding failures. |
| `SSH_SUCCESS_FAILURE_WINDOW_SECONDS` | 600 seconds. |
| `SSH_INVALID_USER_THRESHOLD` | 3 invalid-user events. |
| `SSH_INVALID_USER_WINDOW_SECONDS` | 300 seconds. |
| `DETECTION_GROUPING_WINDOW_SECONDS` | 1800 seconds. |
| `OLLAMA_API_URL` | `http://127.0.0.1:11434/api/chat` (loopback only). |
| `OLLAMA_MODEL` | `qwen2.5:3b`. |
| `OLLAMA_TIMEOUT_SECONDS` | 300 seconds maximum. |
| `VITE_API_URL` | Frontend-only optional override; defaults to `http://127.0.0.1:8000`. |

The root, backend and frontend `.env.example` files contain examples/placeholders only. `.gitignore` excludes `.env` and `.env.*` while allowing the example templates. Existing local `.env` files are ignored and should stay local.

## Incident and log workflow

1. Create or review incidents in the dashboard or through `/api/incidents`.
2. Upload `.log`/`.txt` Linux SSH logs or `.csv` records from the Log ingestion panel or `POST /api/logs/upload`.
3. The backend parses supported records, stores event evidence in PostgreSQL, and applies the deterministic rules below. Malformed records are reported; unrecognized SSH lines may be stored as unclassified events and do not qualify as SSH detections.
4. CSV headers accept case-insensitive variations of `timestamp`, `event_type`, `source_ip`, `username`, `hostname`, `description`, and `raw_log`. A CSV must include at least an event type, description/message, or raw-log column. Missing timestamps remain unknown and are excluded from time-window rules. RFC 3164 timestamps have no year; the parser assumes the current UTC year and returns a warning.
5. Review incident evidence, detections and reports. Local Ollama investigation is an explicit on-demand operation, not an automatic action during API startup.

Upload limits are 5 MiB and 10,000 records. Default detection rules:

- `SSH-AUTH-001` (High): at least 5 failed SSH password attempts from one IP within 300 seconds.
- `SSH-AUTH-002` (Critical): successful password login after at least 5 failures from that IP within 600 seconds.
- `SSH-AUTH-003` (Medium): at least 3 invalid-user attempts from one IP within 300 seconds.

The incident API includes create/list/read/update/delete routes under `/api/incidents`, event routes under `/api/incidents/{incident_id}/events`, investigation results, and structured/Markdown reports at `/api/incidents/{incident_id}/report` and `/api/incidents/{incident_id}/report.md`.

## Local investigation, agents and safety

### Ollama

Install Ollama separately using its official local installer; the project does not install or start it automatically. The configured model is **Qwen 2.5 3B**, model name `qwen2.5:3b`. After installing Ollama, make this model available locally (for example, `ollama pull qwen2.5:3b`) and ensure the local service is running at the configured loopback endpoint. The settings are shown in `backend/.env.example`; they are not changed by this README. The client makes a schema-constrained request and can make one repair call after invalid model output. No cloud model is used.

Use **Run local investigation** in an incident's detail panel or call `POST /api/incidents/{incident_id}/investigate`. A successful structured result is saved in the existing investigation-results table; failed or unavailable inference is not represented as a successful finding. Deterministic log detection remains available without Ollama.

### Local ATT&CK and RAG

The bundled `backend/app/security/mitre_attack_ssh.json` catalog supplies qualified, possible SSH behavior mappings (including T1110 mappings) using local detection/event types. These mappings are context, not proof of an attack. The local RAG knowledge base is bundled under `backend/data/`; retrieval is local and its knowledge text is kept separate from incident event evidence. No live ATT&CK lookup, IP reputation or external threat-intelligence API is used.

### Verification and recommendations

The independent deterministic verifier checks structured claims and recommendations against actual stored incident events, including evidence IDs and structured IP/account/time/login fields. It does not use the LLM's own verification status. Unsupported facts are not promoted to verified; hypotheses remain unverified unless the system has structured support. Free-text meaning has limits and is not semantically proven by this deterministic verifier.

The internal typed Central Orchestrator sequences:

**Triage → Correlation → Investigation → Attack Reconstruction → Threat Intelligence/Knowledge → Risk Assessment → Response Planning → Independent Verification → Report Handoff**

The orchestrator is currently an internal service; the existing incident API does not expose a new endpoint for this entire sequence. Its response planner only recommends actions from available case data. Any potentially high-impact recommendation requires explicit human approval and defaults to `pending`. **No firewall changes, blocking, account disabling, process killing, notifications, containment or remediation are executed.** Report handoff uses the existing report builder and does not make recommendations appear completed.

## Synthetic evaluation and dashboard

The evaluation dataset in `backend/evaluation/synthetic_cases.json` contains five controlled synthetic SSH cases. The runner is local and deterministic for its deterministic mode:

```powershell
Set-Location backend
python -m app.evaluation.runner
```

It uses existing deterministic detection, local ATT&CK, risk, verification and response-planning logic with transient in-memory case data. It does not write database records or call external services. Results are written to `backend/evaluation/results/evaluation.json` and `evaluation.md`. `--mode complete` or `--mode both` additionally invokes the production orchestrator and requires the configured local Ollama service.

The dashboard's **Evaluation** section reads the stored JSON through read-only `GET /api/evaluation/results`; the endpoint does not trigger a run. It presents the mode, case count, metrics, and unavailable baselines. The generated result currently includes the deterministic baseline; the single-LLM-only and multi-agent-without-verification baselines are **Unavailable**, not assigned zero scores.

All evaluation labels and metrics apply only to this synthetic dataset. They are not real-world performance claims, model quality measurements, or proof of superiority over a baseline. Current generated values and limitations are documented in the result files; rerunning the runner updates them from the current local code and dataset.

## Tests and validation

From `backend`:

```powershell
.\.venv\Scripts\Activate.ps1
python -m unittest discover -s tests -v
python -m unittest discover -s tests -p "test_evaluation.py" -v
python -m unittest discover -s tests -p "test_evaluation_api.py" -v
```

From `frontend`:

```powershell
npm run build
```

The focused test files cover typed agent tools, investigation, attack reconstruction, orchestration, knowledge/risk, response planning, evaluation and the evaluation-results endpoint. No frontend test framework is configured; TypeScript type-check and Vite production build are used for frontend validation.

### Current finalization validation

Validated for the Stage 7 handoff on 2026-10-01:

- Backend unittest suite: **103 passed** (`python -m unittest discover -s tests -v`).
- Frontend production build: **passed** (`npm run build`; TypeScript check and Vite build).
- Deterministic evaluation runner: **passed**, 5 synthetic cases; results regenerated under `backend/evaluation/results/`.
- Live API smoke checks on a fresh local FastAPI instance at port 8001: `/api/health` 200; `/api/db-health` 200 (`connected`); `/api/evaluation/results` 200 (5 cases); `/api/incidents` 200.
- Report routes are registered; there were no stored incidents available for a successful report fetch, and a request for a nonexistent incident correctly returned 404.
- FastAPI, agent contract, Central Orchestrator and evaluation import/schema smoke checks: **passed**.
- Environment examples were confirmed to use `CHANGE_ME` placeholders; local `.env` files are ignored and are not tracked.
- `git diff --check`: **passed**.
- PostgreSQL was reachable. Ollama was not listening on its configured local port during validation; live inference and the Ollama-dependent complete-pipeline evaluation were therefore not run. Ollama-dependent behavior remains covered only by the backend's tests in this run.

An already-running backend on the default port 8000 did not serve the newly added evaluation endpoint during the check. The endpoint worked on the fresh instance at port 8001. Restart FastAPI after updating the project so the process loads the current router code.

## Limitations

- Local demonstration/development project; no authentication or deployment hardening is included.
- PostgreSQL is required for persisted incidents, events, investigation records and database-health checks.
- Ollama and its local Qwen model must be installed separately for on-demand LLM investigation.
- The local threat knowledge and ATT&CK catalog are limited and are not live threat intelligence or IP reputation.
- The orchestrator is internal and its transient state is not persisted as a multi-agent run.
- Deterministic verification checks evidence IDs and structured attributes; it cannot establish intent or semantically prove arbitrary free text.
- Response recommendations are advisory only, approval is not an implemented user workflow, and no response actions are executed.
- Five synthetic cases are too limited to support real-world performance conclusions. Single-LLM and verification-disabled comparison baselines are unavailable.
