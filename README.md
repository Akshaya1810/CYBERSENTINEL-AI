# CyberSentinel AI

A local-first foundation for a college project exploring cybersecurity incident investigation and response. It contains a React/TypeScript SOC dashboard and a FastAPI backend with PostgreSQL-backed incident, security event, and investigation result records. It does not perform automated threat analysis or run AI agents.

## Project structure

```text
CyberSentinel/
├── backend/
│   ├── app/
│   │   ├── core/config.py       # Local settings via Pydantic Settings
│   │   ├── db/session.py        # SQLAlchemy engine and model base
│   │   └── main.py              # FastAPI app and /api/health
│   └── requirements.txt
├── frontend/
│   ├── src/App.tsx              # SOC dashboard and backend status
│   ├── src/main.tsx
│   ├── src/styles.css
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   └── vite.config.ts
├── .env.example
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or newer
- Node.js 20.19+ or 22.12+ and npm
- PostgreSQL 18 is used for incident data and database health checks

LangGraph, Ollama, and MITRE ATT&CK are reserved for later phases. Ollama is not installed or launched by this project. No OpenAI API, API key, or external AI service is used. The frontend uses local system fonts. Project data stays on your machine.

## Windows PowerShell setup

Open two PowerShell terminals at the project root.

### Backend

```powershell
cd backend
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If PowerShell blocks virtual environment activation, run this once in that terminal, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Vite prints a local URL, normally `http://127.0.0.1:5173`.

## Verify

- Open `http://127.0.0.1:5173` and confirm **Backend API** changes to **Connected**.
- Open `http://127.0.0.1:8000/api/health`; expect `{"status":"ok","service":"CyberSentinel AI API"}`.
- Open `http://127.0.0.1:8000/docs` for the local FastAPI docs.

The health route reports only that the API process is responding. It does not indicate database connectivity, threat detection, or AI analysis. PostgreSQL settings can be provided via `DATABASE_URL` in a local `.env` file; credentials shown in `.env.example` are placeholders only.

## Incident API (Windows CMD)

The backend reads `DATABASE_URL` from `backend/.env`. Copy `backend/.env.example` to `backend/.env` and set your local PostgreSQL password there. Do not commit `.env`.

From the project root, start or restart the backend in CMD:

```cmd
cd /d C:\Users\aksha\OneDrive\Desktop\AI\CYBERSENTINEL-AI\backend
.venv\Scripts\activate.bat
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

On startup, SQLAlchemy `create_all` creates any missing incident tables without dropping existing tables or records. Browse to `http://127.0.0.1:8000/docs` to explore the API. The main endpoints are:

- `POST /api/incidents`, `GET /api/incidents`, `GET /api/incidents/{incident_id}`, `PATCH /api/incidents/{incident_id}`, `DELETE /api/incidents/{incident_id}`
- `POST /api/incidents/{incident_id}/events`, `GET /api/incidents/{incident_id}/events`
- `POST /api/incidents/{incident_id}/investigation-results`
- `GET /api/health`, `GET /api/db-health`

Manually entered investigation results are stored records. On-demand local Ollama investigation is documented below; deterministic log detection remains independent of Ollama availability.
## Security log ingestion and deterministic detection

Install the backend dependencies, including the required multipart parser, from `backend`:

```cmd
python -m pip install -r requirements.txt
```

Use `POST /api/logs/upload` in `http://127.0.0.1:8000/docs` or the dashboard. Upload `.log`/`.txt` Linux SSH authentication logs or `.csv` records. Files are limited to 5 MiB and 10,000 records. Malformed rows are reported in the response and do not stop processing other rows. Unrecognized SSH lines are stored as unclassified evidence and are not treated as detections.

CSV accepts case-insensitive variations of `timestamp`, `event_type`, `source_ip`, `username`, `hostname`, `description`, and `raw_log`. A CSV must include at least an event type, description/message, or raw log column. Timestamps may be omitted; missing timestamps remain unknown and those events are excluded from time-window rules. RFC 3164 SSH timestamps do not include a year; the parser assumes the current UTC year and returns a warning.

Active default rules are:

- `SSH-AUTH-001` (High): 5 failed SSH password attempts from one IP within 300 seconds.
- `SSH-AUTH-002` (Critical): a successful password login after at least 5 failures from that IP within 600 seconds.
- `SSH-AUTH-003` (Medium): 3 invalid-user attempts from one IP within 300 seconds.

Thresholds and the 1,800-second incident grouping window can be overridden with the corresponding `SSH_BRUTEFORCE_*`, `SSH_SUCCESS_FAILURE_*`, `SSH_INVALID_USER_*`, and `DETECTION_GROUPING_WINDOW_SECONDS` settings shown in `backend/.env.example`. Detection descriptions report observed behavior and do not prove a source is malicious or that an account was compromised. Events are retained in PostgreSQL; unassociated events are attached when a rule creates or reuses an open detection incident.

On startup, SQLAlchemy creates missing detection tables. A safe idempotent PostgreSQL adjustment makes the existing `security_events.incident_id` and `timestamp` columns nullable and adds nullable username/hostname columns. It does not drop tables or alter existing event values.

Run the backend's dependency-free synthetic parser/rule/database tests from `backend`:

```cmd
python -m unittest discover -s tests -v
```

`GET /api/detections/rules` returns active thresholds and `GET /api/detections/history` returns recent persisted matches with evidence event IDs and incident IDs.

## Local Ollama incident investigation

Ollama inference is on-demand; backend startup does not call Ollama. Set these optional entries in `backend/.env` (defaults shown):

```env
OLLAMA_API_URL=http://127.0.0.1:11434/api/chat
OLLAMA_MODEL=qwen2.5:3b
OLLAMA_TIMEOUT_SECONDS=120
```

Start Ollama separately and ensure `qwen2.5:3b` is available locally. The API accepts loopback Ollama URLs only and uses Python's standard library HTTP client; no additional backend package or cloud API is used. In Swagger or the incident detail dialog, call **POST `/api/incidents/{incident_id}/investigate`** / **Run local investigation**. A successful response is stored as structured JSON in the existing `investigation_results.findings` field, then revalidated against current incident event rows whenever the report is retrieved. Failed or unavailable inference is returned as such and is not stored as a successful result.

The pipeline uses one structured Ollama inference call for triage, findings, attack reconstruction, impact/risk assessment, and advisory response planning; these are distinct output responsibilities, not separate autonomous agents. Event correlation and ATT&CK context use deterministic database/local catalog logic. The independent verifier checks evidence IDs and structured IP/account/time/login assertions. The model cannot set verification or approval status. Response actions are never executed; recommendations remain pending human approval. The local ATT&CK catalog does not perform IP reputation checks or live threat-intelligence lookups.

Existing incident report endpoints include the structured investigation and freshly computed verifier results: `GET /api/incidents/{incident_id}/report` and `GET /api/incidents/{incident_id}/report.md`. No database migration or new table is required.
