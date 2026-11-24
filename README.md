# Ephemeral-Scope

Explainable analysis of Python dependency upgrade risk. Upload a project,
pick a dependency and a target version, and get back the migration risk, the
upgrade urgency, the code the upgrade touches, the tests to run and the
actions to take.

## Layout

| Path | What it is |
| --- | --- |
| `src/ephemeral_scope/` | Analysis pipeline: ingestion, AST usage analysis, API comparison, evidence, classification, Prolog inference, reporting |
| `src/ephemeral_scope/api/` | FastAPI layer over the pipeline: uploads, background jobs, version lookup |
| `frontend/` | React (Vite) single-page app |
| `tests/` | Unit tests, API tests, and end-to-end cases under `tests/e2e/` |
| `frontend/e2e/` | Browser tests (Playwright) against the real stack |

## Requirements

- Python 3.12 or newer
- [SWI-Prolog](https://www.swi-prolog.org/) on `PATH` (`brew install swi-prolog`).
  Without it the service falls back to the Python rules and says so in the report.
- Node.js 20 or newer, for the frontend

## Run it locally

Two terminals, from the repository root.

```bash
# 1. API on http://127.0.0.1:8765
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,web]"
uvicorn ephemeral_scope.api.app:create_app --factory --port 8765
```

```bash
# 2. Frontend on http://127.0.0.1:5273
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5273. The dev server proxies `/api` to the API; set
`VITE_API_TARGET` if the API is somewhere else.

To serve everything from one process instead, build the frontend and start
only the API. It serves `frontend/dist` when that directory exists:

```bash
cd frontend && npm run build && cd ..
uvicorn ephemeral_scope.api.app:create_app --factory --port 8765
```

Run a single API process. Jobs and uploads are held in memory, so several
workers would each see a different set.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Whether Prolog and the trained classifier are loaded; job counts |
| `POST` | `/api/projects` | Upload a project ZIP (multipart field `file`). Returns its id and declared dependencies |
| `GET` | `/api/projects/{id}` | The same summary again |
| `GET` | `/api/packages/{name}/versions` | Released versions from PyPI, newest first |
| `POST` | `/api/analyses` | Queue an analysis: `project_id`, `package_name`, `current_version`, `target_version`. Returns `202` with a job id |
| `GET` | `/api/analyses?ids=a,b` | Status of the named jobs |
| `GET` | `/api/analyses/{id}` | One job, with its report once `status` is `done` |

Analyses run on a bounded thread pool, so several run at once and the request
that queues one returns immediately. An identical request (same archive,
package and versions) is answered with the existing job.

Settings, all optional:

| Variable | Default | Meaning |
| --- | --- | --- |
| `EPHEMERAL_SCOPE_WORKERS` | `4` | Analyses running at the same time |
| `EPHEMERAL_SCOPE_MAX_PENDING` | `32` | Analyses allowed to wait before new ones are refused |
| `EPHEMERAL_SCOPE_CORS_ORIGINS` | none | Comma-separated origins, if the frontend is served from another origin |
| `EPHEMERAL_SCOPE_SWIPL` | `swipl` | SWI-Prolog executable |
| `EPHEMERAL_SCOPE_OFFLINE` | off | Use cached HTTP responses only |

## Tests

```bash
python -m pytest -q                                          # offline suite
python -m pytest tests/e2e -m "integration and not live" -q  # recorded end-to-end cases
python -m pytest tests/e2e -m "live and integration" -q -s   # real PyPI, GitHub and OSV
cd frontend && npx playwright install chromium && npm run test:e2e   # browser, real stack
```

The browser tests start the API and the dev server themselves, and contact
PyPI, GitHub and OSV.

## Classifier evaluation

```bash
python scripts/evaluate_classifiers.py
```
