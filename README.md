# lthm-resume

Personal resume/portfolio site with a private, password-protected stats dashboard.

## What is in this repo

- Public portfolio page at `/`
- Private stats dashboard at `/stats`
- Plaintext stats import page at `/stats/import`
- Raw drilldown endpoint for HTMX partial updates at `/stats/raw`

## Tech stack

- Python
- Flask
- pandas
- SQLite (in-memory data shaping for analytics)
- Plotly
- HTMX
- Jinja2 templates
- Waitress (serving)

## Project layout

- `app.py`: Flask app and routes
- `stats_service.py`: parsing, dedupe, analytics, chart generation, import logic
- `content.py`: public page content data
- `templates/`: Jinja templates
- `static/`: styles, JS, images
- `stats/`: source data files used by the private dashboard

## Requirements

- Python 3.10+ (3.11+ recommended)

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Environment variables

- `STATS_PASSWORD` (required for `/stats` access)
- `FLASK_SECRET_KEY` (recommended; fallback is random per process start)
- `PORT` (optional, default `8000`)
- `HOST` (optional, default `localhost`)
- `WAITRESS_THREADS` (optional, default `8`)

Example:

```bash
export STATS_PASSWORD="your-password"
export FLASK_SECRET_KEY="replace-with-long-random-secret"
```

## Run locally

Option 1 (same behavior as code entrypoint):

```bash
python3 app.py
```

Option 2 (same as `Procfile` style):

```bash
python3 -m waitress --listen=0.0.0.0:${PORT:-8000} app:app
```

Health endpoint:

- `GET /healthz` -> `{"status":"ok"}`

## Stats data format

Dashboard data is loaded from markdown/text files in `stats/`:

- `Home.md`
- `Home  Work.md`
- `Work Home.md`
- `Work.md`
- `Sleep.md`

Expected event line format:

```text
Event text at DD/MM/YYYY, HH.MM
```

Example:

```text
Left home at 05/03/2026, 08.14
```

Notes:

- Non-event lines are ignored.
- Events are deduplicated by `(source, event text, timestamp)`.
- Importing a full file repeatedly is supported.

## Private dashboard flow

1. Open `/stats/login`
2. Authenticate with `STATS_PASSWORD`
3. Use `/stats` for analytics/charts
4. Use `/stats/import` to paste full plaintext exports into a selected source file

## Deploying to Azure App Service

This repo includes:

- `Procfile`:
  - `web: sh -c 'python3 -m waitress --listen=0.0.0.0:${PORT:-8000} app:app'`

Recommended app settings in Azure:

- `STATS_PASSWORD`
- `FLASK_SECRET_KEY`
- `SCM_DO_BUILD_DURING_DEPLOYMENT=true` (if using Oryx build)

Also ensure `requirements.txt` is present (it is) so dependencies install on deploy.
