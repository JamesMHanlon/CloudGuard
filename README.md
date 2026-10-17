# CloudGuard

Multi-cloud compliance scanner for AWS, Azure and GCP. Checks resources
against CIS, NIST and ISO 27001 controls, scores them with a Gradient
Boosting model, and explains violations in plain English using Claude.

BS3203 Computing Project — James Hanlon, University of Winchester.

## Run it

```bash
pip install -r requirements.txt
python run.py
# open http://127.0.0.1:8000
```

Needs Python 3.11 or newer. First launch trains the model (about 5–10
seconds); after that it starts in roughly a second. The Anthropic API
key is already in `.env`, so the in-app explanations work out of the
box. Stop with `Ctrl + C`.

## What's in the UI

The sidebar has four views:

- **Dashboard** — KPIs, per-cloud and per-framework charts, top-risk table
- **Resources** — filter and inspect every scanned resource. Click a row for the full violation list and Claude-generated explanations.
- **ML Insights** — feature importances, risk distribution, scatter plot
- **Custom Scan** — paste your own JSON or drop a file (up to 200 resources). Two sample files are linked at the top of the tab.

## Tests

```bash
python -m pytest tests/
```

108 tests in total — 82 rule unit tests, 13 feature-extractor tests,
12 API integration tests. All should pass in a couple of seconds.

## Project structure

```
backend/   FastAPI app, rule engine, ML pipeline, RAG
frontend/  HTML + CSS + JS, no build step
data/      Mock resources, knowledge base, sample files
tests/     pytest suite
run.py     Entry point
.env       ANTHROPIC_API_KEY
```

## Notes

- The interactive API docs are at `/docs` when the server is running.
- Port 8000 already used? Run `CLOUDGUARD_PORT=8001 python run.py`.
- To retrain the ML model from scratch, delete
  `backend/ml/trained_model.joblib` and re-run.
- Without the API key the app still works — rule scanning and ML risk
  scoring run normally, but the resource modal shows "API key not
  configured" instead of generated explanations.
