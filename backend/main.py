"""FastAPI backend for the Smart Log Analyzer."""
import os
import sys
import threading
from pathlib import Path

# Fix path for Render deployment (when run from repo root)
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from db import bulk_insert_log, insert_flags, clear_all, query_logs, \
    flagged_with_logs, pending_flags, update_ai, set_reviewed, stats, \
    chart_timeline, chart_severity, chart_top_ips
from parser import load_file, parse_line
from detector import detect
from ai_explainer import explain_entry
from generate_data import generate

app = FastAPI(title="Smart Log Analyzer")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

FRONTEND = Path(__file__).parent.parent / "frontend"


def _get_key():
    key = os.environ.get("OPENROUTER_API_KEY", "")
    env_file = Path(__file__).parent / ".env"
    if not key and env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("OPENROUTER_API_KEY="):
                key = line.split("=", 1)[1].strip().strip('"')
    return key


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


@app.post("/api/ingest/sample")
def ingest_sample():
    clear_all()
    # Use real assignment data if available, fall back to synthetic generator
    assignment_csv = Path(__file__).parent.parent / "data" / "log-data.csv"
    if assignment_csv.exists():
        rows, skipped = load_file(str(assignment_csv))
    else:
        rows = generate()
        skipped = []
    ids = bulk_insert_log(rows)
    flags = detect(rows)
    insert_flags([{**f, "log_id": ids[f["row_index"]]} for f in flags])
    return {"inserted": len(ids), "flagged": len(flags), "skipped_invalid": len(skipped)}


@app.post("/api/ingest/file")
async def ingest_file(file: UploadFile = File(...)):
    tmp = Path(os.environ.get("TEMP", "/tmp")) / f"upload_{file.filename}"
    tmp.write_bytes(await file.read())
    try:
        rows, skipped = load_file(str(tmp))
    except Exception as e:
        raise HTTPException(400, f"could not parse file: {e}")
    if not rows:
        raise HTTPException(400, "no log entries found in file (empty dataset?)")
    clear_all()
    ids = bulk_insert_log(rows)
    flags = detect(rows)
    insert_flags([{**f, "log_id": ids[f["row_index"]]} for f in flags])
    return {"inserted": len(ids), "flagged": len(flags), "skipped_invalid": len(skipped)}


@app.post("/api/ingest/text")
async def ingest_text(payload: dict):
    text = (payload or {}).get("text", "")
    rows = [r for r in (parse_line(l) for l in text.splitlines()) if r]
    if not rows:
        raise HTTPException(400, "no valid-looking lines found")
    clear_all()
    ids = bulk_insert_log(rows)
    flags = detect(rows)
    insert_flags([{**f, "log_id": ids[f["row_index"]]} for f in flags])
    invalid = sum(1 for r in rows if not r["valid"])
    return {"inserted": len(ids), "flagged": len(flags), "invalid": invalid}


@app.get("/api/logs")
def get_logs(severity: str = None, only_invalid: bool = False,
             search: str = None, limit: int = 50, offset: int = 0):
    rows, total = query_logs(severity, only_invalid, search, limit, offset)
    return {"logs": rows, "total": total, "limit": limit, "offset": offset}


@app.get("/api/flags")
def get_flags(min_score: float = 0.0):
    return {"flags": flagged_with_logs(min_score)}


@app.get("/api/stats")
def get_stats():
    return stats()


# ─── Chart endpoints ────────────────────────────────────────────────

@app.get("/api/charts/timeline")
def get_chart_timeline():
    return {"data": chart_timeline()}


@app.get("/api/charts/severity")
def get_chart_severity():
    return {"data": chart_severity()}


@app.get("/api/charts/top-ips")
def get_chart_top_ips(limit: int = 10):
    return {"data": chart_top_ips(limit)}


# ─── AI explain ─────────────────────────────────────────────────────

class ExplainRequest(BaseModel):
    limit: int = 5


@app.post("/api/explain")
def run_explain(req: ExplainRequest = ExplainRequest()):
    """Explain pending flagged entries via AI. Detection already happened locally."""
    key = _get_key()
    if not key:
        raise HTTPException(503, "OPENROUTER_API_KEY not configured — see README AI setup")
    batch = pending_flags(min(req.limit, 20))
    done = 0
    for b in batch:
        flag_row = next((f for f in flagged_with_logs() if f["flag_id"] == b["id"]), None)
        reasons = flag_row["reasons"] if flag_row else []
        score = flag_row["anomaly_score"] if flag_row else 0
        try:
            expl, cause, step = explain_entry(b, score, reasons, key)
            update_ai(b["id"], expl, cause, step, "done")
            done += 1
        except Exception as e:
            update_ai(b["id"], None, None, None, "error")
            print(f"[ai] failed on flag {b['id']}: {e}")
    remaining = len(pending_flags(limit=1000))
    return {"explained": done, "remaining": remaining}


@app.post("/api/flags/{flag_id}/review")
def review(flag_id: int, payload: dict):
    set_reviewed(flag_id, bool(payload.get("reviewed")))
    return {"ok": True}


# background explainer thread: keeps chipping away at the queue
def _bg_explainer():
    import time
    while True:
        time.sleep(20)   # pace to stay under free-tier rate limits
        try:
            if pending_flags(limit=1) and _get_key():
                run_explain(ExplainRequest(limit=1))
        except Exception:
            pass


threading.Thread(target=_bg_explainer, daemon=True).start()
