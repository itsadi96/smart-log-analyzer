"""SQLite persistence layer: logs + flagged anomalies."""
import sqlite3, json, threading
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "logs.db"
DB_PATH.parent.mkdir(exist_ok=True)
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS log_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    event_type TEXT,
    severity TEXT,
    status_code INTEGER,
    message TEXT,
    raw_line TEXT,
    valid INTEGER DEFAULT 1,
    validation_error TEXT,
    user_agent TEXT,
    session_id TEXT,
    location TEXT
);
CREATE TABLE IF NOT EXISTS flagged_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id INTEGER NOT NULL REFERENCES log_entries(id),
    anomaly_score REAL NOT NULL,
    reasons TEXT NOT NULL,          -- JSON list of reason strings
    ai_explanation TEXT,
    ai_root_cause TEXT,
    ai_next_step TEXT,
    ai_status TEXT DEFAULT 'pending',  -- pending | done | error
    reviewed INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON log_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_flag_score ON flagged_entries(anomaly_score DESC);
"""


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock, get_conn() as conn:
        conn.executescript(SCHEMA)


def insert_log(conn, row):
    cur = conn.execute(
        """INSERT INTO log_entries
           (timestamp, source_ip, event_type, severity, status_code, message, raw_line, valid, validation_error,
            user_agent, session_id, location)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (row.get("timestamp"), row.get("source_ip"), row.get("event_type"),
         row.get("severity"), row.get("status_code"), row.get("message"),
         row.get("raw_line"), int(row.get("valid", True)), row.get("validation_error"),
         row.get("user_agent"), row.get("session_id"), row.get("location")))
    return cur.lastrowid


def bulk_insert_log(rows):
    with _lock, get_conn() as conn:
        ids = [insert_log(conn, r) for r in rows]
        conn.commit()
    return ids


def insert_flags(flags):
    """flags: list of dicts {log_id, anomaly_score, reasons}"""
    with _lock, get_conn() as conn:
        for f in flags:
            conn.execute(
                "INSERT INTO flagged_entries (log_id, anomaly_score, reasons) VALUES (?,?,?)",
                (f["log_id"], f["score"], json.dumps(f["reasons"])))
        conn.commit()


def clear_all():
    with _lock, get_conn() as conn:
        conn.executescript("DELETE FROM flagged_entries; DELETE FROM log_entries;")


def query_logs(severity=None, only_invalid=False, search=None, limit=500, offset=0):
    q = ("SELECT l.*, f.id AS flag_id, f.anomaly_score, f.reasons, f.ai_explanation, "
         "f.ai_root_cause, f.ai_next_step, f.ai_status, f.reviewed "
         "FROM log_entries l LEFT JOIN flagged_entries f ON f.log_id = l.id WHERE 1=1")
    count_q = "SELECT COUNT(*) c FROM log_entries l WHERE 1=1"
    args = []
    count_args = []
    if severity:
        q += " AND l.severity = ?"
        count_q += " AND l.severity = ?"
        args.append(severity)
        count_args.append(severity)
    if only_invalid:
        q += " AND l.valid = 0"
        count_q += " AND l.valid = 0"
    if search:
        q += " AND (l.source_ip LIKE ? OR l.message LIKE ? OR l.event_type LIKE ?)"
        count_q += " AND (l.source_ip LIKE ? OR l.message LIKE ? OR l.event_type LIKE ?)"
        s = f"%{search}%"
        args += [s, s, s]
        count_args += [s, s, s]
    q += " ORDER BY l.timestamp DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    with get_conn() as conn:
        total = conn.execute(count_q, count_args).fetchone()["c"]
        rows = [dict(r) for r in conn.execute(q, args)]
    return rows, total


def flagged_with_logs(min_score=0.0):
    q = ("SELECT l.*, f.id AS flag_id, f.anomaly_score, f.reasons, f.ai_explanation, "
         "f.ai_root_cause, f.ai_next_step, f.ai_status, f.reviewed, f.created_at AS flagged_at "
         "FROM flagged_entries f JOIN log_entries l ON l.id = f.log_id "
         "WHERE f.anomaly_score >= ? ORDER BY f.anomaly_score DESC")
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute(q, (min_score,))]
    import json as _json
    for r in rows:
        try:
            r["reasons"] = _json.loads(r["reasons"])
        except Exception:
            r["reasons"] = [r["reasons"]]
    return rows


def pending_flags(limit=10):
    q = ("SELECT f.id, l.* FROM flagged_entries f JOIN log_entries l ON l.id = f.log_id "
         "WHERE f.ai_status = 'pending' ORDER BY f.anomaly_score DESC LIMIT ?")
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(q, (limit,))]


def update_ai(flag_id, explanation, root_cause, next_step, status="done"):
    with _lock, get_conn() as conn:
        conn.execute(
            "UPDATE flagged_entries SET ai_explanation=?, ai_root_cause=?, ai_next_step=?, ai_status=? WHERE id=?",
            (explanation, root_cause, next_step, status, flag_id))
        conn.commit()


def set_reviewed(flag_id, reviewed):
    with _lock, get_conn() as conn:
        conn.execute("UPDATE flagged_entries SET reviewed=? WHERE id=?", (int(reviewed), flag_id))
        conn.commit()


def stats():
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM log_entries").fetchone()["c"]
        invalid = conn.execute("SELECT COUNT(*) c FROM log_entries WHERE valid=0").fetchone()["c"]
        flagged = conn.execute("SELECT COUNT(*) c FROM flagged_entries").fetchone()["c"]
        by_sev = dict(conn.execute("SELECT severity, COUNT(*) FROM log_entries GROUP BY severity").fetchall())
        explained = conn.execute("SELECT COUNT(*) c FROM flagged_entries WHERE ai_status='done'").fetchone()["c"]
    return {"total": total, "invalid": invalid, "flagged": flagged, "explained": explained, "by_severity": by_sev}


# ─── Chart data queries ─────────────────────────────────────────────

def chart_timeline():
    """Anomaly scores bucketed by minute for the timeline chart."""
    q = """SELECT substr(l.timestamp, 1, 16) AS minute,
                  COUNT(f.id) AS flag_count,
                  ROUND(AVG(f.anomaly_score), 2) AS avg_score,
                  ROUND(MAX(f.anomaly_score), 2) AS max_score
           FROM flagged_entries f
           JOIN log_entries l ON l.id = f.log_id
           GROUP BY minute ORDER BY minute"""
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(q)]


def chart_severity():
    """Severity distribution counts."""
    q = "SELECT severity, COUNT(*) AS count FROM log_entries WHERE severity IS NOT NULL GROUP BY severity"
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(q)]


def chart_top_ips(limit=10):
    """Top IPs by number of flags."""
    q = """SELECT l.source_ip, COUNT(f.id) AS flag_count,
                  ROUND(AVG(f.anomaly_score), 2) AS avg_score
           FROM flagged_entries f
           JOIN log_entries l ON l.id = f.log_id
           WHERE l.source_ip IS NOT NULL
           GROUP BY l.source_ip ORDER BY flag_count DESC LIMIT ?"""
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(q, (limit,))]


init_db()
