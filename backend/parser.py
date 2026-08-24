"""Log parsing + validation. Handles the assignment CSV format and generic formats.

Assignment CSV columns:
  Timestamp,IP_Address,Request_Type,Status_Code,User_Agent,Session_ID,Location

Also handles:
  Pipe-delimited: 2026-08-20 09:14:02 | 192.168.1.14 | 200 | GET /api/users — success
  Generic CSV: timestamp,ip,event,severity,status,message
"""
import csv
import re
from datetime import datetime

TS_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S",
              "%m/%d/%Y %H:%M:%S", "%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S,%f"]
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
SEVERITIES = {"DEBUG": 0, "INFO": 1, "WARN": 2, "WARNING": 2, "ERROR": 3, "CRITICAL": 4, "FATAL": 4}

# Assignment CSV column names (case-insensitive matching)
ASSIGNMENT_COLS = {"timestamp", "ip_address", "request_type", "status_code",
                   "user_agent", "session_id", "location"}


def parse_timestamp(raw):
    if not raw or not str(raw).strip():
        return None, "missing timestamp"
    raw = str(raw).strip()
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt).strftime("%Y-%m-%d %H:%M:%S"), None
        except ValueError:
            continue
    return None, f"malformed timestamp: {raw!r}"


def normalize_severity(sev):
    if sev:
        s = str(sev).strip().upper()
        if s in SEVERITIES:
            return s if s != "FATAL" else "CRITICAL"
    return None


def infer_from_status(code):
    code = int(code)
    if code >= 500: return "CRITICAL"
    if code >= 400: return "ERROR"
    if code >= 300: return "WARN"
    return "INFO"


def parse_assignment_row(row_dict):
    """Parse a row from the assignment CSV format (dict with Timestamp, IP_Address, etc.)."""
    raw_parts = ",".join(str(v) for v in row_dict.values())
    row = {"raw_line": raw_parts, "valid": True, "validation_error": None}

    ts, ts_err = parse_timestamp(row_dict.get("Timestamp", ""))
    row["timestamp"] = ts
    row["source_ip"] = str(row_dict.get("IP_Address", "")).strip() or None
    row["event_type"] = str(row_dict.get("Request_Type", "")).strip().upper() or None

    try:
        code = int(row_dict.get("Status_Code", 0))
        row["status_code"] = code if 100 <= code <= 599 else None
    except (ValueError, TypeError):
        row["status_code"] = None

    row["user_agent"] = str(row_dict.get("User_Agent", "")).strip() or None
    row["session_id"] = str(row_dict.get("Session_ID", "")).strip() or None
    row["location"] = str(row_dict.get("Location", "")).strip() or None

    # Build a descriptive message from the fields
    row["message"] = (f"{row['event_type'] or '?'} — "
                      f"status {row['status_code'] or '?'} — "
                      f"{row['user_agent'] or 'unknown agent'} — "
                      f"{row['location'] or 'unknown location'}")

    if ts_err:
        row["valid"], row["validation_error"] = False, ts_err
    elif not row["source_ip"]:
        row["valid"], row["validation_error"] = False, "missing source IP"

    if row["status_code"]:
        row["severity"] = infer_from_status(row["status_code"])
    else:
        row["severity"] = "INFO"

    return row


def parse_line(line):
    """Return a normalized row dict; never raises. Sets valid/validation_error."""
    line = (line or "").strip()
    if not line:
        return None
    row = {"raw_line": line, "valid": True, "validation_error": None}

    # pipe-delimited
    parts = [p.strip() for p in line.split("|")] if "|" in line else None
    # csv
    if parts is None and "," in line:
        cparts = next(csv.reader([line]))
        if len(cparts) >= 4:
            parts = [p.strip() for p in cparts]

    if parts and len(parts) >= 4:
        ts, ts_err = parse_timestamp(parts[0])
        row["timestamp"], row["source_ip"] = ts, None
        ip_m = IP_RE.search(parts[1]) if len(parts) > 1 else None
        row["source_ip"] = ip_m.group(0) if ip_m else parts[1] if len(parts) > 1 else None
        try:
            raw_code = int(re.sub(r"\D", "", parts[2]) or 0)
            row["status_code"] = raw_code if 100 <= raw_code <= 599 else None
        except ValueError:
            row["status_code"] = None
        row["event_type"] = (re.match(r"(GET|POST|PUT|DELETE|PATCH|LOGIN|AUTH\w*)", parts[3], re.I) or [None])[0]
        row["message"] = " | ".join(parts[3:]) if len(parts) > 4 else parts[3]
        if ts_err:
            row["valid"], row["validation_error"] = False, ts_err
        elif not row["source_ip"]:
            row["valid"], row["validation_error"] = False, "missing source"
        if row["status_code"]:
            row["severity"] = infer_from_status(row["status_code"])
        else:
            row["severity"] = "INFO"
        return row

    # free-form fallback: find timestamp & IP anywhere
    ts_m = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", line)
    ts = None
    if ts_m:
        ts, _err = parse_timestamp(ts_m.group(1))
    ip_m = IP_RE.search(line)
    sev_m = re.search(r"\[(DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)\]", line, re.I)
    code_m = re.search(r"\b([1-5]\d{2})\b", line)
    has_ts = bool(ts)
    row.update({
        "timestamp": ts, "source_ip": ip_m.group(0) if ip_m else None,
        "event_type": (re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\b", line, re.I) or [None])[0],
        "severity": normalize_severity(sev_m.group(1)) if sev_m else ("INFO" if code_m else None),
        "status_code": int(code_m.group(1)) if code_m else None,
        "message": line,
        "valid": has_ts,
        "validation_error": None if has_ts else "unparseable / missing timestamp",
    })
    if row["severity"] is None and row["status_code"]:
        row["severity"] = infer_from_status(row["status_code"])
    return row


def _detect_assignment_csv(header_line):
    """Check if this CSV has the assignment column format."""
    cols = {c.strip().lower() for c in header_line.split(",")}
    return cols >= {"timestamp", "ip_address", "request_type", "status_code"}


def load_file(path):
    """Load a .log/.csv/.txt file into rows. Skips blank lines and headers."""
    rows, skipped = [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)

        # Check if this is the assignment CSV format
        if _detect_assignment_csv(first):
            reader = csv.DictReader(fh)
            for i, row_dict in enumerate(reader):
                parsed = parse_assignment_row(row_dict)
                if parsed is None:
                    skipped.append((i + 1, "blank"))
                    continue
                if not parsed.get("valid"):
                    skipped.append((i + 1, parsed.get("validation_error")))
                rows.append(parsed)
            return rows, skipped

        # Generic CSV/log handling
        fh.seek(0)
        if "," in first and ("timestamp" in first.lower() or "time" in first.lower()):
            fh.readline()  # header
        for i, line in enumerate(fh):
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            parsed = parse_line(line)
            if parsed is None:
                skipped.append((i + 1, "blank"))
                continue
            if not parsed.get("valid"):
                skipped.append((i + 1, parsed.get("validation_error")))
            rows.append(parsed)
    return rows, skipped
