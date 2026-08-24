"""Multi-signal anomaly detector (our own implementation — no AI here).

Signals, combined into a 0..10 score:
  1. Severity weight          — CRITICAL/FATAL entries carry intrinsic weight.
  2. Per-IP request-rate spike— an IP whose rate z-score > threshold vs the fleet.
  3. Error-frequency z-score  — a time bucket whose error rate deviates from the norm.
  4. Status-code rarity       — status codes seen far below expected frequency.
  5. Repeat-failure streak    — same IP failing repeatedly in a short window.
  6. Off-hours bonus          — entries during 00:00–06:00 get a small weight bump.
"""
from collections import Counter, defaultdict
from datetime import datetime
import math

SEV_WEIGHT = {"INFO": 0.0, "WARN": 1.5, "ERROR": 3.0, "CRITICAL": 5.0}


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def _zscore(x, xs):
    if len(xs) < 3:
        return 0.0
    mu = _mean(xs)
    var = sum((v - mu) ** 2 for v in xs) / len(xs)
    sd = math.sqrt(var)
    return 0.0 if sd < 1e-9 else (x - mu) / sd


def _precompute_streaks(valid_rows):
    """O(N) forward-pass streak computation per IP.

    Returns a dict mapping row_index -> streak_length for rows that are
    failures (status >= 400). A streak is the count of consecutive failures
    from the same IP ending at (and including) this row.
    """
    by_ip = defaultdict(list)
    for idx, r in sorted(valid_rows, key=lambda x: x[1]["timestamp"]):
        if r.get("source_ip"):
            is_fail = bool(r.get("status_code") and r["status_code"] >= 400)
            by_ip[r["source_ip"]].append((idx, is_fail))

    streak_map = {}
    for ip, entries in by_ip.items():
        current_streak = 0
        for row_idx, failed in entries:
            if failed:
                current_streak += 1
            else:
                current_streak = 0
            if current_streak >= 3:
                streak_map[row_idx] = current_streak
    return streak_map


def detect(rows):
    """rows: list of parsed row dicts (with 'timestamp', 'source_ip', 'severity',
    'status_code'). Returns list of {row_index, score, reasons}."""
    valid = [(i, r) for i, r in enumerate(rows)
             if r.get("valid") and r.get("timestamp")]
    results = []

    # --- Precompute per-IP counts and per-minute error rates -------------
    ip_counts = Counter(r["source_ip"] for _, r in valid)
    per_minute_errors = defaultdict(int)
    minute_total = Counter()
    for _, r in valid:
        minute_key = r["timestamp"][:16]  # YYYY-MM-DD HH:MM
        minute_total[minute_key] += 1
        if r.get("status_code", 0) and r["status_code"] >= 400:
            per_minute_errors[minute_key] += 1

    err_rates = [per_minute_errors[m] / minute_total[m]
                 for m in minute_total if minute_total[m] >= 3]

    # status code frequency for rarity signal
    code_counts = Counter(r["status_code"] for _, r in valid if r.get("status_code"))
    total_codes = sum(code_counts.values()) or 1

    # O(N) failure streak precomputation
    streak_map = _precompute_streaks(valid)

    for idx, r in enumerate(rows):
        if not (r.get("valid") and r.get("timestamp")):
            continue
        score, reasons = 0.0, []

        # 1. severity weight
        sev_w = SEV_WEIGHT.get(r.get("severity"), 0.0)
        if sev_w >= 1.5:
            score += sev_w
            reasons.append(f"high severity '{r['severity']}' (+{sev_w:.1f})")

        # 2. IP rate spike
        ip = r.get("source_ip")
        if ip:
            counts = list(ip_counts.values())
            z = _zscore(ip_counts[ip], counts)
            if z > 2.0:
                pts = min(3.0, (z - 2.0) * 1.2)
                score += pts
                reasons.append(f"IP {ip} volume spike: {ip_counts[ip]} requests "
                               f"(z={z:.1f}, +{pts:.1f})")

        # 3. error-rate deviation in its minute
        mk = r["timestamp"][:16]
        if minute_total.get(mk, 0) >= 3 and err_rates:
            rate = per_minute_errors[mk] / minute_total[mk]
            z = _zscore(rate, err_rates)
            if z > 2.0 and rate > 0.15:
                pts = min(3.0, (z - 2.0) * 1.0 + rate)
                score += pts
                reasons.append(f"error burst at {mk}: {per_minute_errors[mk]}/{minute_total[mk]} "
                               f"failed (z={z:.1f}, +{pts:.1f})")

        # 4. status-code rarity (<1% of traffic and is an error)
        code = r.get("status_code")
        if code and code >= 400 and code_counts[code] / total_codes < 0.01:
            score += 1.0
            reasons.append(f"rare status code {code}: {code_counts[code]} occurrences "
                           f"({100*code_counts[code]/total_codes:.1f}% of traffic, +1.0)")

        # 5. failure streak (O(1) lookup from precomputed map)
        if idx in streak_map:
            score += 1.5
            reasons.append(f"{streak_map[idx]} consecutive failures from {ip} (+1.5)")

        # 6. off-hours bonus (00:00–06:00 local time)
        try:
            hour = int(r["timestamp"][11:13])
            if 0 <= hour < 6:
                score += 0.8
                reasons.append(f"off-hours activity at {r['timestamp'][11:16]} (+0.8)")
        except (ValueError, IndexError):
            pass

        if score >= 2.0:  # flagging threshold
            results.append({"row_index": idx, "score": round(min(score, 10.0), 2),
                            "reasons": reasons})
    return results
