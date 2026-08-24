"""Synthesize a realistic dataset: mostly-normal traffic + injected anomalies."""
import random
from datetime import datetime, timedelta

PATHS = ["/api/users", "/api/orders", "/api/products", "/api/cart",
         "/api/session", "/health", "/static/app.js", "/api/search"]
GOOD_IPS = ["192.168.1.14", "192.168.1.27", "10.0.0.55", "172.16.4.9"]
ERROR_PATHS = ["/api/payment", "/api/orders", "/api/checkout"]


def generate(n=400, seed=42):
    rng = random.Random(seed)
    rows = []
    t = datetime(2026, 8, 20, 9, 0, 0)
    for _ in range(n):
        t += timedelta(seconds=rng.randint(1, 12))
        ip = rng.choice(GOOD_IPS)
        code = 200 if rng.random() < 0.92 else rng.choice([404, 500])
        path = rng.choice(PATHS)
        rows.append(_fmt(t, ip, code, f"{'GET' if code != 500 or rng.random() < .5 else 'POST'} {path}"))

    # --- Injected anomalies -------------------------------------------------
    # A1: brute-force burst from one external IP
    attacker = "203.0.113.7"
    bt = datetime.strptime(rows[120][0], "%Y-%m-%d %H:%M:%S")
    for k in range(30):
        rows.append(_fmt(bt + timedelta(seconds=k * 2), attacker,
                         rng.choice([403] * 6 + [401]), f"POST /login — auth attempt {k}"))
    # A2: payment-service meltdown (error burst)
    mt = datetime.strptime(rows[220][0], "%Y-%m-%d %H:%M:%S")
    for k in range(12):
        rows.append(_fmt(mt + timedelta(seconds=k * 3), GOOD_IPS[k % 2], 500,
                         f"POST /api/payment — upstream timeout ({k})"))
    # A3: rare critical status + data exfil pattern
    xt = datetime.strptime(rows[300][0], "%Y-%m-%d %H:%M:%S")
    for k in range(5):
        rows.append(_fmt(xt + timedelta(minutes=k), "198.51.100.23", 503,
                         f"GET /api/users/export?all=true — service unavailable"))

    rows.sort(key=lambda r: r[0])
    return [{"timestamp": r[0], "source_ip": r[1], "status_code": r[2],
             "message": r[3], "event_type": r[3].split()[0],
             "severity": ("CRITICAL" if r[2] >= 500 else
                          "ERROR" if r[2] >= 400 else
                          "WARN" if r[2] >= 300 else "INFO"),
             "valid": True, "validation_error": None} for r in rows]


def _fmt(t, ip, code, msg):
    return (t.strftime("%Y-%m-%d %H:%M:%S"), ip, code, msg)


if __name__ == "__main__":
    import json, pathlib
    out = pathlib.Path(__file__).parent.parent / "data" / "sample_logs.csv"
    out.parent.mkdir(exist_ok=True)
    with open(out, "w") as f:
        f.write("timestamp,source_ip,status_code,message\n")
        for r in generate():
            f.write(f'{r["timestamp"]},{r["source_ip"]},{r["status_code"]},{r["message"]}\n')
    print(f"wrote {out}")
