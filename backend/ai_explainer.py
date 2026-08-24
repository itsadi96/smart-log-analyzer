"""AI explainer: turns detector-flagged entries into plain-English explanations
via OpenRouter. Detection itself is NOT done by AI (per requirements)."""
import json
import urllib.request

MODEL = "stealth/ox-alpha"  # reasoning model; JSON in message.content
BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

SYSTEM_PROMPT = """You are a senior SRE analyzing a single flagged log entry.
Given the entry and the rule-based anomaly signals that flagged it, respond with
STRICT JSON only:
{"explanation": "<2-3 sentences, plain English, what happened>",
 "root_cause": "<most likely root cause, 1-2 sentences>",
 "next_step": "<one concrete next action for an on-call engineer>"}
No markdown, no code fences."""


def explain_entry(row, score, reasons, api_key):
    user_msg = json.dumps({
        "log_entry": {k: row.get(k) for k in
                      ("timestamp", "source_ip", "event_type", "severity",
                       "status_code", "message")},
        "anomaly_score": score,
        "why_flagged": reasons,
    })
    payload = json.dumps({
        "model": MODEL,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": user_msg}],
        "temperature": 0.2,
        "max_tokens": 1500,  # reasoning models burn tokens on hidden thinking
    }).encode()

    req = urllib.request.Request(
        BASE_URL, data=payload,
        headers={"Authorization": f"Bearer {api_key}",
                 "Content-Type": "application/json"})
    data = None
    for attempt in range(3):  # retry transient network errors / rate limits
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                import time; time.sleep(15 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, OSError):
            if attempt < 2:
                import time; time.sleep(5)
                continue
            raise
    content = data["choices"][0]["message"]["content"].strip()
    if content.startswith("```"):
        content = content.strip("`").lstrip("json").strip()
    parsed = json.loads(content)
    return (parsed.get("explanation", "").strip(),
            parsed.get("root_cause", "").strip(),
            parsed.get("next_step", "").strip())
