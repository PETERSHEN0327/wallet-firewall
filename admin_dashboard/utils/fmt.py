from datetime import datetime

def safe_str(x) -> str:
    return "" if x is None else str(x)

def shorten(s: str, n: int = 10) -> str:
    if not s:
        return ""
    s = str(s)
    if len(s) <= n:
        return s
    return s[: n//2] + "…" + s[-(n//2):]

def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

def pretty_ts(ts: str) -> str:
    dt = parse_iso(ts) if ts else None
    if not dt:
        return safe_str(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S")
