import os
import requests
from typing import Any, Dict, Optional, Tuple

DEFAULT_BACKEND = "http://127.0.0.1:8000"

def backend_base() -> str:
    # 优先环境变量，其次默认本地
    return os.getenv("BACKEND_URL", DEFAULT_BACKEND).rstrip("/")

def _url(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return backend_base() + path

def get_json(path: str, params: Optional[Dict[str, Any]] = None, timeout: int = 10) -> Tuple[bool, Any, str]:
    try:
        r = requests.get(_url(path), params=params, timeout=timeout)
        if r.status_code >= 400:
            return False, None, f"HTTP {r.status_code}: {r.text[:200]}"
        return True, r.json(), ""
    except Exception as e:
        return False, None, str(e)

def post_json(path: str, json: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, timeout: int = 10) -> Tuple[bool, Any, str]:
    try:
        r = requests.post(_url(path), json=json, params=params, timeout=timeout)
        if r.status_code >= 400:
            return False, None, f"HTTP {r.status_code}: {r.text[:200]}"
        # 有些接口可能不返回 json
        try:
            return True, r.json(), ""
        except Exception:
            return True, r.text, ""
    except Exception as e:
        return False, None, str(e)

def healthcheck() -> Tuple[bool, str]:
    ok, data, err = get_json("/health")
    if not ok:
        return False, err
    if isinstance(data, dict) and data.get("status") == "ok":
        return True, "ok"
    return False, f"unexpected response: {data}"
