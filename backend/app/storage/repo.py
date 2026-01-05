from typing import List, Dict, Optional
from backend.app.storage.db import get_conn

def fetch_recent_intercepts(limit: int = 200) -> List[Dict]:
    with get_conn() as conn:
        cur = conn.execute("""
            SELECT *
            FROM intercept_log
            ORDER BY ts DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cur.fetchall()]

def fetch_intercept_by_request_id(request_id: str) -> Optional[Dict]:
    with get_conn() as conn:
        cur = conn.execute("""
            SELECT *
            FROM intercept_log
            WHERE request_id = ?
        """, (request_id,))
        row = cur.fetchone()
        return dict(row) if row else None
