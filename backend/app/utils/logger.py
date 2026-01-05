import sqlite3
from pathlib import Path
from typing import Any, Dict

DB_PATH = Path(__file__).resolve().parents[3] / "data" / "app.db"

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS intercept_log (
            request_id TEXT PRIMARY KEY,
            ts TEXT,
            chain TEXT,
            from_address TEXT,
            to_address TEXT,
            amount_usdt REAL,
            risk_score INTEGER,
            risk_level TEXT,
            decision TEXT,
            reason_codes TEXT,
            forced INTEGER DEFAULT 0,
            tx_hash TEXT
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS list_store (
            kind TEXT,
            address TEXT,
            PRIMARY KEY(kind, address)
        )
        """)
        conn.commit()

def log_intercept(row: Dict[str, Any]):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
        INSERT OR REPLACE INTO intercept_log
        (request_id, ts, chain, from_address, to_address, amount_usdt, risk_score, risk_level, decision, reason_codes, forced, tx_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["request_id"], row["ts"], row["chain"], row.get("from_address"),
            row["to_address"], row["amount_usdt"], row["risk_score"], row["risk_level"],
            row["decision"], row["reason_codes"], row.get("forced", 0), row.get("tx_hash")
        ))
        conn.commit()

def list_add(kind: str, address: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT OR IGNORE INTO list_store(kind, address) VALUES(?, ?)", (kind, address))
        conn.commit()

def list_remove(kind: str, address: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM list_store WHERE kind=? AND address=?", (kind, address))
        conn.commit()

def list_get(kind: str):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("SELECT address FROM list_store WHERE kind=?", (kind,))
        return [r[0] for r in cur.fetchall()]

def get_recent_intercepts(limit: int = 200):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("""
        SELECT request_id, ts, chain, from_address, to_address, amount_usdt, risk_score, risk_level, decision, reason_codes, forced, tx_hash
        FROM intercept_log
        ORDER BY ts DESC
        LIMIT ?
        """, (limit,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

def get_by_request_id(request_id: str):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("""
        SELECT request_id, ts, chain, from_address, to_address, amount_usdt, risk_score, risk_level, decision, reason_codes, forced, tx_hash
        FROM intercept_log
        WHERE request_id=?
        """, (request_id,))
        row = cur.fetchone()
        if not row:
            return None
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))
