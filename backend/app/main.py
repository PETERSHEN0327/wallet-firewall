from fastapi import FastAPI, HTTPException
from datetime import datetime, timezone
from .models.schemas import TxRequest, RiskResult, TxReceipt
from .services.risk_engine import assess, make_request_id
from .utils.logger import init_db, log_intercept, get_recent_intercepts, get_by_request_id, list_add, list_remove, list_get

app = FastAPI(title="Wallet Firewall API")

@app.on_event("startup")
def _startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/risk/check", response_model=RiskResult)
def risk_check(req: TxRequest):
    request_id = make_request_id(req.chain, req.to_address, req.amount_usdt)
    score, level, decision, reasons, votes = assess(req.chain, req.to_address, req.amount_usdt)

    row = {
        "request_id": request_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "chain": req.chain,
        "from_address": req.from_address,
        "to_address": req.to_address,
        "amount_usdt": req.amount_usdt,
        "risk_score": score,
        "risk_level": level,
        "decision": decision,
        "reason_codes": ",".join(reasons),
        "forced": 0,
        "tx_hash": None
    }
    log_intercept(row)

    return RiskResult(
        risk_score=score,
        risk_level=level,
        decision=decision,
        reason_codes=reasons,
        model_votes=votes,
        request_id=request_id
    )

@app.post("/tx/send", response_model=TxReceipt)
def tx_send(request_id: str, forced: bool = False):
    row = get_by_request_id(request_id)
    if not row:
        raise HTTPException(404, "request_id not found")

    if row["decision"] == "BLOCK" and not forced:
        return TxReceipt(status="BLOCKED", request_id=request_id, tx_hash=None)

    # MVP：不真的广播链上，生成 pseudo tx_hash
    tx_hash = f"tx_{request_id}"
    row["forced"] = 1 if forced else 0
    row["tx_hash"] = tx_hash
    log_intercept(row)

    status = "FORCED_LOGGED" if forced else "FORWARDED"
    return TxReceipt(status=status, request_id=request_id, tx_hash=tx_hash)

@app.get("/admin/intercepts")
def admin_intercepts(limit: int = 200):
    return {"items": get_recent_intercepts(limit=limit)}

@app.get("/admin/intercepts/{request_id}")
def admin_intercept_detail(request_id: str):
    row = get_by_request_id(request_id)
    if not row:
        raise HTTPException(404, "not found")
    return row

@app.post("/admin/list/add")
def admin_list_add(kind: str, address: str):
    if kind not in ("BLACKLIST", "WHITELIST"):
        raise HTTPException(400, "kind must be BLACKLIST or WHITELIST")
    list_add(kind, address)
    return {"ok": True}

@app.post("/admin/list/remove")
def admin_list_remove(kind: str, address: str):
    if kind not in ("BLACKLIST", "WHITELIST"):
        raise HTTPException(400, "kind must be BLACKLIST or WHITELIST")
    list_remove(kind, address)
    return {"ok": True}

@app.get("/admin/list")
def admin_list(kind: str):
    if kind not in ("BLACKLIST", "WHITELIST"):
        raise HTTPException(400, "kind must be BLACKLIST or WHITELIST")
    return {"items": list_get(kind)}
