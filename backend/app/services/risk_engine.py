import hashlib
import time
from typing import List, Dict, Tuple

BLACKLIST = set()   # 后面接数据库
WHITELIST = set()

def _score_to_level_decision(score: int) -> Tuple[str, str]:
    # 你后面在 A9 页面可配置阈值；先硬编码
    if score >= 90:
        return "BLOCKED", "BLOCK"
    if score >= 70:
        return "HIGH", "REQUIRE_CONFIRM"
    if score >= 40:
        return "MEDIUM", "ALLOW"
    return "LOW", "ALLOW"

def assess(chain: str, to_address: str, amount: float) -> Tuple[int, str, str, List[str], Dict]:
    reason_codes: List[str] = []
    model_votes: Dict = {}

    if to_address in BLACKLIST:
        return 100, "BLOCKED", "BLOCK", ["BLACKLIST_HIT"], {"rule": "BLACKLIST"}

    if to_address in WHITELIST:
        # 白名单允许但记录
        base = 10
        reason_codes.append("WHITELIST_HIT")
    else:
        base = 30

    # 简单规则：金额越大风险越高（占位逻辑）
    if amount >= 100000:
        base += 40
        reason_codes.append("LARGE_AMOUNT")
    elif amount >= 10000:
        base += 20
        reason_codes.append("MEDIUM_LARGE_AMOUNT")

    # 假装模型投票（占位，后面换 IsolationForest/XGB/GNN）
    model_votes["IsolationForest"] = {"triggered": base >= 70, "score": base / 100}
    model_votes["XGBoost"] = {"triggered": base >= 80, "prob": min(0.99, base / 100)}
    model_votes["GNN"] = {"triggered": base >= 90, "embed_risk": min(1.0, base / 100)}

    score = max(0, min(100, base))
    level, decision = _score_to_level_decision(score)
    if not reason_codes:
        reason_codes.append("NO_SIGNIFICANT_RISK")

    return score, level, decision, reason_codes, model_votes

def make_request_id(chain: str, to_address: str, amount: float) -> str:
    raw = f"{time.time()}|{chain}|{to_address}|{amount}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]
