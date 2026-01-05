from pydantic import BaseModel, Field
from typing import List, Optional, Literal

Decision = Literal["ALLOW", "REQUIRE_CONFIRM", "BLOCK"]
RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "BLOCKED"]

class TxRequest(BaseModel):
    chain: Literal["TRON", "ETHEREUM"]
    from_address: Optional[str] = None
    to_address: str
    amount_usdt: float = Field(gt=0)
    memo: Optional[str] = None

class RiskResult(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    decision: Decision
    reason_codes: List[str]
    model_votes: dict
    request_id: str

class TxReceipt(BaseModel):
    status: Literal["FORWARDED", "BLOCKED", "FORCED_LOGGED"]
    request_id: str
    tx_hash: Optional[str] = None
