import os
from pathlib import Path

# 项目根目录
BASE_DIR = Path(__file__).resolve().parents[3]

# 数据库
DB_PATH = os.getenv(
    "DB_PATH",
    str(BASE_DIR / "data" / "app.db")
)

# 后端基础配置
APP_NAME = "Wallet Firewall API"
ENV = os.getenv("ENV", "dev")

# 风控阈值（后续可接 admin_dashboard）
RISK_THRESHOLDS = {
    "ALLOW_MAX": int(os.getenv("ALLOW_MAX", 69)),
    "REQUIRE_CONFIRM_MIN": int(os.getenv("REQUIRE_CONFIRM_MIN", 70)),
    "BLOCK_MIN": int(os.getenv("BLOCK_MIN", 90)),
}
