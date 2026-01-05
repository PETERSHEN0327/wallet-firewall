import streamlit as st
from utils.api import backend_base, healthcheck
from utils.state import init_state

st.set_page_config(page_title="Wallet Firewall - Admin", layout="wide")

init_state()

st.sidebar.title("app admin")

st.sidebar.caption("Backend")
st.sidebar.code(backend_base(), language="text")

ok, msg = healthcheck()
if ok:
    st.sidebar.success("Backend: OK")
else:
    st.sidebar.error("Backend: DOWN")
    st.sidebar.caption(msg)

st.title("Wallet Firewall Admin Dashboard")

st.markdown("""
使用左侧菜单进入各功能页面：
- **Overview**：总体状态与关键指标
- **Intercepts**：拦截记录列表
- **Transaction Detail**：单笔请求详情
- **Wallets / Wallet Profile**：地址维度统计与画像
- **Cases**：案例管理（本地示例）
- **Graph Explorer**：关系图（本地示例）
- **Reports**：导出报告（示例）
- **Models Thresholds**：阈值配置（本地）
- **Settings Audit**：黑白名单与审计
""")

st.info("提示：如果页面显示后端不可用，请先启动 FastAPI：python -m uvicorn backend.app.main:app --reload --port 8000")
