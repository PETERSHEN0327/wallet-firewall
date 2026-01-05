import streamlit as st
from utils.state import init_state, add_audit

st.set_page_config(page_title="Models Thresholds", layout="wide")
st.title("Models Thresholds")

init_state()

th = st.session_state["thresholds"]

st.subheader("Decision Thresholds (local demo)")
col1, col2, col3 = st.columns(3)

allow_max = col1.slider("ALLOW_MAX", 0, 100, int(th["ALLOW_MAX"]))
require_min = col2.slider("REQUIRE_CONFIRM_MIN", 0, 100, int(th["REQUIRE_CONFIRM_MIN"]))
block_min = col3.slider("BLOCK_MIN", 0, 100, int(th["BLOCK_MIN"]))

if st.button("Save Thresholds", type="primary"):
    st.session_state["thresholds"] = {
        "ALLOW_MAX": allow_max,
        "REQUIRE_CONFIRM_MIN": require_min,
        "BLOCK_MIN": block_min
    }
    add_audit("THRESHOLD_UPDATE", {"thresholds": st.session_state["thresholds"]})
    st.success("Saved (session only).")

st.caption("当前阈值仅保存在 Streamlit session 中；后续可写入后端 DB 并由模型调用。")
