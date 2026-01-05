import streamlit as st
from typing import Dict, List

DEFAULT_THRESHOLDS = {
    "ALLOW_MAX": 69,
    "REQUIRE_CONFIRM_MIN": 70,
    "BLOCK_MIN": 90
}

def init_state():
    if "thresholds" not in st.session_state:
        st.session_state["thresholds"] = DEFAULT_THRESHOLDS.copy()

    if "audit_log" not in st.session_state:
        st.session_state["audit_log"] = []  # list of dicts

def add_audit(action: str, detail: Dict):
    st.session_state["audit_log"].insert(0, {"action": action, **detail})
    # 限制长度
    st.session_state["audit_log"] = st.session_state["audit_log"][:500]
