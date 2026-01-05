import streamlit as st
import pandas as pd
from utils.api import get_json, post_json, healthcheck
from utils.state import init_state, add_audit

st.set_page_config(page_title="Settings & Audit", layout="wide")
st.title("Settings & Audit")

init_state()

ok, msg = healthcheck()
if not ok:
    st.error(f"Backend unavailable: {msg}")
    st.stop()

tab1, tab2 = st.tabs(["Lists (backend)", "Audit (local session)"])

with tab1:
    st.subheader("Blacklist / Whitelist")

    colA, colB = st.columns(2)
    with colA:
        kind = st.selectbox("List kind", ["BLACKLIST", "WHITELIST"])
    with colB:
        addr = st.text_input("Address", value="").strip()

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Add", type="primary", use_container_width=True):
            if not addr:
                st.warning("Address required.")
            else:
                ok, data, err = post_json("/admin/list/add", params={"kind": kind, "address": addr})
                if ok:
                    add_audit("LIST_ADD", {"kind": kind, "address": addr})
                    st.success("Added.")
                else:
                    st.error(err)

    with c2:
        if st.button("Remove", use_container_width=True):
            if not addr:
                st.warning("Address required.")
            else:
                ok, data, err = post_json("/admin/list/remove", params={"kind": kind, "address": addr})
                if ok:
                    add_audit("LIST_REMOVE", {"kind": kind, "address": addr})
                    st.success("Removed.")
                else:
                    st.error(err)

    with c3:
        if st.button("Refresh List", use_container_width=True):
            st.rerun()

    st.divider()

    ok, data, err = get_json("/admin/list", params={"kind": kind})
    if ok and isinstance(data, dict):
        items = data.get("items", [])
        df = pd.DataFrame({"address": items})
        st.dataframe(df, use_container_width=True)
    else:
        st.error(f"List API unavailable or not implemented yet: {err}")

with tab2:
    st.subheader("Audit Log (session)")
    df = pd.DataFrame(st.session_state["audit_log"])
    if df.empty:
        st.info("No audit records yet.")
    else:
        st.dataframe(df, use_container_width=True)

    if st.button("Clear Audit Log"):
        st.session_state["audit_log"] = []
        st.success("Cleared.")
