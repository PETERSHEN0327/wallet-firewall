import streamlit as st
from utils.api import get_json, healthcheck
from utils.fmt import pretty_ts

st.set_page_config(page_title="Transaction Detail", layout="wide")

st.title("Transaction Detail")

ok, msg = healthcheck()
if not ok:
    st.error(f"Backend unavailable: {msg}")
    st.stop()

request_id = st.text_input("request_id", value="").strip()

col1, col2 = st.columns([1, 2])

with col1:
    fetch = st.button("Fetch Detail", type="primary", use_container_width=True)

if fetch:
    if not request_id:
        st.warning("Please input request_id.")
        st.stop()

    ok, data, err = get_json(f"/admin/intercepts/{request_id}")
    if not ok:
        st.error(err)
        st.stop()

    st.subheader("Raw Detail")
    if isinstance(data, dict) and "ts" in data:
        data["ts"] = pretty_ts(data["ts"])
    st.json(data)

    st.subheader("Quick Summary")
    if isinstance(data, dict):
        st.write(
            {
                "ts": data.get("ts"),
                "chain": data.get("chain"),
                "from": data.get("from_address"),
                "to": data.get("to_address"),
                "amount_usdt": data.get("amount_usdt"),
                "risk_score": data.get("risk_score"),
                "risk_level": data.get("risk_level"),
                "decision": data.get("decision"),
                "forced": data.get("forced"),
                "tx_hash": data.get("tx_hash"),
            }
        )
