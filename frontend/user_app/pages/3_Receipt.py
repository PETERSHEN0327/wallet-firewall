import streamlit as st

st.title("U3 - Receipt / Status")

receipt = st.session_state.get("receipt")
risk = st.session_state.get("last_risk")

if not receipt:
    st.warning("No receipt found yet. Please complete U2 actions first.")
    st.stop()

st.subheader("Status")
st.write(f"**{receipt['status']}**")

st.subheader("Receipt Details")
st.write(f"Request ID: `{receipt['request_id']}`")
st.write(f"TX Hash: `{receipt.get('tx_hash')}`")

if risk and risk.get("request_id") == receipt["request_id"]:
    st.subheader("Risk Snapshot")
    st.write(f"Risk Score: {risk['risk_score']} | Level: {risk['risk_level']} | Decision: {risk['decision']}")
    st.write("Reasons: " + ", ".join(risk["reason_codes"]))
