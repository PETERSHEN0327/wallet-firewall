import streamlit as st
import httpx

API = "http://127.0.0.1:8000"

st.title("U2 - Risk Decision")

risk = st.session_state.get("last_risk")
if not risk:
    st.warning("No risk result found. Please go to 'Create Transaction' and run 'Check Risk' first.")
    st.stop()

st.subheader("Risk Summary")
st.metric("Risk Score", risk["risk_score"])
st.write(f"Risk Level: **{risk['risk_level']}**")
st.write(f"Decision: **{risk['decision']}**")
st.write(f"Request ID: `{risk['request_id']}`")

st.subheader("Reasons")
st.write(", ".join(risk["reason_codes"]))

st.subheader("Model Votes")
st.json(risk["model_votes"])

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("Cancel"):
        st.session_state["receipt"] = {"status": "BLOCKED", "request_id": risk["request_id"], "tx_hash": None}
        st.success("Cancelled. Go to 'Receipt'.")
with col2:
    if risk["decision"] != "BLOCK" and st.button("Send Transaction"):
        with httpx.Client(timeout=10.0) as client:
            r = client.post(f"{API}/tx/send", params={"request_id": risk["request_id"], "forced": False})
            r.raise_for_status()
            st.session_state["receipt"] = r.json()
        st.success("Sent. Go to 'Receipt'.")
with col3:
    if risk["decision"] == "REQUIRE_CONFIRM":
        st.write("Secondary Confirmation Required")
        ack = st.checkbox("I understand the risk and take responsibility.")
        token = st.text_input('Type "CONFIRM" to proceed')
        if st.button("Force Execution") and ack and token.strip().upper() == "CONFIRM":
            with httpx.Client(timeout=10.0) as client:
                r = client.post(f"{API}/tx/send", params={"request_id": risk["request_id"], "forced": True})
                r.raise_for_status()
                st.session_state["receipt"] = r.json()
            st.success("Forced execution logged. Go to 'Receipt'.")
