import streamlit as st
import httpx

API = "http://127.0.0.1:8000"

st.title("U1 - Create Transaction")

with st.form("tx_form"):
    chain = st.selectbox("Chain", ["TRON", "ETHEREUM"])
    from_address = st.text_input("From Address (optional)")
    to_address = st.text_input("To Address (required)")
    amount = st.number_input("Amount (USDT)", min_value=0.01, value=10.0, step=1.0)
    memo = st.text_input("Memo/Note (optional)")
    submitted = st.form_submit_button("Check Risk")

if submitted:
    if not to_address.strip():
        st.error("To Address is required.")
    else:
        payload = {
            "chain": chain,
            "from_address": from_address.strip() or None,
            "to_address": to_address.strip(),
            "amount_usdt": float(amount),
            "memo": memo.strip() or None
        }
        with httpx.Client(timeout=10.0) as client:
            r = client.post(f"{API}/risk/check", json=payload)
            r.raise_for_status()
            data = r.json()

        st.session_state["last_risk"] = data
        st.success("Risk assessment completed. Go to 'Risk Decision' page.")
