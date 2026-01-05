import streamlit as st
import pandas as pd
from utils.api import get_json, healthcheck
from utils.fmt import pretty_ts

st.set_page_config(page_title="Wallet Profile", layout="wide")
st.title("Wallet Profile")

ok, msg = healthcheck()
if not ok:
    st.error(f"Backend unavailable: {msg}")
    st.stop()

address = st.text_input("Wallet address (to_address)", value="").strip()
limit = st.slider("Search window (recent intercepts)", 50, 2000, 500, 50)

run = st.button("Build Profile", type="primary")

if run:
    if not address:
        st.warning("Please input wallet address.")
        st.stop()

    ok, data, err = get_json("/admin/intercepts", params={"limit": int(limit)})
    if not ok:
        st.error(err)
        st.stop()

    items = data.get("items", []) if isinstance(data, dict) else []
    df = pd.DataFrame(items)
    if df.empty:
        st.info("No records.")
        st.stop()

    df = df[df.get("to_address") == address]
    if df.empty:
        st.warning("No records found for this address in the selected window.")
        st.stop()

    total = len(df)
    max_risk = int(df["risk_score"].max())
    avg_risk = float(df["risk_score"].mean())
    blocked = int((df["decision"] == "BLOCK").sum())
    forced = int((df["forced"] == 1).sum())

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Tx Count", total)
    col2.metric("Max Risk", max_risk)
    col3.metric("Avg Risk", round(avg_risk, 2))
    col4.metric("Blocked / Forced", f"{blocked} / {forced}")

    st.subheader("Risk Distribution")
    st.bar_chart(df["risk_score"].value_counts().sort_index())

    st.subheader("Recent Transactions to this Wallet")
    df_show = df.copy()
    if "ts" in df_show.columns:
        df_show["ts"] = df_show["ts"].apply(pretty_ts)
    st.dataframe(df_show.sort_values("ts", ascending=False), use_container_width=True)
