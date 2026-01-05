import streamlit as st
import pandas as pd
from utils.api import get_json, healthcheck
from utils.fmt import shorten

st.set_page_config(page_title="Wallets", layout="wide")
st.title("Wallets")

ok, msg = healthcheck()
if not ok:
    st.error(f"Backend unavailable: {msg}")
    st.stop()

limit = st.slider("Load intercepts for aggregation", 50, 2000, 500, 50)

ok, data, err = get_json("/admin/intercepts", params={"limit": int(limit)})
if not ok:
    st.error(err)
    st.stop()

items = data.get("items", []) if isinstance(data, dict) else []
df = pd.DataFrame(items)
if df.empty:
    st.info("No records yet.")
    st.stop()

# Aggregate by to_address (risk target)
if "to_address" not in df.columns:
    st.error("Missing to_address in data.")
    st.stop()

grp = df.groupby("to_address").agg(
    tx_count=("request_id", "count"),
    max_risk=("risk_score", "max"),
    avg_risk=("risk_score", "mean"),
    blocked=("decision", lambda s: int((s == "BLOCK").sum())),
    forced=("forced", lambda s: int((s == 1).sum())),
).reset_index()

grp = grp.sort_values(["max_risk", "tx_count"], ascending=[False, False])

st.subheader("Wallet Risk Aggregation (by to_address)")
grp_show = grp.copy()
grp_show["to_address"] = grp_show["to_address"].apply(lambda x: shorten(str(x), 14))
grp_show["avg_risk"] = grp_show["avg_risk"].round(2)

st.dataframe(grp_show, use_container_width=True)

st.caption("Tip: copy a full to_address then go to Wallet Profile.")
