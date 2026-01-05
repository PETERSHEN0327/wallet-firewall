import streamlit as st
import pandas as pd
from utils.api import get_json, healthcheck
from utils.fmt import pretty_ts

st.set_page_config(page_title="Overview", layout="wide")

st.title("Overview")

ok, msg = healthcheck()
if not ok:
    st.error(f"Backend unavailable: {msg}")
    st.stop()

limit = st.slider("Load recent intercepts", min_value=10, max_value=500, value=100, step=10)
ok, data, err = get_json("/admin/intercepts", params={"limit": limit})
if not ok:
    st.error(err)
    st.stop()

items = data.get("items", []) if isinstance(data, dict) else []
df = pd.DataFrame(items)

col1, col2, col3, col4 = st.columns(4)

total = len(df)
high = int((df.get("risk_level") == "HIGH").sum()) if total else 0
blocked = int((df.get("decision") == "BLOCK").sum()) if total else 0
forced = int((df.get("forced") == 1).sum()) if total else 0

col1.metric("Recent Intercepts", total)
col2.metric("High Risk", high)
col3.metric("Blocked", blocked)
col4.metric("Forced Releases", forced)

st.subheader("Recent Intercepts (Preview)")
if total == 0:
    st.warning("No intercept records yet. Create a transaction from user_app to generate logs.")
else:
    df_show = df.copy()
    if "ts" in df_show.columns:
        df_show["ts"] = df_show["ts"].apply(pretty_ts)
    st.dataframe(df_show.head(50), use_container_width=True)
