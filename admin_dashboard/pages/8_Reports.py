import streamlit as st
import pandas as pd
from utils.api import get_json, healthcheck
from utils.fmt import pretty_ts

st.set_page_config(page_title="Reports", layout="wide")
st.title("Reports")

ok, msg = healthcheck()
if not ok:
    st.error(f"Backend unavailable: {msg}")
    st.stop()

limit = st.number_input("Export last N intercepts", min_value=10, max_value=5000, value=500, step=50)

ok, data, err = get_json("/admin/intercepts", params={"limit": int(limit)})
if not ok:
    st.error(err)
    st.stop()

items = data.get("items", []) if isinstance(data, dict) else []
df = pd.DataFrame(items)

if df.empty:
    st.info("No data to export.")
    st.stop()

if "ts" in df.columns:
    df["ts"] = df["ts"].apply(pretty_ts)

st.dataframe(df.head(50), use_container_width=True)

csv = df.to_csv(index=False).encode("utf-8")
st.download_button("Download CSV", data=csv, file_name="intercepts_export.csv", mime="text/csv")
