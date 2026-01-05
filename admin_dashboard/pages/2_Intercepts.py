import streamlit as st
import pandas as pd
from utils.api import get_json, healthcheck
from utils.fmt import pretty_ts, shorten

st.set_page_config(page_title="Intercepts", layout="wide")

st.title("Intercepts")

ok, msg = healthcheck()
if not ok:
    st.error(f"Backend unavailable: {msg}")
    st.stop()

colA, colB, colC = st.columns([2, 2, 3])
with colA:
    limit = st.number_input("Limit", min_value=10, max_value=2000, value=200, step=10)
with colB:
    level_filter = st.selectbox("Risk level filter", ["ALL", "LOW", "MEDIUM", "HIGH", "BLOCKED"])
with colC:
    keyword = st.text_input("Search keyword (request_id / address)", value="").strip()

ok, data, err = get_json("/admin/intercepts", params={"limit": int(limit)})
if not ok:
    st.error(err)
    st.stop()

items = data.get("items", []) if isinstance(data, dict) else []
df = pd.DataFrame(items)

if df.empty:
    st.info("No records yet.")
    st.stop()

# Basic filters
if level_filter != "ALL" and "risk_level" in df.columns:
    df = df[df["risk_level"] == level_filter]

if keyword:
    k = keyword.lower()
    def hit(row):
        for col in ["request_id", "from_address", "to_address", "tx_hash"]:
            v = str(row.get(col, "")).lower()
            if k in v:
                return True
        return False
    df = df[df.apply(hit, axis=1)]

# Beautify
df_show = df.copy()
if "ts" in df_show.columns:
    df_show["ts"] = df_show["ts"].apply(pretty_ts)
if "from_address" in df_show.columns:
    df_show["from_address"] = df_show["from_address"].apply(lambda x: shorten(str(x), 12))
if "to_address" in df_show.columns:
    df_show["to_address"] = df_show["to_address"].apply(lambda x: shorten(str(x), 12))
if "request_id" in df_show.columns:
    df_show["request_id"] = df_show["request_id"].apply(lambda x: str(x))

st.caption("Tip: copy request_id to Transaction Detail page.")
st.dataframe(df_show, use_container_width=True)
