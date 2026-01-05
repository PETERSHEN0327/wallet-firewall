import streamlit as st
import pandas as pd
from utils.api import get_json, healthcheck
from utils.fmt import shorten

st.set_page_config(page_title="Graph Explorer", layout="wide")
st.title("Graph Explorer")

ok, msg = healthcheck()
if not ok:
    st.error(f"Backend unavailable: {msg}")
    st.stop()

limit = st.slider("Load intercepts", 50, 2000, 300, 50)
ok, data, err = get_json("/admin/intercepts", params={"limit": int(limit)})
if not ok:
    st.error(err)
    st.stop()

items = data.get("items", []) if isinstance(data, dict) else []
df = pd.DataFrame(items)

if df.empty:
    st.info("No records.")
    st.stop()

# Build edges: from_address -> to_address
df["from_address"] = df.get("from_address", "").fillna("")
df["to_address"] = df["to_address"].fillna("")

edges = df[df["from_address"] != ""].groupby(["from_address", "to_address"]).size().reset_index(name="tx_count")
edges = edges.sort_values("tx_count", ascending=False)

st.subheader("Top Edges (from -> to)")
edges_show = edges.copy()
edges_show["from_address"] = edges_show["from_address"].apply(lambda x: shorten(str(x), 14))
edges_show["to_address"] = edges_show["to_address"].apply(lambda x: shorten(str(x), 14))
st.dataframe(edges_show.head(200), use_container_width=True)

st.caption("此页面为简易版图谱探索。后续可接 Neo4j / NetworkX 可视化。")
