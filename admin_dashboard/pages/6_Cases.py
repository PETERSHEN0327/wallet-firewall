import streamlit as st
import pandas as pd
from utils.state import init_state, add_audit

st.set_page_config(page_title="Cases", layout="wide")
st.title("Cases")

init_state()

if "cases" not in st.session_state:
    st.session_state["cases"] = []

with st.expander("Create a new case", expanded=True):
    col1, col2 = st.columns(2)
    with col1:
        case_title = st.text_input("Title", value="")
        severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    with col2:
        request_id = st.text_input("Related request_id (optional)", value="")
        tag = st.text_input("Tag", value="")

    notes = st.text_area("Notes", value="", height=120)

    if st.button("Add Case", type="primary"):
        case = {
            "title": case_title.strip() or "(untitled)",
            "severity": severity,
            "request_id": request_id.strip(),
            "tag": tag.strip(),
            "notes": notes.strip(),
        }
        st.session_state["cases"].insert(0, case)
        add_audit("CASE_ADD", {"title": case["title"], "severity": severity})
        st.success("Case added.")

st.subheader("Case List")
df = pd.DataFrame(st.session_state["cases"])
if df.empty:
    st.info("No cases yet.")
else:
    st.dataframe(df, use_container_width=True)
