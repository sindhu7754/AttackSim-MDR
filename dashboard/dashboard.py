import streamlit as st
import pandas as pd
import ast
import base64

def set_background(image_file):
    with open(image_file, "rb") as file:
        encoded = base64.b64encode(file.read()).decode()

    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image: url("data:image/png;base64,{encoded}");
            background-size: cover;
            background-attachment: fixed;
            background-position: center;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

st.set_page_config(page_title="ATTACKSIM-MDR SOC Dashboard", layout="wide")
set_background("dashboard/assets/cyber__.jpg")

st.title("🛡 ATTACKSIM-MDR — Simulated SOC Dashboard")


try:
    incidents = pd.read_csv("correlation_output.csv")
    alerts = pd.read_csv("alerts_temp.csv")
except:
    st.error("Run main.py first to generate data.")
    st.stop()

# -----------------------------
# KPI SECTION
# -----------------------------
st.subheader(" Key Security Metrics")

col1, col2, col3 = st.columns(3)

col1.metric("Total Alerts", len(alerts))
col2.metric("Total Incidents", len(incidents))

if not incidents.empty:
    max_risk = incidents["risk_score"].max()
    col3.metric("Highest Risk Score", int(max_risk))
else:
    col3.metric("Highest Risk Score", 0)

st.divider()

# -----------------------------
# INCIDENT TABLE
# -----------------------------
st.subheader(" Correlated Incidents")

if incidents.empty:
    st.info("No correlated incidents found.")
else:
    st.dataframe(incidents, use_container_width=True)

st.divider()

# -----------------------------
# SEVERITY DISTRIBUTION
# -----------------------------
st.subheader(" Severity Distribution")

if not incidents.empty:
    severity_counts = incidents["highest_severity"].value_counts()
    st.bar_chart(severity_counts)

st.divider()

# -----------------------------
# MITRE TECHNIQUE VISUALIZATION
# -----------------------------
st.subheader(" MITRE Techniques Observed")

if not incidents.empty:
    all_techniques = []

    for row in incidents["techniques_involved"]:
        techniques = ast.literal_eval(row)
        all_techniques.extend(techniques)

    technique_counts = pd.Series(all_techniques).value_counts()
    st.bar_chart(technique_counts)

st.divider()

# -----------------------------
# TIMELINE VIEW
# -----------------------------
st.subheader(" Incident Timeline")

if not incidents.empty:
    incidents["incident_start"] = pd.to_datetime(incidents["incident_start"])
    timeline = incidents.sort_values("incident_start")[["incident_start", "risk_score"]]
    timeline = timeline.set_index("incident_start")
    st.line_chart(timeline)

st.divider()

st.success("Dashboard Loaded Successfully ✔")
# -----------------------------
# INCIDENT INVESTIGATION VIEW
# -----------------------------
st.subheader(" Incident Investigation")

if not incidents.empty:

    incident_index = st.selectbox(
        "Select Incident",
        incidents.index
    )

    selected_incident = incidents.loc[incident_index]

    st.markdown("### Attack Details")

    col1, col2 = st.columns(2)

    col1.write(f"**Source Host:** {selected_incident['source_ip']}")
    col1.write(f"**Risk Score:** {selected_incident['risk_score']}")
    col1.write(f"**Severity:** {selected_incident['highest_severity']}")

    col2.write(f"**Start Time:** {selected_incident['incident_start']}")
    col2.write(f"**End Time:** {selected_incident['incident_end']}")
    col2.write(f"**Alerts Correlated:** {selected_incident['num_alerts']}")

    st.markdown("### Attack Chain")

    stages = ast.literal_eval(selected_incident["kill_chain_stages"])

    for i, stage in enumerate(stages):
        st.success(f"Step {i+1}: {stage}")

    st.markdown("### MITRE Techniques")

    techniques = ast.literal_eval(selected_incident["techniques_involved"])

    for t in techniques:
        st.write(f"- {t}")