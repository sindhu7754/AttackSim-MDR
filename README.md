# AttackSim-MDR: SIEM-Inspired Cyber Threat Detection Pipeline

## Overview

AttackSim-MDR is a Security Operations Center (SOC)-inspired pipeline designed to simulate real-world cyber threat detection, correlation, and response. The system processes raw logs, detects malicious activities using rule-based techniques, correlates alerts into multi-stage attack chains, and generates structured incident insights.

This project moves beyond traditional intrusion detection by incorporating attack correlation, risk scoring, and contextual analysis aligned with the MITRE ATT&CK framework.

---

## Architecture

Raw Logs
→ Detection Engine
→ Alerts (MITRE-tagged)
→ Correlation Engine
→ Attack Chains
→ Risk Scoring
→ Incident Reports and Dashboard

---

## Key Features

* Multi-source log ingestion and preprocessing
* Rule-based detection mapped to MITRE ATT&CK techniques
* Alert correlation to identify multi-stage attack chains
* Risk scoring and severity classification
* Detection of shared command-and-control (C2) infrastructure
* Automated incident reporting
* Interactive dashboard for monitoring and investigation

---

## MITRE ATT&CK Coverage

* T1110 – Brute Force
* T1078 – Valid Accounts
* T1071 – Command and Control
* T1021 – Lateral Movement

---

## Detection Approach

The detection engine identifies suspicious activities such as brute-force attempts, unauthorized account usage, and malicious domain communication. Domain-based threat intelligence is incorporated using a predefined blacklist.

---

## Correlation Strategy

Alerts are correlated based on shared attributes such as source IP or user identity within a defined time window. The system identifies multi-stage attack sequences and assigns a risk score based on technique combinations, frequency, and progression patterns.

---

## Shared C2 Detection

The system detects potential command-and-control infrastructure by identifying multiple hosts communicating with the same malicious domain.

---

## Dashboard Capabilities

* Summary metrics for alerts and incidents
* Severity distribution analysis
* MITRE technique frequency visualization
* Temporal analysis of incidents
* Detailed investigation view for individual attack chains

---

## Project Structure

AttackSim-MDR/
├── detection/
├── correlation/
├── response/
├── dashboard/
├── main.py
├── malicious_domains.txt
├── requirements.txt
└── README.md

---

## Execution

Install dependencies:

pip install -r requirements.txt

Run the pipeline:

python main.py

Launch the dashboard:

streamlit run dashboard.py

---

## Future Work

* Integration of anomaly detection models
* Real-time log ingestion and streaming
* Extended threat intelligence enrichment
* Automated response mechanisms

---

## Author

Sindhu Varshini S.P.

---

## Summary

AttackSim-MDR demonstrates a structured approach to threat detection by combining rule-based analysis with correlation-driven insights. The system reflects core principles of modern SIEM and MDR platforms and emphasizes practical security engineering design.
