import pandas as pd
import ast

INCIDENT_SOURCE = "correlation_output.csv"


def calculate_confidence(score):
    if score >= 140:
        return "Very High"
    elif score >= 100:
        return "High"
    elif score >= 70:
        return "Medium"
    else:
        return "Low"

def classify_objective(techniques):
    if "T1110" in techniques and "T1078" in techniques and "T1071" in techniques:
        return "Multi-Stage Intrusion with Active C2"
    elif "T1110" in techniques and "T1078" in techniques:
        return "Credential Compromise"
    elif "T1071" in techniques:
        return "Command & Control Establishment"
    else:
        return "Unknown Objective"
    

def generate_incident_report():
    incidents = pd.read_csv(INCIDENT_SOURCE)

    if incidents.empty:
        print("No incidents to generate reports for.")
        return

    for _, incident in incidents.iterrows():

        risk_score = incident["risk_score"]
        confidence = calculate_confidence(risk_score)

        # Convert stored string lists back to Python lists
        techniques = ast.literal_eval(incident["techniques_involved"])
        kill_chain_stages = ast.literal_eval(incident["kill_chain_stages"])

        # Classify objective AFTER extracting techniques
        objective = classify_objective(techniques)

        print("\n" + "=" * 65)
        print("INCIDENT REPORT — ATTACKSIM-MDR")
        print("=" * 65)

        print(f"\nIncident Type       : {incident['incident_type']}")
        print(f"Affected Host       : {incident['source_ip']}")
        print(f"Risk Score          : {risk_score}")
        print(f"Severity Level      : {incident['highest_severity']}")
        print(f"Confidence Level    : {confidence}")
        print(f"Attack Objective    : {objective}")

        print(f"\nIncident Start Time : {incident['incident_start']}")
        print(f"Incident End Time   : {incident['incident_end']}")
        print(f"Alerts Correlated   : {incident['num_alerts']}")

        print("\n--- Attack Chain Intelligence ---")
        for i, stage in enumerate(kill_chain_stages):
            print(f"Step {i+1}: {stage}")

        print("\n--- Analyst Interpretation ---")

        if "T1110" in techniques and "T1078" in techniques:
            print("• Brute-force attack likely succeeded resulting in account compromise.")
        if "T1071" in techniques:
            print("• Host initiated communication with potential command-and-control infrastructure.")

        print("\n--- Recommended Remediation ---")

        if incident["highest_severity"] == "Critical":
            print("• Immediately isolate the affected host.")
            print("• Reset compromised credentials.")
            print("• Block malicious domains and IPs.")
            print("• Initiate forensic investigation.")
        elif incident["highest_severity"] == "High":
            print("• Review authentication logs.")
            print("• Enforce password reset.")
            print("• Monitor host for persistence.")
        else:
            print("• Continue monitoring.")
            print("• Conduct log review.")

        print("\n" + "=" * 65)