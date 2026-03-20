import pandas as pd
from datetime import timedelta
import os

NORMALIZED_LOG_PATH = "data/normalized_logs/normalized_events.csv"
THREAT_INTEL_PATH = "data/threat_intel/malicious_domains.txt"

def detect_lateral_movement(df):
    alerts = []

    # Look for internal firewall connections (ALLOW)
    firewall_events = df[
        (df["event_type"] == "FIREWALL") &
        (df["status"] == "ALLOW") &
        (df["dest_ip"].notna())
    ].copy()
    print("Firewall events:")
    print(firewall_events)

    for source_ip, group in firewall_events.groupby("source_ip"):

        unique_targets = group["dest_ip"].unique()

        # If connecting to multiple internal hosts within short time → suspicious
        if len(unique_targets) >= 2:

            alert = {
                "alert_type": "Lateral Movement Suspected",
                "user": None,
                "source_ip": source_ip,
                "domain": None,
                "start_time": group["timestamp"].min(),
                "end_time": group["timestamp"].max(),
                "mitre_technique": "T1021",
                "severity": "High"
            }

            alerts.append(alert)

    return alerts
# -----------------------------
# BRUTE FORCE DETECTION
# -----------------------------
def detect_bruteforce(df):
    failed_logins = df[
        (df["event_type"] == "AUTH") &
        (df["status"] == "FAILED")
    ].copy()

    alerts = []

    for user, group in failed_logins.groupby("user"):
        group = group.sort_values("timestamp")

        for i in range(len(group) - 2):
            t1 = group.iloc[i]["timestamp"]
            t3 = group.iloc[i + 2]["timestamp"]

            if (t3 - t1) <= timedelta(seconds=60):
                alert = {
                    "alert_type": "Brute Force Login",
                    "user": user,
                    "source_ip": group.iloc[i]["source_ip"],
                    "domain": None,
                    "start_time": t1,
                    
                    "end_time": t3,
                    "mitre_technique": "T1110",
                    "severity": "High"
                }
                alerts.append(alert)
                break

    return alerts
# -----------------------------
# ACCOUNT COMPROMISE DETECTION
# -----------------------------
def detect_compromised_account(df):
    alerts = []

    auth_events = df[df["event_type"] == "AUTH"].copy()
    auth_events = auth_events.sort_values("timestamp")

    for user, group in auth_events.groupby("user"):

        group = group.reset_index(drop=True)

        for i in range(len(group) - 3):

            # Check 3 failed attempts
            first = group.iloc[i]
            second = group.iloc[i + 1]
            third = group.iloc[i + 2]
            fourth = group.iloc[i + 3]

            failed_pattern = (
                first["status"] == "FAILED" and
                second["status"] == "FAILED" and
                third["status"] == "FAILED"
            )

            success_after = (
                fourth["status"] == "SUCCESS"
            )

            time_window = (
                fourth["timestamp"] - first["timestamp"]
            ) <= timedelta(minutes=2)

            if failed_pattern and success_after and time_window:

                alert = {
                    "alert_type": "Account Compromise Suspected",
                    "user": user,
                    "source_ip": fourth["source_ip"],
                    "start_time": first["timestamp"],
                    "end_time": fourth["timestamp"],
                    "mitre_technique": "T1078",
                    "severity": "High"
                }

                alerts.append(alert)
                break

    return alerts

# -----------------------------
# DNS IOC DETECTION
# -----------------------------
def detect_malicious_dns(df):
    alerts = []

    # Load threat intel
    with open(THREAT_INTEL_PATH, "r") as f:
        malicious_domains = [line.strip() for line in f.readlines()]

    dns_events = df[df["event_type"] == "DNS"].copy()

    for _, row in dns_events.iterrows():
        if row["domain"] in malicious_domains:
            alert = {
                "alert_type": "Malicious DNS Query (Possible C2)",
                "user": None,
                "source_ip": row["source_ip"],
                "domain": row["domain"],
                "start_time": row["timestamp"],
                "end_time": row["timestamp"],
                "mitre_technique": "T1071",
                "severity": "Critical"
            }
            alerts.append(alert)

    return alerts


# -----------------------------
# MAIN DETECTION ENGINE
# -----------------------------
def run_detection():
    df = pd.read_csv(NORMALIZED_LOG_PATH)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    all_alerts = []

    all_alerts.extend(detect_bruteforce(df))
    all_alerts.extend(detect_compromised_account(df))
    all_alerts.extend(detect_malicious_dns(df))
    all_alerts.extend(detect_lateral_movement(df))
    

    return pd.DataFrame(all_alerts)


if __name__ == "__main__":
    alerts = run_detection()

    if alerts.empty:
        print("No threats detected.")
    else:
        print("\nThreat Alerts Detected:\n")
        print(alerts)

        # Save for correlation engine
        alerts.to_csv("alerts_temp.csv", index=False)