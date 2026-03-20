import pandas as pd
from datetime import timedelta

# -----------------------
# MITRE → Kill Chain Mapping
# -----------------------

KILL_CHAIN_MAP = {
    "T1110": "Initial Access (Brute Force)",
    "T1078": "Credential Abuse (Valid Account)",
    "T1071": "Command & Control Communication",
    "T1021": "Lateral Movement (Remote Services)"
}

ALERT_SOURCE = "alerts_temp.csv"


# -----------------------
# SHARED C2 INFRASTRUCTURE DETECTION
# -----------------------

def detect_shared_c2(alerts):
    shared_incidents = []

    dns_alerts = alerts[
        (alerts["mitre_technique"] == "T1071") &
        (alerts["domain"].notna())
    ]

    for domain, group in dns_alerts.groupby("domain"):

        unique_hosts = group["source_ip"].unique()

        # If more than one host contacted same malicious domain
        if len(unique_hosts) > 1:

            techniques = list(group["mitre_technique"])

            incident = {
                "incident_type": "Shared C2 Infrastructure",
                "source_ip": ", ".join(unique_hosts),
                "num_alerts": len(group),
                "techniques_involved": techniques,
                "kill_chain_stages": [
                    KILL_CHAIN_MAP.get(t, "Unknown Stage")
                    for t in techniques
                ],
                "risk_score": 180,
                "highest_severity": "Critical",
                "incident_start": group["start_time"].min(),
                "incident_end": group["start_time"].max()
            }

            shared_incidents.append(incident)

    return shared_incidents


# -----------------------
# MAIN CORRELATION ENGINE
# -----------------------

def correlate_alerts():

    alerts = pd.read_csv(ALERT_SOURCE)
    alerts["start_time"] = pd.to_datetime(alerts["start_time"])

    incidents = []
    processed = set()

    for i in range(len(alerts)):

        if i in processed:
            continue

        current = alerts.iloc[i]
        related = [i]

        # -----------------------
        # CORRELATION LOGIC
        # -----------------------

        for j in range(i + 1, len(alerts)):

            if j in processed:
                continue

            candidate = alerts.iloc[j]

            same_ip = current["source_ip"] == candidate["source_ip"]

            same_user = (
                pd.notna(current["user"]) and
                pd.notna(candidate["user"]) and
                current["user"] == candidate["user"]
            )

            time_close = abs(
                candidate["start_time"] - current["start_time"]
            ) <= timedelta(minutes=5)

            if (same_ip or same_user) and time_close:
                related.append(j)

        # Only build incident if multiple alerts linked
        if len(related) > 1:

            technique_weights = {
                "T1110": 25,
                "T1078": 30,
                "T1071": 40,
                "T1021": 35,
            }

            techniques = list(alerts.iloc[related]["mitre_technique"])

            kill_chain_stages = [
                KILL_CHAIN_MAP.get(t, "Unknown Stage")
                for t in techniques
            ]

            # -----------------------
            # RISK SCORING
            # -----------------------

            score = 0

            for t in techniques:
                score += technique_weights.get(t, 10)

            score += len(related) * 10

            if len(set(techniques)) > 1:
                score += 15

                ordered_chain = ["T1110", "T1078", "T1071"]

                if all(t in techniques for t in ordered_chain):

                    technique_sequence = list(
                        alerts.iloc[related]
                        .sort_values("start_time")["mitre_technique"]
                    )

                    if technique_sequence[:3] == ordered_chain:
                        score += 25

            # -----------------------
            # SEVERITY MAPPING
            # -----------------------

            if score >= 80:
                calculated_severity = "Critical"
            elif score >= 60:
                calculated_severity = "High"
            elif score >= 40:
                calculated_severity = "Medium"
            else:
                calculated_severity = "Low"

            incident = {
                "incident_type": "Correlated Attack Chain",
                "source_ip": current["source_ip"],
                "num_alerts": len(related),
                "techniques_involved": techniques,
                "kill_chain_stages": kill_chain_stages,
                "risk_score": score,
                "highest_severity": calculated_severity,
                "incident_start": alerts.iloc[related]["start_time"].min(),
                "incident_end": alerts.iloc[related]["start_time"].max()
            }

            incidents.append(incident)

            for idx in related:
                processed.add(idx)

    # Add Shared C2 incidents
    shared_incidents = detect_shared_c2(alerts)
    incidents.extend(shared_incidents)

    return pd.DataFrame(incidents)


if __name__ == "__main__":

    incidents = correlate_alerts()

    if incidents.empty:
        print("No correlated incidents found.")
    else:
        print("\nCorrelated Incidents Detected:\n")
        print(incidents)

        incidents.to_csv("correlation_output.csv", index=False)