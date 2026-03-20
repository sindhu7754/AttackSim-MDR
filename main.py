import pandas as pd

# Import modules
from detection.detection_engine import run_detection
from correlation.correlation_engine import correlate_alerts
from response.incident_report import generate_incident_report


def main():

    print("\n========== ATTACKSIM-MDR PIPELINE START ==========\n")

    # -----------------------
    # STAGE 1 — DETECTION
    # -----------------------
    print("Running Detection Engine...")
    alerts = run_detection()

    if alerts.empty:
        print("No threats detected. Exiting pipeline.")
        return

    alerts.to_csv("alerts_temp.csv", index=False)
    print(f"{len(alerts)} alerts detected and saved.\n")

    # -----------------------
    # STAGE 2 — CORRELATION
    # -----------------------
    print("Running Correlation Engine...")
    incidents = correlate_alerts()

    if incidents.empty:
        print("No correlated incidents found.")
        return

    incidents.to_csv("correlation_output.csv", index=False)
    print(f"{len(incidents)} incidents correlated and saved.\n")

    # -----------------------
    # STAGE 3 — INCIDENT REPORT
    # -----------------------
    print("Generating Incident Reports...")
    generate_incident_report()

    print("\n========== PIPELINE COMPLETE ==========\n")


if __name__ == "__main__":
    main()