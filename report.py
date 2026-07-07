import csv
from datetime import datetime

def save_report(target, ports):

    filename = f"reports/{target}_report.csv"

    with open(filename, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(["Target", target])
        writer.writerow(["Date", datetime.now()])
        writer.writerow([])

        writer.writerow(["Port", "Service"])

        for port, service in ports:
            writer.writerow([port, service])

    print("Report Saved")