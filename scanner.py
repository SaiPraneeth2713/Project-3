import socket
from concurrent.futures import ThreadPoolExecutor
from services import COMMON_PORTS
from banner import banner
from report import save_report

# Get user input
target = input("Enter IP Address or Hostname: ")
start_port = int(input("Start Port: "))
end_port = int(input("End Port: "))

open_ports = []

def scan(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    result = sock.connect_ex((target, port))

    if result == 0:
        service = COMMON_PORTS.get(port, "Unknown")
        print(f"[OPEN] Port {port} - {service}")

        # Banner Grabbing
        print(banner(target, port))

        open_ports.append((port, service))

    sock.close()

print("\nScanning...\n")

with ThreadPoolExecutor(max_workers=100) as executor:
    executor.map(scan, range(start_port, end_port + 1))

print("\nScan Complete")

print("\nOpen Ports:")
for port, service in open_ports:
    print(f"{port} - {service}")

# Save the scan report
save_report(target, open_ports)
