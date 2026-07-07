import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import resolve_target, parse_port_range, format_duration
from logger import setup_logger
from hostinfo import get_hostname, is_host_alive, get_service_name
import risk
import database

logger = setup_logger()


def scan_port(ip, port, timeout=1.0):
    """Attempt a TCP connect to a single port. Returns True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except socket.error:
        return False


def run_scan(target, port_str="1-1024", threads=100, timeout=1.0, check_alive=True):
    """
    Full scan workflow:
      1. Resolve target hostname/IP
      2. Optionally ping-check the host is alive
      3. Scan ports concurrently with a thread pool
      4. Assess risk of each open port
      5. Persist everything to scan.db
      6. Log progress/events to scan.log
    Returns a summary dict.
    """
    database.init_db()

    ip = resolve_target(target)
    hostname = get_hostname(ip) or target
    ports = parse_port_range(port_str)

    logger.info(f"Starting scan on {target} ({ip}) — {len(ports)} ports, {threads} threads")

    if check_alive and not is_host_alive(ip):
        logger.warning(f"Host {ip} did not respond to ping — continuing anyway (may be blocking ICMP)")

    scan_id = database.create_scan(target, ip, hostname, port_str)

    open_ports = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")
                continue

            if is_open:
                service, risk_level, note = risk.assess_port(port)
                sys_service = get_service_name(port)
                open_ports.append(port)
                database.add_result(
                    scan_id, port, "open",
                    service if service != "unknown" else sys_service,
                    risk_level, note
                )
                logger.info(f"Port {port} OPEN — {service} [{risk_level}]")

    elapsed = time.time() - start
    open_ports.sort()
    database.finish_scan(scan_id, len(open_ports))

    summary = risk.summarize_risk(open_ports)
    summary.update({
        "scan_id": scan_id,
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "open_ports": open_ports,
        "duration": format_duration(elapsed),
        "ports_scanned": len(ports),
    })

    logger.info(
        f"Scan complete: {len(open_ports)}/{len(ports)} ports open in {summary['duration']} "
        f"(highest risk: {summary['highest_risk']})"
    )

    return summary


def print_summary(summary):
    print(f"\nScan Results for {summary['target']} ({summary['ip']})")
    print(f"Hostname: {summary['hostname']}")
    print(f"Ports scanned: {summary['ports_scanned']}  |  Duration: {summary['duration']}")
    print(f"Open ports: {len(summary['open_ports'])}\n")

    if not summary['details']:
        print("No open ports found.")
        return

    print(f"{'PORT':<8}{'SERVICE':<15}{'RISK':<10}NOTE")
    print("-" * 70)
    for d in summary['details']:
        print(f"{d['port']:<8}{d['service']:<15}{d['risk_level']:<10}{d['note']}")

    print(f"\nHighest overall risk: {summary['highest_risk']}")


if __name__ == "__main__":
    # Quick manual test against a well-known safe scan target
    result = run_scan("scanme.nmap.org", "20-25,80,443", threads=50)
    print_summary(result)