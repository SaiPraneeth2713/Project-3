import argparse
import sys

import app
import database


def build_parser():
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description="A simple multithreaded TCP port scanner with risk assessment."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Run a new scan")
    scan_p.add_argument("target", help="IP address or hostname to scan")
    scan_p.add_argument("-p", "--ports", default="1-1024",
                         help="Port(s) to scan, e.g. '80', '1-1024', '22,80,443' (default: 1-1024)")
    scan_p.add_argument("-t", "--threads", type=int, default=100,
                         help="Number of concurrent threads (default: 100)")
    scan_p.add_argument("--timeout", type=float, default=1.0,
                         help="Per-port connection timeout in seconds (default: 1.0)")
    scan_p.add_argument("--no-ping", action="store_true",
                         help="Skip the initial host-alive ping check")

    subparsers.add_parser("history", help="List previous scans")

    show_p = subparsers.add_parser("show", help="Show results of a past scan")
    show_p.add_argument("scan_id", type=int, help="ID of the scan to display")

    del_p = subparsers.add_parser("delete", help="Delete a past scan record")
    del_p.add_argument("scan_id", type=int, help="ID of the scan to delete")

    return parser


def cmd_scan(args):
    summary = app.run_scan(
        target=args.target,
        port_str=args.ports,
        threads=args.threads,
        timeout=args.timeout,
        check_alive=not args.no_ping,
    )
    app.print_summary(summary)


def cmd_history(args):
    database.init_db()
    scans = database.get_scans()
    if not scans:
        print("No scans recorded yet.")
        return
    print(f"{'ID':<5}{'TARGET':<25}{'IP':<18}{'START TIME':<22}{'OPEN'}")
    print("-" * 80)
    for s in scans:
        print(f"{s['id']:<5}{s['target']:<25}{s['resolved_ip'] or '-':<18}"
              f"{s['start_time'][:19]:<22}{s['total_open']}")


def cmd_show(args):
    database.init_db()
    results = database.get_results(args.scan_id)
    if not results:
        print(f"No results found for scan ID {args.scan_id}.")
        return
    print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<15}{'RISK':<10}NOTE")
    print("-" * 70)
    for r in results:
        print(f"{r['port']:<8}{r['state']:<8}{r['service']:<15}{r['risk_level']:<10}{r['risk_note']}")


def cmd_delete(args):
    database.init_db()
    database.delete_scan(args.scan_id)
    print(f"Deleted scan {args.scan_id}.")


def main():
    parser = build_parser()
    args = parser.parse_args()

    commands = {
        "scan": cmd_scan,
        "history": cmd_history,
        "show": cmd_show,
        "delete": cmd_delete,
    }
    commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())