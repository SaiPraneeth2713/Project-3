import ipaddress
import socket


def validate_ip(ip):
    """Return True if the given string is a valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def resolve_target(target):
    """Resolve a hostname to an IP address, or pass through if already an IP."""
    if validate_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {target}")


def parse_port_range(port_str):
    """
    Parse port specifications like:
      '80'
      '1-1024'
      '22,80,443'
      '1-100,443,8080-8090'
    Returns a sorted list of unique valid port ints (1-65535).
    """
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = part.split('-')
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    valid_ports = sorted(p for p in ports if 0 < p <= 65535)
    if not valid_ports:
        raise ValueError("No valid ports found in range specification")
    return valid_ports


def format_duration(seconds):
    """Human-readable duration string."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, sec = divmod(seconds, 60)
    return f"{int(minutes)}m {sec:.2f}s"