import socket
import platform
import subprocess


def get_hostname(ip):
    """Reverse DNS lookup: get hostname from an IP. Returns None if not found."""
    try:
        return socket.gethostbyname_ex(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def get_ip_from_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_local_ip():
    """Best-effort discovery of this machine's IP on its main interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def is_host_alive(ip, timeout=1):
    """
    Ping the host once to check if it responds.
    Cross-platform (Windows vs Linux/Mac use different ping flags).
    """
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    command = ["ping", count_flag, "1", timeout_flag, str(timeout), ip]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2
        )
        return result.returncode == 0
    except Exception:
        return False


def get_service_name(port, proto="tcp"):
    """Use the system's services database to guess a port's service name."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"