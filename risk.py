"""
Risk assessment for commonly (in)secure ports.
A lightweight, static risk model — not a substitute for a full vulnerability
scanner, but useful for flagging obviously risky exposure at a glance.
"""

# port -> (service name, risk_level, note)
PORT_RISK_DB = {
    21:    ("FTP", "HIGH", "Unencrypted file transfer; credentials sent in plaintext."),
    22:    ("SSH", "LOW", "Generally secure if key-based auth and kept up-to-date."),
    23:    ("Telnet", "CRITICAL", "Unencrypted remote login; should never be exposed."),
    25:    ("SMTP", "MEDIUM", "Can be abused for spam relay if misconfigured."),
    53:    ("DNS", "MEDIUM", "Open resolvers can be abused in amplification attacks."),
    69:    ("TFTP", "HIGH", "No authentication; often used in exploits/misconfig."),
    80:    ("HTTP", "MEDIUM", "Unencrypted web traffic."),
    110:   ("POP3", "MEDIUM", "Often unencrypted mail retrieval."),
    111:   ("RPCbind", "HIGH", "Frequently targeted for enumeration/exploits."),
    135:   ("MSRPC", "HIGH", "Historically targeted by worms (e.g., Blaster)."),
    139:   ("NetBIOS", "HIGH", "Legacy Windows file sharing; frequent attack target."),
    143:   ("IMAP", "MEDIUM", "Often unencrypted mail access."),
    443:   ("HTTPS", "LOW", "Encrypted web traffic; ensure valid TLS config."),
    445:   ("SMB", "CRITICAL", "Target of major worms (WannaCry, EternalBlue)."),
    993:   ("IMAPS", "LOW", "Encrypted mail access."),
    995:   ("POP3S", "LOW", "Encrypted mail access."),
    1433:  ("MSSQL", "HIGH", "Database exposed directly to network is risky."),
    3306:  ("MySQL", "HIGH", "Database exposed directly to network is risky."),
    3389:  ("RDP", "CRITICAL", "Frequent brute-force/ransomware entry point."),
    5432:  ("PostgreSQL", "HIGH", "Database exposed directly to network is risky."),
    5900:  ("VNC", "HIGH", "Often weakly authenticated remote desktop access."),
    6379:  ("Redis", "CRITICAL", "Frequently found unauthenticated and exposed."),
    8080:  ("HTTP-Alt", "MEDIUM", "Often an admin panel or proxy; check exposure."),
    27017: ("MongoDB", "CRITICAL", "Frequently found unauthenticated and exposed."),
}

DEFAULT_RISK = ("unknown", "INFO", "No specific risk profile available for this port.")

RISK_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def assess_port(port):
    """Return (service, risk_level, note) for a given port number."""
    return PORT_RISK_DB.get(port, DEFAULT_RISK)


def summarize_risk(open_ports):
    """
    Given a list of open port ints, return a summary dict:
      { highest_risk, counts_by_level, details: [...] }
    """
    details = []
    counts = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    highest = "INFO"

    for port in open_ports:
        service, level, note = assess_port(port)
        counts[level] += 1
        if RISK_ORDER[level] > RISK_ORDER[highest]:
            highest = level
        details.append({
            "port": port,
            "service": service,
            "risk_level": level,
            "note": note
        })

    return {
        "highest_risk": highest,
        "counts_by_level": counts,
        "details": details
    }