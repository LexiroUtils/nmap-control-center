from __future__ import annotations

SCAN_TYPES = {
    "-sT": "TCP connect scan. Reliable without raw packet privileges, but more visible in logs.",
    "-sS": "SYN scan. Fast and common; normally requires root/admin raw-packet privileges.",
    "-sU": "UDP scan. Useful for DNS/SNMP/VPN services; slower and often needs care with timing.",
    "-sA": "ACK scan. Maps firewall rules rather than open services; usually privileged.",
    "-sW": "Window scan. ACK-like scan that can infer open ports on some systems.",
    "-sM": "Maimon scan. Specialized FIN/ACK technique; rarely useful on modern stacks.",
    "-sF": "FIN scan. Stealthier on some non-Windows stacks; unreliable against many targets.",
    "-sN": "NULL scan. Sends no TCP flags; stealth-oriented but not universally reliable.",
    "-sX": "Xmas scan. FIN/PSH/URG flags; stealth-oriented but not universally reliable.",
    "-sY": "SCTP INIT scan. For SCTP services; may require privileges.",
    "-sZ": "SCTP COOKIE-ECHO scan. Quieter SCTP technique where supported.",
    "-sO": "IP protocol scan. Finds supported IP protocols, not TCP/UDP ports.",
}

DISCOVERY = {
    "default": "Nmap's normal host discovery based on local network and privileges.",
    "-Pn": "No ping. Treat hosts as up; useful when probes are blocked, slower on large ranges.",
    "-PE": "ICMP echo request discovery.",
    "-PP": "ICMP timestamp discovery.",
    "-PM": "ICMP netmask discovery.",
    "-PS": "TCP SYN ping, optionally with ports such as -PS22,80,443.",
    "-PA": "TCP ACK ping, optionally with ports.",
    "-PU": "UDP discovery probes, optionally with ports.",
    "-PY": "SCTP discovery probes, optionally with ports.",
    "-PR": "ARP ping on local Ethernet networks.",
}

TIMING = {
    "T0": "Paranoid. Very slow; attempts to avoid IDS timing thresholds.",
    "T1": "Sneaky. Slow and conservative.",
    "T2": "Polite. Slows down to reduce network load.",
    "T3": "Normal. Nmap default.",
    "T4": "Aggressive. Faster; suitable for reliable networks.",
    "T5": "Insane. Very fast; can miss results or stress networks.",
}

NSE_CATEGORIES = {
    "auth": "Authentication-related checks.",
    "broadcast": "Local network broadcast discovery.",
    "brute": "Brute force checks. Intrusive and noisy.",
    "default": "Curated default scripts, equivalent to -sC.",
    "discovery": "Network and service discovery.",
    "dos": "Denial-of-service checks. High risk.",
    "exploit": "Exploit checks. Intrusive and high risk.",
    "external": "May contact third-party systems.",
    "fuzzer": "Fuzzing scripts. Intrusive.",
    "intrusive": "Likely to affect logs, stability, or service behavior.",
    "malware": "Malware/backdoor detection.",
    "safe": "Scripts intended to be low risk.",
    "version": "Version-detection support scripts.",
    "vuln": "Known vulnerability checks.",
}

RISKY_OPTIONS = {
    "evasion": "Packet shaping, spoofing, decoys, and unusual payload options can confuse monitoring and may break scans.",
    "intrusive_scripts": "NSE brute, exploit, dos, fuzzer, and intrusive scripts can cause account lockouts, outages, or strong alerts.",
    "privileged": "Raw packet scan modes and OS detection often require root/admin privileges.",
}


def all_help() -> dict[str, dict[str, str]]:
    return {
        "Scan types": SCAN_TYPES,
        "Discovery": DISCOVERY,
        "Timing": TIMING,
        "NSE categories": NSE_CATEGORIES,
        "Risk notes": RISKY_OPTIONS,
    }
