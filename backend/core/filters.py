# Pre-allocate sets at the module level for O(1) lookup speed
DNS_SUPPRESS_ALERTS = {"SQL Injection", "SSH-Bruteforce"}
MULTICAST_SUPPRESS_ALERTS = {"Reconnaissance", "SSH-Bruteforce"}

def is_multicast_fast(ip_str: str) -> bool:
    # Performance improvement: Avoid instantiating ipaddress objects.
    # Multicast IPs range from 224.0.0.0 to 239.255.255.255.
    try:
        first_octet = ip_str.split('.', 1)[0]
        return 224 <= int(first_octet) <= 239
    except (ValueError, IndexError, AttributeError):
        # Security note: Reaching here implies upstream IP validation failure.
        return False

def suppress_false_positive(alert_type: str, protocol: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bool:
    """
    Evaluates network flow properties against specific false-positive intersection rules.
    Returns True if the alert should be suppressed (treated as Benign).
    """
    # Group by protocol to minimize redundant evaluations
    if protocol == "UDP":
        # Rule 1: Suppress specific alerts on DNS (UDP/53)
        if dst_port == 53 and alert_type in DNS_SUPPRESS_ALERTS:
            return True
            
        # Rule 2: Suppress SSH-Bruteforce on DHCP (UDP 68 -> 67)
        if dst_port == 67 and src_port == 68 and alert_type == "SSH-Bruteforce":
            return True

    # Rule 4: Suppress Reconnaissance on specific internal heartbeat/unknown packets
    # Match both representation variants to prevent parser-dependent evasion
    elif protocol in ("UNKNOWN", "HOPOPT") and dst_port == 0 and src_port == 0:
        if alert_type == "Reconnaissance" and src_ip == "8.6.0.1" and dst_ip == "8.0.6.4":
            return True

    # Rule 3: Suppress Reconnaissance and SSH-Bruteforce on Multicast traffic
    # Short-circuit logic: Check alert_type first
    if alert_type in MULTICAST_SUPPRESS_ALERTS and is_multicast_fast(dst_ip):
        return True

    return False
