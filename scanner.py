import socket
import ipaddress
import argparse
import concurrent.futures
import threading
import json
import csv
import sys
import time
import logging
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any

# Ensure stdout/stderr use UTF-8 so box-drawing and block characters
# render correctly on Windows (avoids cp1252 UnicodeEncodeError).
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# ══════════════════════════════════════════════════════════════════════════════
#  COLOR LAYER  (Member 3 — Output & UI)
# ══════════════════════════════════════════════════════════════════════════════

try:
    import colorama
    colorama.init(autoreset=True)
    C = {
        "green":  colorama.Fore.GREEN,
        "red":    colorama.Fore.RED,
        "yellow": colorama.Fore.YELLOW,
        "cyan":   colorama.Fore.CYAN,
        "white":  colorama.Fore.WHITE,
        "blue":   colorama.Fore.BLUE,
        "magenta":colorama.Fore.MAGENTA,
        "bold":   colorama.Style.BRIGHT,
        "dim":    colorama.Style.DIM,
        "reset":  colorama.Style.RESET_ALL,
    }
    HAS_COLOR = True
except ImportError:
    C = {k: "" for k in (
        "green","red","yellow","cyan","white","blue","magenta","bold","dim","reset"
    )}
    HAS_COLOR = False


# ══════════════════════════════════════════════════════════════════════════════
#  MEMBER 1 — CORE NETWORKING LAYER
#
#  Commit 1 ▸ feat: add TCP port scanner with timeout handling
#             scan_port(), grab_banner()
#
#  Commit 2 ▸ feat: add subnet/host parser supporting CIDR and hostnames
#             resolve_targets(), parse_ports()
#
#  Commit 3 ▸ feat: add extended service fingerprinting map
#             COMMON_SERVICES dict, get_service()
# ══════════════════════════════════════════════════════════════════════════════

# Service fingerprint map — port → service name
COMMON_SERVICES: Dict[int, str] = {
    20: "FTP-Data",    21: "FTP",           22: "SSH",         23: "Telnet",
    25: "SMTP",        53: "DNS",           67: "DHCP",        68: "DHCP",
    69: "TFTP",        80: "HTTP",         110: "POP3",       119: "NNTP",
   123: "NTP",        135: "MS-RPC",       137: "NetBIOS",    139: "NetBIOS",
   143: "IMAP",       161: "SNMP",         194: "IRC",        389: "LDAP",
   443: "HTTPS",      445: "SMB",          465: "SMTPS",      514: "Syslog",
   587: "SMTP-Sub",   631: "IPP",          636: "LDAPS",      993: "IMAPS",
   995: "POP3S",     1433: "MSSQL",       1521: "Oracle-DB", 1723: "PPTP",
  2049: "NFS",       2181: "Zookeeper",   3000: "Node/Grafana",3306: "MySQL",
  3389: "RDP",       4369: "RabbitMQ",    5000: "Flask/API",  5432: "PostgreSQL",
  5672: "AMQP",      5900: "VNC",         5985: "WinRM",      6379: "Redis",
  6443: "K8s-API",   7001: "WebLogic",    8080: "HTTP-Alt",   8443: "HTTPS-Alt",
  8888: "Jupyter",   9090: "Prometheus",  9092: "Kafka",      9200: "Elasticsearch",
  9300: "ES-Cluster",9418: "Git",        10250: "K8s-Kubelet",27017: "MongoDB",
 27018: "MongoDB",   28015: "RethinkDB", 50070: "Hadoop-NN",
}

# Top 100 most commonly scanned TCP ports (shortcut for --top-ports flag)
TOP_100_PORTS: List[int] = sorted([
    21, 22, 23, 25, 53, 80, 110, 111, 119, 123, 135, 139, 143, 161, 194,
    389, 443, 445, 465, 514, 587, 631, 636, 993, 995, 1433, 1521, 1723,
    2049, 2181, 3000, 3306, 3389, 4369, 5000, 5432, 5672, 5900, 5985,
    6379, 6443, 7001, 8080, 8443, 8888, 9090, 9092, 9200, 9300, 9418,
    10250, 27017, 27018, 28015, 50070,
    # Additional well-known ports
    20, 67, 68, 69, 79, 88, 102, 109, 113, 115, 137, 138, 156, 179, 199,
    211, 212, 264, 308, 383, 366, 369, 370, 372, 411, 412, 427, 444,
    500, 512, 513, 515, 520, 554, 601,
])



def get_service(port: int) -> str:
    """Return the known service name for a port, or 'Unknown'."""
    return COMMON_SERVICES.get(port, "Unknown")


def grab_banner(sock: socket.socket, port: int, timeout: float = 1.5) -> str:
    """
    Attempt to grab a service banner from an already-open socket.
    Sends an appropriate probe depending on the port, reads up to 1 KB.
    Returns the first line of the response (max 120 chars), or empty string.
    """
    try:
        sock.settimeout(timeout)
        # HTTP probe
        if port in (80, 8080, 8000, 8008):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        elif port in (443, 8443):
            return "TLS/SSL — use --tls flag to negotiate (not implemented here)"
        # SSH / FTP / SMTP send a banner automatically on connect — just read
        data = sock.recv(1024)
        banner = data.decode("utf-8", errors="replace").strip()
        first_line = banner.split("\n")[0].strip()
        return first_line[:120] if first_line else ""
    except Exception:
        return ""


def scan_port(
    host: str,
    port: int,
    timeout: float = 1.0,
    grab_banners: bool = True,
) -> Tuple[int, bool, str, str]:
    """
    Attempt a non-blocking TCP connection to host:port.

    Uses connect_ex() which returns an OS error code on failure (instead of
    raising an exception), making it safe to call in tight loops.

    Returns:
        (port, is_open, banner, service_name)
    """
    service = get_service(port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = grab_banner(sock, port) if grab_banners else ""
                return (port, True, banner, service)
    except (socket.timeout, socket.error, OSError):
        pass
    return (port, False, "", service)


def parse_ports(port_string: str) -> List[int]:
    """
    Parse a port specification into a sorted, deduplicated list of ints.

    Supported formats:
        80             → single port
        1-1024         → inclusive range
        22,80,443      → comma-separated list
        22,80,8000-8100 → mixed
    """
    ports: List[int] = []
    for segment in port_string.split(","):
        segment = segment.strip()
        if not segment:
            continue
        if "-" in segment:
            parts = segment.split("-", 1)
            try:
                start, end = int(parts[0].strip()), int(parts[1].strip())
            except ValueError:
                raise argparse.ArgumentTypeError(
                    f"Invalid port range: '{segment}'"
                )
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise argparse.ArgumentTypeError(
                    f"Port range out of bounds (1-65535): '{segment}'"
                )
            ports.extend(range(start, end + 1))
        else:
            try:
                p = int(segment)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port: '{segment}'")
            if not (1 <= p <= 65535):
                raise argparse.ArgumentTypeError(
                    f"Port out of range (1-65535): {p}"
                )
            ports.append(p)
    if not ports:
        raise argparse.ArgumentTypeError("No valid ports specified.")
    return sorted(set(ports))


def resolve_targets(target: str) -> List[str]:
    """
    Resolve a target string to a list of IP address strings.

    Accepts:
        192.168.1.5        → single IP
        192.168.1.0/24     → CIDR block (yields all host IPs)
        example.com        → hostname (resolved via DNS)
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        if not hosts:
            # /32 or /128 — single host
            hosts = [str(network.network_address)]
        return hosts
    except ValueError:
        pass
    # Hostname
    try:
        resolved_ip = socket.gethostbyname(target)
        return [resolved_ip]
    except socket.gaierror:
        raise ValueError(f"Cannot resolve target: '{target}'")


def os_hint_from_ttl(ttl: int) -> str:
    """
    Estimate the OS family from an IP TTL value.
    Different operating systems use different default TTL values:
      Linux/Android  : 64
      Windows        : 128
      Cisco IOS      : 255
      FreeBSD/macOS  : 64 (sometimes 255)
    We compare against common thresholds (TTL decrements per hop).
    """
    if ttl <= 0:
        return "Unknown"
    if ttl <= 64:
        return "Linux / macOS / Android"
    if ttl <= 128:
        return "Windows"
    return "Network Device (Cisco/FreeBSD)"


def ping_sweep(targets: List[str], timeout: float = 1.0) -> List[str]:
    """
    Perform a TCP-based 'ping' sweep to discover live hosts.

    Since ICMP requires root/admin privileges on most systems, we use a
    TCP SYN probe on port 80 (and 443 fallback) to detect live hosts.
    This is a common technique used by Nmap's -sn (no-port-scan) mode.

    Returns a list of hosts that responded (appear to be alive).
    """
    alive: List[str] = []
    lock  = threading.Lock()

    def _probe(host: str) -> None:
        for probe_port in (80, 443, 22, 445):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((host, probe_port)) == 0:
                        with lock:
                            alive.append(host)
                        return
            except OSError:
                continue

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        list(pool.map(_probe, targets))

    return sorted(
        alive,
        key=lambda ip: (
            [int(x) for x in ip.split(".")] if _is_valid_ip(ip) else [ip]
        ),
    )


def _is_valid_ip(s: str) -> bool:
    """Return True if s is a valid IPv4 or IPv6 address string."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
