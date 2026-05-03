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

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

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

TOP_100_PORTS: List[int] = sorted([
    21, 22, 23, 25, 53, 80, 110, 111, 119, 123, 135, 139, 143, 161, 194,
    389, 443, 445, 465, 514, 587, 631, 636, 993, 995, 1433, 1521, 1723,
    2049, 2181, 3000, 3306, 3389, 4369, 5000, 5432, 5672, 5900, 5985,
    6379, 6443, 7001, 8080, 8443, 8888, 9090, 9092, 9200, 9300, 9418,
    10250, 27017, 27018, 28015, 50070,
    20, 67, 68, 69, 79, 88, 102, 109, 113, 115, 137, 138, 156, 179, 199,
    211, 212, 264, 308, 383, 366, 369, 370, 372, 411, 412, 427, 444,
    500, 512, 513, 515, 520, 554, 601,
])



def get_service(port: int) -> str:
    """Return the known service name for a port, or 'Unknown'."""
    return COMMON_SERVICES.get(port, "Unknown")


def grab_banner(sock: socket.socket, port: int, timeout: float = 1.5) -> str:
    try:
        sock.settimeout(timeout)
        if port in (80, 8080, 8000, 8008):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        elif port in (443, 8443):
            return "TLS/SSL — use --tls flag to negotiate (not implemented here)"
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
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        if not hosts:
            hosts = [str(network.network_address)]
        return hosts
    except ValueError:
        pass
    try:
        resolved_ip = socket.gethostbyname(target)
        return [resolved_ip]
    except socket.gaierror:
        raise ValueError(f"Cannot resolve target: '{target}'")


def os_hint_from_ttl(ttl: int) -> str:
    if ttl <= 0:
        return "Unknown"
    if ttl <= 64:
        return "Linux / macOS / Android"
    if ttl <= 128:
        return "Windows"
    return "Network Device (Cisco/FreeBSD)"


def ping_sweep(targets: List[str], timeout: float = 1.0) -> List[str]:
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

_lock = threading.Lock()
_done_count = 0
_total_count = 0


def _progress_bar(host: str, port: int, is_open: bool) -> None:
    global _done_count
    with _lock:
        _done_count += 1
        done  = _done_count
        total = _total_count

    pct    = (done / total * 100) if total else 0
    filled = int(28 * done / total) if total else 0
    bar    = "█" * filled + "░" * (28 - filled)
    status = (
        f"{C['green']}OPEN{C['reset']}"
        if is_open
        else f"{C['dim']}----{C['reset']}"
    )
    sys.stderr.write(
        f"\r  {C['cyan']}{bar}{C['reset']} {pct:5.1f}%  "
        f"{C['white']}{host}:{port:<5}{C['reset']} {status}   "
    )
    sys.stderr.flush()


def scan_host(
    host: str,
    ports: List[int],
    timeout: float = 1.0,
    threads: int = 100,
    grab_banners: bool = True,
    show_progress: bool = True,
) -> Dict[str, Any]:
    open_ports: List[Dict[str, Any]] = []
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        future_map = {
            pool.submit(scan_port, host, port, timeout, grab_banners): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_map):
            try:
                port, is_open, banner, service = future.result()
                if show_progress:
                    _progress_bar(host, port, is_open)
                if is_open:
                    open_ports.append(
                        {"port": port, "service": service, "banner": banner}
                    )
            except Exception:
                pass  # Individual port failures are silently skipped

    elapsed = round(time.time() - start, 2)
    open_ports.sort(key=lambda x: x["port"])

    return {
        "host":           host,
        "open_ports":     open_ports,
        "total_scanned":  len(ports),
        "elapsed_seconds": elapsed,
        "timestamp":      datetime.now().isoformat(),
    }


def scan_network(
    targets: List[str],
    ports: List[int],
    timeout: float = 1.0,
    threads: int = 100,
    host_threads: int = 10,
    grab_banners: bool = True,
    show_progress: bool = True,
) -> List[Dict[str, Any]]:
    global _done_count, _total_count
    _done_count  = 0
    _total_count = len(targets) * len(ports)

    results: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=host_threads) as pool:
        future_map = {
            pool.submit(
                scan_host, host, ports, timeout, threads, grab_banners, show_progress
            ): host
            for host in targets
        }
        for future in concurrent.futures.as_completed(future_map):
            host = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append(
                    {
                        "host":            host,
                        "error":           str(exc),
                        "open_ports":      [],
                        "total_scanned":   0,
                        "elapsed_seconds": 0,
                        "timestamp":       datetime.now().isoformat(),
                    }
                )

    results.sort(
        key=lambda r: (
            [int(x) for x in r["host"].split(".")]
            if _is_valid_ip(r["host"])
            else [r["host"]]
        )
    )
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            "  Smart Network Scanner — Network Discovery & Auditing Tool\n"
            "  Multi-threaded · Banner Grabbing · CIDR · JSON/CSV Export"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  Scan a single host over common ports:
    python scanner.py -t 192.168.1.1 -p 1-1024

  Scan a full /24 subnet, specific ports, 200 threads:
    python scanner.py -t 192.168.1.0/24 -p 22,80,443,3306 --threads 200

  Full port scan with JSON export:
    python scanner.py -t 10.0.0.5 -p 1-65535 --threads 500 -o results.json

  Scan a hostname, skip banner grabbing, export to CSV:
    python scanner.py -t example.com -p 80,443 --no-banner -o results.csv

  Quiet scan (no progress bar — good for piping):
    python scanner.py -t 10.0.0.1 -p 1-1024 --quiet
  Ping sweep (host discovery only, no port scan):
    python scanner.py -t 192.168.1.0/24 --ping-sweep

  Scan only top 100 common ports:
    python scanner.py -t 192.168.1.1 --top-ports
        """,
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version="SmartScanner v1.0.0 — Network Discovery & Auditing Tool",
    )

    required = parser.add_argument_group("required arguments")
    required.add_argument(
        "--target", "-t",
        required=True,
        metavar="HOST/CIDR",
        help="Target IP, hostname, or CIDR block (e.g. 192.168.1.0/24)",
    )

    scan_opts = parser.add_argument_group("scan options")
    scan_opts.add_argument(
        "--ports", "-p",
        default="1-1024",
        metavar="PORTS",
        help=(
            "Ports to scan. Supports: single (80), range (1-1024), "
            "comma list (22,80,443), or mixed (22,80,8000-8100). "
            "[default: 1-1024]"
        ),
    )
    scan_opts.add_argument(
        "--threads", "-T",
        type=int,
        default=100,
        metavar="N",
        help="Threads per host — controls port-level parallelism [default: 100]",
    )
    scan_opts.add_argument(
        "--host-threads",
        type=int,
        default=10,
        metavar="N",
        help="Hosts to scan in parallel [default: 10]",
    )
    scan_opts.add_argument(
        "--timeout", "-to",
        type=float,
        default=1.0,
        metavar="SEC",
        help="TCP connection timeout in seconds [default: 1.0]",
    )
    scan_opts.add_argument(
        "--top-ports",
        action="store_true",
        help=f"Scan the top {len(TOP_100_PORTS)} most commonly used ports (overrides --ports)",
    )
    scan_opts.add_argument(
        "--ping-sweep",
        action="store_true",
        help="Discover live hosts only (TCP probe on ports 80/443/22/445) — no port scan",
    )
    scan_opts.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing (faster, less noisy on the network)",
    )

    output_opts = parser.add_argument_group("output options")
    output_opts.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Export results to a file (.json or .csv auto-detected by extension)",
    )
    output_opts.add_argument(
        "--log",
        metavar="FILE",
        default="scan_session.log",
        help="Session log file path [default: scan_session.log]",
    )
    output_opts.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress the live progress bar",
    )

    return parser

