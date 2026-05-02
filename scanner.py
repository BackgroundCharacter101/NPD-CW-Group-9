#!/usr/bin/env python3
"""
scanner.py — Network Discovery & Auditing Tool
High-performance multi-threaded TCP port scanner for internal network auditing.

Course    : Python Programming – Network Programming Design
Type      : Group Assignment
Due       : Sunday, 3 May 2026

Phases:
  Phase 1 — Core TCP scanning, banner grabbing, service fingerprinting
  Phase 2 — CIDR subnet support, flexible port parsing, hostname resolution
  Phase 3 — ThreadPoolExecutor engine, two-level parallelism, progress bar
  Phase 4 — Ping sweep (ICMP/TCP), OS fingerprinting via TTL, top-ports shortcut
  Phase 5 — JSON/CSV export, session logging, colorized UI, full CLI

Usage:
    python scanner.py --target 192.168.1.1 --ports 1-1024
    python scanner.py --target 192.168.1.0/24 --top-ports --threads 200
    python scanner.py --target 192.168.1.1 --ports 1-65535 --threads 500 --output results.json
    python scanner.py --target 192.168.1.0/24 --ping-sweep
"""

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


# ══════════════════════════════════════════════════════════════════════════════
#  MEMBER 2 — THREADING ENGINE & CLI
#
#  Commit 1 ▸ feat: add multi-threaded port scan engine (ThreadPoolExecutor)
#             scan_host() — thread pool per host
#
#  Commit 2 ▸ feat: add parallel host scanning with live progress tracking
#             scan_network(), _progress_bar()
#
#  Commit 3 ▸ feat: add professional argparse CLI with full flag set
#             build_parser()
# ══════════════════════════════════════════════════════════════════════════════

# Thread-safe shared counters for the progress bar
_lock = threading.Lock()
_done_count = 0
_total_count = 0


def _progress_bar(host: str, port: int, is_open: bool) -> None:
    """
    Update and redraw the live scan progress bar on stderr.
    Thread-safe via _lock.
    """
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
    """
    Scan all ports on a single host using a ThreadPoolExecutor.

    Each port gets its own thread. Results are collected as futures complete,
    so fast (refused) connections don't wait on slow (filtered/timed-out) ones.

    Returns a dict with host, open_ports list, and scan metadata.
    """
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
    """
    Scan multiple hosts in parallel (two-level parallelism).

    Level 1: host_threads hosts are scanned concurrently.
    Level 2: each host uses up to `threads` threads for its ports.

    This gives O(host_threads × threads) concurrent connections,
    making subnet sweeps dramatically faster than sequential host scanning.
    """
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

    # Sort results by IP address for clean output
    results.sort(
        key=lambda r: (
            [int(x) for x in r["host"].split(".")]
            if _is_valid_ip(r["host"])
            else [r["host"]]
        )
    )
    return results


def build_parser() -> argparse.ArgumentParser:
    """
    Build the argparse CLI parser with a full professional flag set.
    """
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


# ══════════════════════════════════════════════════════════════════════════════
#  MEMBER 3 — OUTPUT, LOGGING & INTEGRATION
#
#  Commit 1 ▸ chore: init repo, add .gitignore and requirements.txt
#
#  Commit 2 ▸ feat: add colorized terminal output and ASCII banner
#             print_banner(), print_host_result(), print_summary()
#
#  Commit 3 ▸ feat: add JSON and CSV export
#             export_json(), export_csv()
#
#  Commit 4 ▸ feat: add session logging
#             setup_logging()
#
#  Commit 5 ▸ feat: integrate all modules — main() orchestrator
#             main()
#
#  Commit 6 ▸ docs: professional README.md with setup guide and examples
# ══════════════════════════════════════════════════════════════════════════════

ASCII_BANNER = r"""
  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""


def setup_logging(log_file: str) -> logging.Logger:
    """Configure a file-based session logger."""
    logger = logging.getLogger("scanner")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(fh)
    return logger


def print_banner() -> None:
    """Print the colourised ASCII art banner."""
    print(f"{C['cyan']}{C['bold']}{ASCII_BANNER}{C['reset']}", end="")
    print(
        f"  {C['yellow']}Network Discovery & Auditing Tool{C['reset']}  "
        f"{C['dim']}v1.0.0{C['reset']}\n"
        f"  {C['dim']}Multi-threaded · Banner Grabbing · CIDR Support · "
        f"JSON/CSV Export{C['reset']}\n"
    )


def print_scan_header(args: argparse.Namespace, targets: List[str], ports: List[int]) -> None:
    """Print the pre-scan configuration table."""
    port_display = (
        args.ports if len(ports) <= 20
        else f"{ports[0]}–{ports[-1]}  ({len(ports)} ports)"
    )
    rows = [
        ("Target",   args.target),
        ("Hosts",    str(len(targets))),
        ("Ports",    port_display),
        ("Threads",  f"{args.threads} per host  /  {args.host_threads} host(s) parallel"),
        ("Timeout",  f"{args.timeout}s"),
        ("Banners",  "disabled" if args.no_banner else "enabled"),
        ("Log",      args.log),
    ]
    if args.output:
        rows.append(("Output", args.output))

    w = max(len(k) for k, _ in rows)
    print(f"  {C['dim']}{'─'*54}{C['reset']}")
    for key, val in rows:
        print(
            f"  {C['bold']}{key.ljust(w)}{C['reset']}  "
            f"{C['cyan']}{val}{C['reset']}"
        )
    print(f"  {C['dim']}{'─'*54}{C['reset']}\n")


def print_host_result(result: Dict[str, Any], logger: logging.Logger) -> None:
    """Pretty-print results for a single scanned host."""
    host        = result["host"]
    open_ports  = result.get("open_ports", [])
    elapsed     = result.get("elapsed_seconds", 0)
    error       = result.get("error")

    if error:
        print(
            f"\n  {C['red']}✗{C['reset']} "
            f"{C['bold']}{host}{C['reset']}  "
            f"{C['red']}Error: {error}{C['reset']}"
        )
        logger.error(f"{host} — scan error: {error}")
        return

    if not open_ports:
        print(
            f"  {C['dim']}○ {host}  "
            f"— no open ports  ({elapsed}s){C['reset']}"
        )
        logger.info(f"{host} — 0 open ports ({elapsed}s)")
        return

    # Host header
    print(
        f"\n  {C['bold']}{C['cyan']}┌─ {host}{C['reset']}  "
        f"{C['dim']}{result['total_scanned']} ports · {elapsed}s{C['reset']}"
    )
    print(f"  {C['cyan']}│{C['reset']}")

    for i, entry in enumerate(open_ports):
        port    = entry["port"]
        service = entry["service"]
        banner  = entry["banner"]
        is_last = i == len(open_ports) - 1
        branch  = "└─" if is_last else "├─"

        svc_col    = f"{C['yellow']}{service:<18}{C['reset']}"
        banner_col = (
            f"\n  {C['dim']}{'   ' if is_last else '│  '}  ↳ {banner[:90]}{C['reset']}"
            if banner else ""
        )
        print(
            f"  {C['cyan']}{branch}{C['reset']} "
            f"{C['green']}{C['bold']}{port:<6}{C['reset']} "
            f"{svc_col} "
            f"{C['green']}OPEN{C['reset']}"
            f"{banner_col}"
        )
        logger.info(
            f"{host}:{port}  {service:<18}  OPEN  "
            f"banner={banner[:80] or 'n/a'}"
        )

    print(
        f"\n  {C['dim']}  {len(open_ports)} open port(s) on {host}{C['reset']}"
    )


def print_summary(results: List[Dict[str, Any]], total_time: float) -> None:
    """Print final scan statistics."""
    total_hosts    = len(results)
    hosts_with_open = sum(1 for r in results if r.get("open_ports"))
    total_open     = sum(len(r.get("open_ports", [])) for r in results)
    total_scanned  = sum(r.get("total_scanned", 0) for r in results)

    print(f"\n  {C['dim']}{'═'*54}{C['reset']}")
    print(f"  {C['bold']}Scan Summary{C['reset']}")
    print(f"  {C['dim']}{'─'*54}{C['reset']}")
    _row = lambda k, v, col="cyan": print(
        f"  {k:<26}: {C[col]}{C['bold']}{v}{C['reset']}"
    )
    _row("Hosts scanned",       total_hosts)
    _row("Hosts with open ports", hosts_with_open, "green")
    _row("Total ports tested",  f"{total_scanned:,}")
    _row("Open ports found",    f"{total_open:,}", "green")
    _row("Total scan time",     f"{total_time:.2f}s", "yellow")
    print(f"  {C['dim']}{'═'*54}{C['reset']}\n")


def export_json(results: List[Dict[str, Any]], filepath: str) -> None:
    """Export full scan results to a JSON file."""
    payload = {
        "tool":       "SmartScanner v1.0.0",
        "scan_time":  datetime.now().isoformat(),
        "total_hosts": len(results),
        "results":    results,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(
        f"  {C['green']}✓{C['reset']} "
        f"JSON exported → {C['cyan']}{filepath}{C['reset']}"
    )


def export_csv(results: List[Dict[str, Any]], filepath: str) -> None:
    """Export scan results to a CSV file (one row per open port)."""
    fields = ["host", "port", "service", "banner", "elapsed_seconds", "timestamp"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for result in results:
            host    = result["host"]
            elapsed = result.get("elapsed_seconds", "")
            ts      = result.get("timestamp", "")
            for entry in result.get("open_ports", []):
                writer.writerow(
                    {
                        "host":             host,
                        "port":             entry["port"],
                        "service":          entry["service"],
                        "banner":           entry.get("banner", ""),
                        "elapsed_seconds":  elapsed,
                        "timestamp":        ts,
                    }
                )
    print(
        f"  {C['green']}✓{C['reset']} "
        f"CSV exported  → {C['cyan']}{filepath}{C['reset']}"
    )


def main() -> None:
    """Main entry point — orchestrates the full scan lifecycle."""
    parser = build_parser()
    args   = parser.parse_args()

    print_banner()
    logger = setup_logging(args.log)

    # ── 1. Resolve targets ───────────────────────────────────────────────────
    try:
        targets = resolve_targets(args.target)
    except ValueError as exc:
        print(f"  {C['red']}[ERROR]{C['reset']} {exc}")
        sys.exit(1)

    # ── 1b. Ping sweep mode ──────────────────────────────────────────────────
    if args.ping_sweep:
        print(
            f"  {C['cyan']}{C['bold']}[ Ping Sweep ]{C['reset']}  "
            f"Probing {len(targets)} host(s) for liveness…\n"
        )
        alive = ping_sweep(targets, timeout=args.timeout)
        if alive:
            print(f"  {C['green']}{C['bold']}{len(alive)} host(s) responded:{C['reset']}")
            for h in alive:
                print(f"    {C['green']}●{C['reset']}  {h}")
        else:
            print(f"  {C['yellow']}No hosts responded to the TCP probe.{C['reset']}")
        print()
        sys.exit(0)

    # ── 2. Parse ports ───────────────────────────────────────────────────────
    if args.top_ports:
        ports = TOP_100_PORTS
        print(
            f"  {C['dim']}Using top {len(ports)} common ports.{C['reset']}\n"
        )
    else:
        try:
            ports = parse_ports(args.ports)
        except argparse.ArgumentTypeError as exc:
            print(f"  {C['red']}[ERROR]{C['reset']} {exc}")
            sys.exit(1)

    # ── 3. Print scan header ─────────────────────────────────────────────────
    print_scan_header(args, targets, ports)

    logger.info(
        f"Scan started — target={args.target}  hosts={len(targets)}  "
        f"ports={len(ports)}  threads={args.threads}  timeout={args.timeout}"
    )

    # ── 4. Run the scan ───────────────────────────────────────────────────────
    global_start = time.time()
    results = scan_network(
        targets      = targets,
        ports        = ports,
        timeout      = args.timeout,
        threads      = args.threads,
        host_threads = args.host_threads,
        grab_banners = not args.no_banner,
        show_progress= not args.quiet,
    )
    total_time = time.time() - global_start

    # Clear the progress bar line
    if not args.quiet:
        sys.stderr.write("\r" + " " * 90 + "\r")
        sys.stderr.flush()

    # ── 5. Print results ──────────────────────────────────────────────────────
    if len(targets) > 1:
        print()
    for result in results:
        print_host_result(result, logger)

    print_summary(results, total_time)
    logger.info(f"Scan complete — {len(results)} hosts in {total_time:.2f}s")

    # ── 6. Export ─────────────────────────────────────────────────────────────
    if args.output:
        if args.output.endswith(".csv"):
            export_csv(results, args.output)
        else:
            if not args.output.endswith(".json"):
                args.output += ".json"
            export_json(results, args.output)


if __name__ == "__main__":
    main()
