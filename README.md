# Smart Network Scanner

> High-performance, multi-threaded TCP port scanner for internal network auditing.

**Course:** Python Programming – Network Programming Design  
**Assignment:** Group Assignment (Phase 1–5)  
**Due:** Sunday, 3 May 2026 | **Viva:** Monday, 4 May 2026

---

## Features

| Feature | Details |
|---|---|
| **Multi-threaded scanning** | Two-level parallelism — concurrent hosts + concurrent ports via `ThreadPoolExecutor` |
| **CIDR subnet support** | Scan full networks like `192.168.1.0/24` using the `ipaddress` module |
| **Banner grabbing** | Automatically probes open ports for service banners (SSH, HTTP, FTP, SMTP…) |
| **Service fingerprinting** | 60+ port→service mappings for instant service identification |
| **Flexible port syntax** | Single ports, ranges, comma lists, or any mix: `22,80,8000-8100` |
| **Top-ports shortcut** | `--top-ports` scans the ~90 most commonly targeted ports instantly |
| **Ping sweep** | `--ping-sweep` discovers live hosts via TCP probe (no root required) |
| **OS fingerprinting** | TTL-based OS family hinting (Linux / Windows / Network Device) |
| **Live progress bar** | Real-time per-port progress with open/closed status |
| **JSON & CSV export** | Machine-readable output for reporting and further analysis |
| **Session logging** | Every open port and scan event written to a timestamped log file |
| **Colorized output** | Full-colour terminal UI via `colorama` (graceful fallback if not installed) |

---

## Project Phases

| Phase | What was built | Owner |
|---|---|---|
| **Phase 1** | TCP scanner (`scan_port`), banner grabbing (`grab_banner`), service map (`COMMON_SERVICES`, `get_service`) | Member 1 |
| **Phase 2** | CIDR/hostname resolver (`resolve_targets`), flexible port parser (`parse_ports`) | Member 1 |
| **Phase 3** | `ThreadPoolExecutor` engine (`scan_host`, `scan_network`), live progress bar, argparse CLI | Member 2 |
| **Phase 5** | JSON/CSV export, session logging, colorized ASCII UI, full `main()` orchestrator, README | Member 3 |

---

## Requirements

- **Python 3.8+**
- **colorama** (optional — for coloured output)

No other external dependencies. All core modules (`socket`, `ipaddress`, `argparse`, `concurrent.futures`, `threading`, `json`, `csv`, `logging`) are part of the Python standard library.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/YourGroup/NPD-CW-Group-9.git
cd NPD-CW-Group-9

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python scanner.py --target 192.168.1.1 --ports 1-1024
```

---

## Usage

```
usage: scanner.py [-h] [-V] --target HOST/CIDR [--ports PORTS] [--threads N]
                  [--host-threads N] [--timeout SEC] [--top-ports]
                  [--ping-sweep] [--no-banner] [--output FILE]
                  [--log FILE] [--quiet]
```

### Arguments

| Flag | Short | Default | Description |
|---|---|---|---|
| `--target` | `-t` | *(required)* | Target IP, hostname, or CIDR block |
| `--ports` | `-p` | `1-1024` | Ports to scan (single / range / comma list) |
| `--threads` | `-T` | `100` | Threads per host (port-level parallelism) |
| `--host-threads` | | `10` | Hosts to scan in parallel |
| `--timeout` | `-to` | `1.0` | TCP connection timeout (seconds) |
| `--top-ports` | | off | Scan the top ~90 most common ports |
| `--ping-sweep` | | off | Discover live hosts only (no port scan) |
| `--no-banner` | | off | Skip banner grabbing for faster scans |
| `--output` | `-o` | | Export results to `.json` or `.csv` |
| `--log` | | `scan_session.log` | Session log file path |
| `--quiet` | `-q` | off | Suppress the live progress bar |
| `--version` | `-V` | | Print version and exit |

---

## Examples

### Scan a single host — common ports
```bash
python scanner.py -t 192.168.1.1 -p 1-1024
```

### Scan a full /24 subnet — specific ports, 200 threads
```bash
python scanner.py -t 192.168.1.0/24 -p 22,80,443,3306,3389 --threads 200
```

### Full port scan with JSON export
```bash
python scanner.py -t 10.0.0.5 -p 1-65535 --threads 500 -o results.json
```

### Scan a hostname and export to CSV
```bash
python scanner.py -t example.com -p 80,443,8080 -o results.csv
```

### Fast quiet scan (no banners, no progress bar)
```bash
python scanner.py -t 192.168.0.0/24 -p 22,80,443 --no-banner --quiet -o sweep.json
```

### Ping sweep — discover live hosts only (no port scan)
```bash
python scanner.py -t 192.168.1.0/24 --ping-sweep
```

### Scan top 90 most common ports
```bash
python scanner.py -t 192.168.1.1 --top-ports
```

---

## Sample Output

```
  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

  Network Discovery & Auditing Tool  v1.0.0

  ──────────────────────────────────────────────────────
  Target    :  192.168.1.1
  Hosts     :  1
  Ports     :  1–1024  (1024 ports)
  Threads   :  100 per host  /  10 host(s) parallel
  Timeout   :  1.0s
  Banners   :  enabled
  Log       :  scan_session.log
  ──────────────────────────────────────────────────────

  ████████████████████████████ 100.0%  192.168.1.1:1024  ----

  ┌─ 192.168.1.1  1024 ports · 4.31s
  │
  ├─ 22     SSH                OPEN
  │    ↳ SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  ├─ 80     HTTP               OPEN
  │    ↳ HTTP/1.1 200 OK
  └─ 443    HTTPS              OPEN

    3 open port(s) on 192.168.1.1

  ══════════════════════════════════════════════════════
  Scan Summary
  ──────────────────────────────────────────────────────
  Hosts scanned            :  1
  Hosts with open ports    :  1
  Total ports tested       :  1,024
  Open ports found         :  3
  Total scan time          :  4.31s
  ══════════════════════════════════════════════════════
```

---

## JSON Output Format

```json
{
  "tool": "SmartScanner v1.0.0",
  "scan_time": "2026-05-03T14:22:01.123456",
  "total_hosts": 1,
  "results": [
    {
      "host": "192.168.1.1",
      "open_ports": [
        { "port": 22,  "service": "SSH",   "banner": "SSH-2.0-OpenSSH_8.9p1" },
        { "port": 80,  "service": "HTTP",  "banner": "HTTP/1.1 200 OK"        },
        { "port": 443, "service": "HTTPS", "banner": ""                       }
      ],
      "total_scanned": 1024,
      "elapsed_seconds": 4.31,
      "timestamp": "2026-05-03T14:22:01.123456"
    }
  ]
}
```

---

## Project Structure

```
NPD-CW-Group-9/
├── scanner.py          ← Main source code (all five phases)
├── README.md           ← This file
├── requirements.txt    ← Python dependencies
└── .gitignore          ← Git ignore rules
```

---

## Team Contributions

| Member | Phases | Key Commits |
|---|---|---|
| **Member 1** | Phase 1 + 2 | TCP scanner, banner grabbing, service map (60+ entries), subnet/port parsers |
| **Member 2** | Phase 3 + 4 | ThreadPoolExecutor engine, parallel host scanning, ping sweep, OS fingerprinting, argparse CLI |
| **Member 3** | Phase 5 + Integration | GitHub repo setup, output layer, JSON/CSV export, logging, README |

Each member must have visible commit history on the GitHub repository.

---

## Ethical Use Notice

This tool is for **authorised internal network auditing only**.  
Never scan networks or hosts without explicit written permission from the owner.  
Unauthorised port scanning may be illegal under computer misuse laws in your jurisdiction.

---

## License

MIT License — see `LICENSE` for details.
