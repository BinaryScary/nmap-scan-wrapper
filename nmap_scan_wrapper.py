#!/usr/bin/env python3
"""
nmap-scan-wrapper: Port scanning tool with IP deduplication,
interactive nmap via PTY, and smap with native SOCKS5 proxy.
"""

import argparse
import ipaddress
import os
import pty
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import termios
import tty
import xml.etree.ElementTree as ET
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SMAP_SRC = SCRIPT_DIR / "smap"
SMAP_BIN = SCRIPT_DIR / "smap_bin"
CONFIG_FILE = SCRIPT_DIR / "config.toml"


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config():
    """Load config.toml, return dict."""
    if not CONFIG_FILE.exists():
        print(f"[!] Config file not found: {CONFIG_FILE}", file=sys.stderr)
        sys.exit(1)

    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            print("[!] tomli package required for Python <3.11. Run: pip install tomli",
                  file=sys.stderr)
            sys.exit(1)

    with open(CONFIG_FILE, "rb") as f:
        return tomllib.load(f)


# ---------------------------------------------------------------------------
# Target resolution & deduplication
# ---------------------------------------------------------------------------

def is_domain(s):
    """Return True if s is a hostname (not an IP address)."""
    try:
        ipaddress.ip_address(s)
        return False
    except ValueError:
        return "." in s


def resolve_and_dedup(input_file):
    """
    Read targets file, resolve hostnames to IPs, deduplicate.

    Returns:
        unique_ips: list of unique IP strings
        ip_to_hostnames: dict mapping IP -> list of hostnames
        unresolved: list of hostnames that failed DNS resolution
    """
    ip_to_hostnames = {}
    unresolved = []
    raw_ips = set()

    with open(input_file) as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    total = len(targets)
    print(f"[*] Resolving {total} targets...")

    for target in targets:
        if is_domain(target):
            try:
                results = socket.getaddrinfo(target, None, socket.AF_INET)
                ips = list({r[4][0] for r in results})
                for ip in ips:
                    ip_to_hostnames.setdefault(ip, [])
                    if target not in ip_to_hostnames[ip]:
                        ip_to_hostnames[ip].append(target)
            except (socket.gaierror, socket.herror):
                unresolved.append(target)
                print(f"    [!] Could not resolve: {target}")
        else:
            # Raw IP — track it, no hostname association needed
            raw_ips.add(target)
            ip_to_hostnames.setdefault(target, [])

    unique_ips = list(raw_ips | set(ip_to_hostnames.keys()))
    unique_ips.sort(key=lambda x: tuple(int(o) for o in x.split(".") if o.isdigit()))

    # Stats
    total_hostnames = sum(len(v) for v in ip_to_hostnames.values())
    saved = total - len(unique_ips)
    print(f"[+] {total} targets -> {len(unique_ips)} unique IPs "
          f"(saved {saved} duplicate scan{'s' if saved != 1 else ''})")
    if unresolved:
        print(f"[!] {len(unresolved)} hostname(s) could not be resolved")

    # Show dedup details for IPs with multiple hostnames
    for ip, hostnames in sorted(ip_to_hostnames.items()):
        if len(hostnames) > 1:
            print(f"    {ip} <- {', '.join(hostnames[:5])}"
                  f"{'...' if len(hostnames) > 5 else ''} ({len(hostnames)} hostnames)")

    return unique_ips, ip_to_hostnames, unresolved


# ---------------------------------------------------------------------------
# PTY execution (interactive nmap)
# ---------------------------------------------------------------------------

def set_winsize(fd, rows, cols):
    """Set terminal window size on a file descriptor."""
    import fcntl
    import struct
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def get_winsize(fd):
    """Get terminal window size."""
    import fcntl
    import struct
    packed = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\x00" * 8)
    rows, cols = struct.unpack("HHHH", packed)[:2]
    return rows, cols


def run_with_pty(command):
    """
    Run command in a PTY, forwarding stdin/stdout for full interactivity.
    Returns the exit code of the child process.
    """
    # Check if stdin is a TTY (won't be if piped)
    interactive = os.isatty(sys.stdin.fileno())

    pid, master_fd = pty.fork()

    if pid == 0:
        # Child process — exec the command
        os.execvp(command[0], command)
        # If exec fails
        os._exit(127)

    # Parent process
    if interactive:
        old_tty = termios.tcgetattr(sys.stdin)
        # Propagate current terminal size to child
        try:
            rows, cols = get_winsize(sys.stdin.fileno())
            set_winsize(master_fd, rows, cols)
        except Exception:
            pass

        # Handle window resize
        def handle_sigwinch(signum, frame):
            try:
                rows, cols = get_winsize(sys.stdin.fileno())
                set_winsize(master_fd, rows, cols)
            except Exception:
                pass

        signal.signal(signal.SIGWINCH, handle_sigwinch)

    try:
        if interactive:
            tty.setraw(sys.stdin.fileno())

        while True:
            fds = [master_fd]
            if interactive:
                fds.append(sys.stdin)

            try:
                rlist, _, _ = select.select(fds, [], [], 0.25)
            except (select.error, InterruptedError):
                # select interrupted by signal (SIGWINCH), just retry
                continue

            if master_fd in rlist:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)

            if interactive and sys.stdin in rlist:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                os.write(master_fd, data)
    finally:
        if interactive:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
            signal.signal(signal.SIGWINCH, signal.SIG_DFL)

    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    return 1


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------

def run_nmap_tcp(ip_file):
    """Run TCP nmap scan via PTY for interactivity."""
    cmd = [
        "sudo", "nmap",
        "-T5", "-Pn", "-v",
        "--host-timeout", "0",
        "--initial-rtt-timeout", "100ms",
        "--max-rtt-timeout", "200ms",
        "--script-timeout=30s",
        "--stats-every", "60s",
        "--top-ports", "5000",
        "-sV",
        "-oA", "3-nmap-tcp-all-ports",
        "-iL", ip_file,
    ]

    print(f"\n[*] Running TCP scan (top 5000 ports)...")
    print(f"[*] Command: {' '.join(cmd)}")
    print("[*] Nmap hotkeys: v/V=verbosity, d/D=debug, p=packet-trace, Enter=status\n")
    return run_with_pty(cmd)


def run_smap(ip_file, config):
    """Run smap with native SOCKS5 proxy."""
    proxy_cfg = config.get("proxy", {})
    proxy_addr = proxy_cfg.get("address", "")

    cmd = [str(SMAP_BIN)]
    if proxy_addr:
        cmd.extend(["--proxy", proxy_addr])
    cmd.extend(["-oA", "1-smap-all-ports", "-iL", ip_file])

    print(f"\n[*] Running smap scan...")
    if proxy_addr:
        print(f"[*] Using SOCKS5 proxy: {proxy_addr}")
    print(f"[*] Command: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=False)
    return result.returncode


def run_nmap_udp(ip_file):
    """Run UDP nmap scan via PTY for interactivity."""
    cmd = [
        "sudo", "nmap",
        "-T5", "-Pn", "-v",
        "--host-timeout", "0",
        "--initial-rtt-timeout", "100ms",
        "--max-rtt-timeout", "200ms",
        "--script-timeout=30s",
        "--stats-every", "60s",
        "-sV", "-sU",
        "-oA", "2-nmap-udp-1000-ports",
        "-iL", ip_file,
    ]

    print(f"\n[*] Running UDP scan (top 1000 ports)...")
    print(f"[*] Command: {' '.join(cmd)}")
    print("[*] Nmap hotkeys: v/V=verbosity, d/D=debug, p=packet-trace, Enter=status\n")
    return run_with_pty(cmd)


# ---------------------------------------------------------------------------
# XML domain augmentation
# ---------------------------------------------------------------------------

def augment_xml_with_hostnames(xml_file, ip_to_hostnames, unresolved, is_smap=False):
    """
    Add all matching hostnames to hosts in nmap/smap XML by IP resolution.
    Creates -final.xml output and backs up original as .xml.bak.
    """
    xml_path = Path(xml_file)
    if not xml_path.exists():
        print(f"[!] XML file not found, skipping augmentation: {xml_file}")
        return

    # Read original XML as text to preserve formatting for nmap files
    with open(xml_path, "r", encoding="utf-8") as f:
        original_xml = f.read()

    tree = ET.parse(xml_path)
    root = tree.getroot()

    matched_ips = set()
    added_count = 0

    for host in root.findall(".//host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            # Try without addrtype filter
            addr_elem = host.find("address")
        if addr_elem is None:
            continue

        ip = addr_elem.get("addr")
        if ip not in ip_to_hostnames:
            continue

        matched_ips.add(ip)
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is None:
            hostnames_elem = ET.SubElement(host, "hostnames")

        existing = {
            h.get("name", "").lower()
            for h in hostnames_elem.findall("hostname")
        }

        for hostname in ip_to_hostnames[ip]:
            if hostname.lower() not in existing:
                ET.SubElement(hostnames_elem, "hostname", name=hostname, type="user")
                existing.add(hostname.lower())
                added_count += 1

    # Handle smap-specific post-processing
    if is_smap:
        for host in root.findall(".//host"):
            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.findall("port"):
                service = port.find("service")
                if service is None:
                    continue
                name = service.get("name", "")
                if name.endswith("?"):
                    service.set("name", name[:-1])
                name_lower = name.lower()
                if any(kw in name_lower for kw in ("ssl", "tls", "https")):
                    if service.get("tunnel") != "ssl":
                        service.set("tunnel", "ssl")

    # Add stub entries for unmatched resolved hostnames
    all_matched_hostnames = set()
    for ip in matched_ips:
        all_matched_hostnames.update(ip_to_hostnames[ip])

    # Hostnames whose IP resolved but wasn't in scan results
    for ip, hostnames in ip_to_hostnames.items():
        if ip in matched_ips:
            continue
        for hostname in hostnames:
            if hostname.lower() in all_matched_hostnames:
                continue
            host_elem = ET.SubElement(root, "host")
            host_elem.set("starttime", "0")
            host_elem.set("endtime", "0")
            status = ET.SubElement(host_elem, "status")
            status.set("state", "unknown")
            status.set("reason", "no-scan-result")
            addr = ET.SubElement(host_elem, "address")
            addr.set("addr", ip)
            addr.set("addrtype", "ipv4")
            hn_elem = ET.SubElement(host_elem, "hostnames")
            ET.SubElement(hn_elem, "hostname", name=hostname, type="user")
            added_count += 1

    # Add stub entries for completely unresolved hostnames
    for hostname in unresolved:
        host_elem = ET.SubElement(root, "host")
        host_elem.set("starttime", "0")
        host_elem.set("endtime", "0")
        status = ET.SubElement(host_elem, "status")
        status.set("state", "unknown")
        status.set("reason", "unresolved")
        hn_elem = ET.SubElement(host_elem, "hostnames")
        ET.SubElement(hn_elem, "hostname", name=hostname, type="user")
        added_count += 1

    # Write output
    stem = xml_path.stem
    final_path = xml_path.with_name(f"{stem}-final.xml")
    tree.write(str(final_path), encoding="utf-8", xml_declaration=True)

    # Backup original
    bak_path = xml_path.with_suffix(".xml.bak")
    xml_path.rename(bak_path)

    print(f"[+] {xml_file}: added {added_count} hostname entries -> {final_path.name}")
    print(f"    Original backed up to {bak_path.name}")


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

def install():
    """Install dependencies: check nmap, build smap."""
    print("[*] Checking dependencies...\n")

    # Check nmap
    if shutil.which("nmap"):
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        version_line = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
        print(f"[+] nmap found: {version_line}")
    else:
        print("[!] nmap not found. Install with:")
        print("    macOS:  brew install nmap")
        print("    Linux:  sudo apt install nmap")
        sys.exit(1)

    # Check Go
    if not shutil.which("go"):
        print("[!] Go compiler not found. Install from https://go.dev/dl/")
        sys.exit(1)

    result = subprocess.run(["go", "version"], capture_output=True, text=True)
    print(f"[+] Go found: {result.stdout.strip()}")

    # Build smap
    print(f"\n[*] Building smap from source ({SMAP_SRC})...")
    result = subprocess.run(
        ["go", "build", "-o", str(SMAP_BIN), "./cmd/smap"],
        cwd=str(SMAP_SRC),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[!] smap build failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] smap built successfully: {SMAP_BIN}")

    # Install Python deps
    print("\n[*] Installing Python dependencies...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(SCRIPT_DIR / "requirements.txt")],
        capture_output=True,
    )
    print("[+] Python dependencies installed")
    print("\n[+] Installation complete!")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Port scanning wrapper with IP deduplication and interactive nmap",
    )
    parser.add_argument("input_file", nargs="?", help="File containing targets (hostnames/IPs)")
    parser.add_argument("--install", action="store_true", help="Install dependencies and build smap")

    args = parser.parse_args()

    if args.install:
        install()
        return

    if not args.input_file:
        parser.error("input_file is required (or use --install)")

    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"[!] Input file not found: {args.input_file}", file=sys.stderr)
        sys.exit(1)

    # Check smap binary exists
    if not SMAP_BIN.exists():
        print(f"[!] smap binary not found at {SMAP_BIN}")
        print("[!] Run with --install first to build smap")
        sys.exit(1)

    config = load_config()

    # Resolve and deduplicate targets
    unique_ips, ip_to_hostnames, unresolved = resolve_and_dedup(args.input_file)

    if not unique_ips:
        print("[!] No valid targets after resolution. Exiting.")
        sys.exit(1)

    # Write deduplicated IPs to temp file
    tmp_fd, tmp_ip_file = tempfile.mkstemp(prefix="nmap_dedup_", suffix=".txt")
    try:
        with os.fdopen(tmp_fd, "w") as f:
            for ip in unique_ips:
                f.write(ip + "\n")

        # Run scans
        print(f"\n{'='*60}")
        print("TCP SCAN")
        print(f"{'='*60}")
        run_nmap_tcp(tmp_ip_file)

        print(f"\n{'='*60}")
        print("SMAP SCAN")
        print(f"{'='*60}")
        run_smap(tmp_ip_file, config)

        print(f"\n{'='*60}")
        print("UDP SCAN")
        print(f"{'='*60}")
        run_nmap_udp(tmp_ip_file)

    finally:
        os.unlink(tmp_ip_file)

    # Post-process: augment XML files with hostnames
    print(f"\n{'='*60}")
    print("POST-PROCESSING")
    print(f"{'='*60}")

    xml_files = [
        ("3-nmap-tcp-all-ports.xml", False),
        ("1-smap-all-ports.xml", True),
        ("2-nmap-udp-1000-ports.xml", False),
    ]

    for xml_file, is_smap in xml_files:
        if Path(xml_file).exists():
            augment_xml_with_hostnames(xml_file, ip_to_hostnames, unresolved, is_smap=is_smap)

    print(f"\n[+] Scans completed.")


if __name__ == "__main__":
    main()
