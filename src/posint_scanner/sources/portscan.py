"""Active source: TCP connect scan + banner grab against discovered IPs.

Alongside `ping`, this is the only source that touches the target directly
rather than querying a resolver or third-party API. Runs by default; opt
out with `--no-scan-ports`. Useful as an
independent fallback for open ports/service versions when Shodan/Censys
don't have data for a host (free tier, host not indexed yet, etc.) - the
NVD vulnerability lookup stage treats whatever this finds the same as
anything from Shodan/Censys.

Not a full port-range scan (that's a much heavier, noisier operation) - just
a bounded list of commonly-open TCP services.
"""

from __future__ import annotations

import re
import threading
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from posint_scanner import proxy
from posint_scanner.models import EnrichmentResult, ServiceInfo
from posint_scanner.sources.base import Source

CONNECT_TIMEOUT_SECONDS = 1.5
READ_TIMEOUT_SECONDS = 2.0
SCAN_WORKERS = 50
# Process-wide cap on probes in flight (one socket each). Per-IP pools run
# inside the enrichment pool, across concurrent domains and web UI scans, so
# without a shared cap those multiply into thousands of open sockets.
MAX_CONCURRENT_PROBES = 200
_PROBE_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_PROBES)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900,
    5984, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 9300,
    11211, 27017,
]  # fmt: skip

TLS_PORTS = {443, 8443, 993, 995, 465, 587}

SSH_RE = re.compile(r"^SSH-\d\.\d-(?P<product>[A-Za-z][\w.]*)_(?P<version>[\w.+-]+)")
SERVER_HEADER_RE = re.compile(r"^Server:\s*([^\r\n/]+)/?([\w.]*)", re.IGNORECASE | re.MULTILINE)
FTP_RE = re.compile(r"\(([A-Za-z][\w-]*)\s+([\d][\w.-]*)\)")


def parse_banner(port: int, banner: str) -> tuple[str | None, str | None]:
    """Best-effort product/version extraction from a raw banner. Returns
    (product, version) - either may be None if nothing recognizable
    matched, in which case the raw banner is still kept as-is by the
    caller."""
    match = SSH_RE.match(banner)
    if match:
        return match.group("product"), match.group("version")

    server_match = SERVER_HEADER_RE.search(banner)
    if server_match:
        product = server_match.group(1).strip()
        version = server_match.group(2).strip() or None
        return product, version

    ftp_match = FTP_RE.search(banner)
    if ftp_match:
        return ftp_match.group(1), ftp_match.group(2)

    return None, None


def _connect(ip: str, port: int) -> socket.socket | None:
    try:
        return proxy.create_connection((ip, port), timeout=CONNECT_TIMEOUT_SECONDS)
    except OSError:
        return None


def probe_port(ip: str, port: int) -> tuple[bool, str | None]:
    """Returns (is_open, raw_banner_or_None). A port can be open with no
    parseable banner - plenty of binary-protocol services (databases, etc.)
    don't send anything without a specific first message this doesn't
    send."""
    with _PROBE_SLOTS:
        return _probe(ip, port)


def _probe(ip: str, port: int) -> tuple[bool, str | None]:
    sock = _connect(ip, port)
    if sock is None:
        return False, None

    try:
        if port in TLS_PORTS:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)
            except (ssl.SSLError, OSError):
                return True, None  # open, but TLS handshake failed - still "open"

        data = b""
        try:
            sock.settimeout(0.5)
            data = sock.recv(4096)
        except OSError:
            data = b""

        if not data:
            # No greeting - try an HTTP probe regardless of port number.
            # Plenty of real HTTP servers run on nonstandard ports; the
            # cost of trying this against a non-HTTP service is just an
            # unused ~2s timeout, not a real downside.
            try:
                sock.settimeout(READ_TIMEOUT_SECONDS)
                sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                data = sock.recv(4096)
            except OSError:
                data = b""

        return True, data.decode(errors="replace") if data else None
    finally:
        sock.close()


class PortScanSource(Source):
    name = "portscan"
    category = "active"

    def enrich(self, target: str, hostnames: list[str]) -> EnrichmentResult:
        services: list[ServiceInfo] = []
        raw_banners: dict[int, str] = {}

        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as executor:
            futures = {
                executor.submit(probe_port, target, port): port for port in COMMON_PORTS
            }
            for future in as_completed(futures):
                port = futures.pop(future)
                is_open, banner = future.result()
                if not is_open:
                    continue

                product, version = parse_banner(port, banner) if banner else (None, None)
                # fall back to the raw banner's first line when nothing
                # recognizable matched, rather than leaving it blank -
                # still something a person can look at.
                display_banner = product or (banner.splitlines()[0][:80] if banner else None)
                services.append(
                    ServiceInfo(port=port, protocol="tcp", banner=display_banner, version=version)
                )
                if banner:
                    raw_banners[port] = banner

        return EnrichmentResult(
            source="portscan",
            target_type="ip",
            target=target,
            data={"open_ports": sorted(s.port for s in services), "raw_banners": raw_banners},
            services=services,
        )
