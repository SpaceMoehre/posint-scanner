"""Global SOCKS5 proxy: when configured, every connection a scan makes goes
through it - or doesn't happen at all.

Set from the web UI's Settings page (stored in the DB, see settings.py) and
applied at the start of every scan by `configure`. What it covers:

  * HTTP(S) via `requests` - the proxy env vars (HTTP_PROXY/HTTPS_PROXY/
    ALL_PROXY) are set process-wide, so every `requests.get` picks them up;
    `socks5h` means hostnames resolve at the proxy, not locally. NO_PROXY is
    cleared so nothing is exempt.
  * Subprocesses (git, trivy, checkov, ...) inherit those env vars; the tools
    that ignore env take an explicit flag (`tool_proxy_url`, see nuclei.py,
    subfinder.py, webscan.py). Tools that can't tunnel at all (ICMP ping,
    Nikto, takeover, theHarvester) are skipped while a proxy is set - see
    `unavailable_reason`.
  * Raw TCP (the port scan) via `create_connection`.
  * DNS via dnspython: SOCKS5 can't carry UDP (not portably), so every query
    goes over TCP through the tunnel - `dns.query.udp` is rerouted to
    `dns.query.tcp`, dnspython's socket factory hands out tunnelled sockets,
    and a UDP socket request raises instead of leaking. The default resolver
    (normally /etc/resolv.conf - often a local stub the proxy can't reach) is
    swapped for `dns_server`, queried through the tunnel.

State is process-global on purpose ("all requests"); `configure(None)`
restores the environment the process started with.
"""

from __future__ import annotations

import errno
import logging
import os
import socket
import threading
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit

import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import requests
import socks

logger = logging.getLogger(__name__)

DEFAULT_DNS_SERVER = "1.1.1.1"
CONNECT_TIMEOUT_SECONDS = 10
_ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
_NO_PROXY_KEYS = ("NO_PROXY", "no_proxy")


class ProxyUnavailableError(Exception):
    """A proxy is configured but can't be reached - the scan must not run
    (running would either fail everywhere or, worse, look like "no results")."""


@dataclass(frozen=True)
class ProxySettings:
    host: str
    port: int
    username: str | None = None
    password: str | None = None
    dns_server: str = DEFAULT_DNS_SERVER

    def url(self, scheme: str = "socks5h") -> str:
        auth = ""
        if self.username:
            auth = quote(self.username, safe="")
            if self.password:
                auth += ":" + quote(self.password, safe="")
            auth += "@"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{scheme}://{auth}{host}:{self.port}"


def parse_proxy_url(raw: str, dns_server: str | None = None) -> ProxySettings:
    """`socks5://` or `socks5h://` (or a bare host:port), optionally with
    user:pass@. Both schemes are treated as socks5h - hostnames always
    resolve at the proxy, never locally. Raises ValueError on anything else."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "socks5h://" + raw
    parts = urlsplit(raw)
    if parts.scheme.lower() not in ("socks5", "socks5h"):
        raise ValueError(f"unsupported proxy scheme {parts.scheme!r} - use socks5:// or socks5h://")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid proxy port: {exc}") from exc
    if not parts.hostname or port is None:
        raise ValueError("proxy needs a host and a port, e.g. socks5h://127.0.0.1:9050")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("proxy URL must not have a path, query or fragment")
    return ProxySettings(
        host=parts.hostname,
        port=port,
        username=unquote(parts.username) if parts.username else None,
        password=unquote(parts.password) if parts.password else None,
        dns_server=(dns_server or "").strip() or DEFAULT_DNS_SERVER,
    )


_lock = threading.Lock()
_active: ProxySettings | None = None
_saved_env: dict[str, str | None] | None = None


def active() -> ProxySettings | None:
    return _active


def configure(url: str | None, dns_server: str | None = None) -> ProxySettings | None:
    """Route everything through `url` (None/empty turns the proxy off).
    Raises ValueError on a malformed URL - before changing anything."""
    global _active, _saved_env
    settings = parse_proxy_url(url, dns_server) if url and url.strip() else None
    with _lock:
        if settings == _active:
            return settings
        if _saved_env is None:
            _saved_env = {k: os.environ.get(k) for k in (*_ENV_KEYS, *_NO_PROXY_KEYS)}
        if settings is None:
            for key, value in _saved_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            dns.resolver.default_resolver = None  # rebuilt from resolv.conf on next use
        else:
            for key in _ENV_KEYS:
                os.environ[key] = settings.url()
            for key in _NO_PROXY_KEYS:
                os.environ.pop(key, None)
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [settings.dns_server]
            dns.resolver.default_resolver = resolver
        _active = settings
    if settings is not None:
        logger.info("routing all scan traffic through SOCKS5 proxy %s:%s", settings.host, settings.port)
    return settings


def check_reachable(
    settings: ProxySettings | None = None, timeout: float = CONNECT_TIMEOUT_SECONDS
) -> None:
    """Raise ProxyUnavailableError unless `settings` (default: the active
    proxy) accepts a TCP connection. A no-op with no proxy."""
    settings = settings or _active
    if settings is None:
        return
    try:
        socket.create_connection((settings.host, settings.port), timeout=timeout).close()
    except OSError as exc:
        raise ProxyUnavailableError(
            f"proxy {settings.host}:{settings.port} unreachable ({exc}) - "
            "refusing to scan without it (change it on the Settings page)"
        ) from exc


TEST_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
TEST_DNS_NAME = "cloudflare.com"


@dataclass(frozen=True)
class ProxyCheck:
    name: str
    ok: bool
    detail: str


def verify_proxy(
    settings: ProxySettings, timeout: float = CONNECT_TIMEOUT_SECONDS, dns_port: int = 53
) -> list[ProxyCheck]:
    """Exercise `settings` end to end without activating it: TCP reach, an
    HTTPS request through it (reporting the exit IP), and a DNS query over
    TCP through it to `settings.dns_server`. Later checks are skipped when
    the proxy can't be reached at all."""
    try:
        check_reachable(settings, timeout)
    except ProxyUnavailableError as exc:
        return [ProxyCheck("Proxy reachable", False, str(exc.__cause__ or exc))]
    checks = [ProxyCheck("Proxy reachable", True, f"{settings.host}:{settings.port} accepts connections")]

    session = requests.Session()
    session.trust_env = False  # only the proxy under test, never env/NO_PROXY
    try:
        response = session.get(
            TEST_TRACE_URL, proxies={"http": settings.url(), "https": settings.url()},
            timeout=timeout,
        )
        response.raise_for_status()
        fields = dict(line.split("=", 1) for line in response.text.splitlines() if "=" in line)
        checks.append(ProxyCheck("HTTPS through proxy", True,
                                 f"exit IP {fields.get('ip', '?')} ({fields.get('loc', '?')})"))
    except requests.RequestException as exc:
        checks.append(ProxyCheck("HTTPS through proxy", False, str(exc)))
    finally:
        session.close()

    try:
        sock = socks.create_connection(
            (settings.dns_server, dns_port), timeout=timeout, proxy_type=socks.SOCKS5,
            proxy_addr=settings.host, proxy_port=settings.port, proxy_rdns=True,
            proxy_username=settings.username, proxy_password=settings.password,
        )
        with sock:
            sock.setblocking(False)  # dnspython wants a non-blocking connected socket
            query = dns.message.make_query(TEST_DNS_NAME, "A")
            answer = _plain_tcp(query, settings.dns_server, timeout=timeout, sock=sock)
        addresses = [str(r) for rrset in answer.answer for r in rrset if r.rdtype == dns.rdatatype.A]
        checks.append(ProxyCheck(
            f"DNS via {settings.dns_server} through proxy", bool(addresses),
            f"{TEST_DNS_NAME} -> {', '.join(addresses)}" if addresses else "no A records returned",
        ))
    except (OSError, dns.exception.DNSException) as exc:
        checks.append(ProxyCheck(f"DNS via {settings.dns_server} through proxy", False, str(exc)))
    return checks


def tool_proxy_url() -> str | None:
    """The proxy URL for a binary's own `-proxy` flag (Go tools take plain
    socks5://, and still send hostnames to the proxy), or None."""
    return _active.url("socks5") if _active else None


def unavailable_reason(what: str) -> str | None:
    """Why `what` (a tool that can't be tunnelled) must be skipped, or None
    when no proxy is set and it may run."""
    if _active is None:
        return None
    return f"{what} skipped: it can't be routed through the configured SOCKS5 proxy"


def create_connection(address: tuple[str, int], timeout: float | None = None) -> socket.socket:
    """socket.create_connection, through the proxy when one is set."""
    settings = _active
    if settings is None:
        return socket.create_connection(address, timeout=timeout)
    host, port = address[0].strip("[]"), address[1]
    return socks.create_connection(
        (host, port),
        timeout=timeout,
        proxy_type=socks.SOCKS5,
        proxy_addr=settings.host,
        proxy_port=settings.port,
        proxy_rdns=True,
        proxy_username=settings.username,
        proxy_password=settings.password,
    )


# -- dnspython hooks ---------------------------------------------------------
# Installed once at import; each checks `_active` so they're inert (plain
# dnspython behaviour) while no proxy is configured.


class _TunnelSocket(socks.socksocket):
    """A socket dnspython can drive through the proxy. dnspython makes every
    socket non-blocking before connecting, but the SOCKS handshake has to
    block - so connecting blocks (with a timeout) and the non-blocking mode
    is applied afterwards."""

    def __init__(self, settings: ProxySettings) -> None:
        family = socket.AF_INET6 if ":" in settings.host else socket.AF_INET
        super().__init__(family, socket.SOCK_STREAM)
        self.set_proxy(socks.SOCKS5, settings.host, settings.port, True,
                       settings.username, settings.password)
        self._nonblocking = False
        self._tunnel_up = False

    def setblocking(self, flag: bool) -> None:
        self._nonblocking = not flag
        if self._tunnel_up:
            super().setblocking(flag)

    def connect_ex(self, address) -> int:  # type: ignore[override]
        self.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            # PySocks wants a 2-tuple (an IPv6 sockaddr has 4 fields).
            self.connect((address[0], address[1]))
        except OSError as exc:
            return exc.errno or errno.ECONNREFUSED
        self._tunnel_up = True
        if self._nonblocking:
            super().setblocking(False)
        return 0


_plain_socket_factory = dns.query.socket_factory
_plain_udp = dns.query.udp
_plain_tcp = dns.query.tcp


def _socket_factory(af, kind, proto):
    settings = _active
    if settings is None:
        return _plain_socket_factory(af, kind, proto)
    if kind != socket.SOCK_STREAM:
        # Fail closed: a UDP query would bypass the proxy.
        raise OSError(errno.EPERM, "UDP DNS is disabled while a SOCKS5 proxy is configured")
    return _TunnelSocket(settings)


def _udp(q, where, timeout=None, port=53, source=None, source_port=0, *args, **kwargs):
    if _active is None:
        return _plain_udp(q, where, timeout, port, source, source_port, *args, **kwargs)
    return _plain_tcp(
        q, where, timeout=timeout, port=port, source=source, source_port=source_port,
        one_rr_per_rrset=kwargs.get("one_rr_per_rrset", False),
        ignore_trailing=kwargs.get("ignore_trailing", False),
    )


dns.query.socket_factory = _socket_factory
dns.query.udp = _udp
