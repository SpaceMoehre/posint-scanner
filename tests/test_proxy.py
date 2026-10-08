import os
import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import dns.message
import dns.query
import dns.rrset
import dns.resolver
import pytest
import requests

from posint_scanner import proxy
from posint_scanner.db import Database
from posint_scanner.nuclei import NucleiScanner
from posint_scanner.settings import AppSettings, apply_settings, load_settings, save_settings
from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.ping import PingSource
from posint_scanner.sources.portscan import probe_port
from posint_scanner.sources.subfinder import SubfinderSource
from posint_scanner.sources.theharvester import TheHarvesterSource
from posint_scanner.webscan import NiktoScanner, TakeoverScanner, WpscanScanner


@pytest.fixture(autouse=True)
def no_proxy_after():
    yield
    proxy.configure(None)


# -- a minimal no-auth SOCKS5 server (CONNECT only) that records targets ----


class _Socks5Handler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        n_methods = conn.recv(2)[1]
        conn.recv(n_methods)
        conn.sendall(b"\x05\x00")
        _, cmd, _, atyp = conn.recv(4)
        if atyp == 1:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            host = conn.recv(conn.recv(1)[0]).decode()
        else:
            host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        port = struct.unpack(">H", conn.recv(2))[0]
        self.server.targets.append((host, port))
        try:
            upstream = socket.create_connection((host, port), timeout=5)
        except OSError:
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)  # connection refused
            return
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        threading.Thread(target=self._pipe, args=(upstream, conn), daemon=True).start()
        self._pipe(conn, upstream)

    @staticmethod
    def _pipe(src, dst):
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


class _Socks5Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Socks5Handler)
        self.targets = []


@pytest.fixture
def socks_server():
    server = _Socks5Server()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def http_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"hello via proxy\nip=203.0.113.9\nloc=DE")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()


@pytest.fixture
def tcp_dns_server():
    """Answers every A query with 192.0.2.7 - over TCP only."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            length = struct.unpack(">H", self.request.recv(2))[0]
            query = dns.message.from_wire(self.request.recv(length))
            response = dns.message.make_response(query)
            response.answer.append(
                dns.rrset.from_text(query.question[0].name, 60, "IN", "A", "192.0.2.7")
            )
            wire = response.to_wire()
            self.request.sendall(struct.pack(">H", len(wire)) + wire)

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def _use(server):
    host, port = server.server_address
    return proxy.configure(f"socks5://{host}:{port}")


class TestParse:
    def test_socks5_is_normalised_to_remote_dns(self):
        assert proxy.parse_proxy_url("socks5://10.0.0.1:1080").url() == "socks5h://10.0.0.1:1080"

    def test_bare_host_port(self):
        s = proxy.parse_proxy_url("tor:9050")
        assert (s.host, s.port) == ("tor", 9050)

    def test_credentials_round_trip(self):
        s = proxy.parse_proxy_url("socks5h://us%40er:p%3Ass@h:1")
        assert (s.username, s.password) == ("us@er", "p:ss")
        assert s.url() == "socks5h://us%40er:p%3Ass@h:1"

    @pytest.mark.parametrize("raw", ["http://h:3128", "socks5://h", "socks5://:1080", "socks5://h:1/x"])
    def test_rejects(self, raw):
        with pytest.raises(ValueError):
            proxy.parse_proxy_url(raw)


class TestConfigure:
    def test_sets_and_restores_env(self, monkeypatch):
        monkeypatch.setenv("NO_PROXY", "internal")
        monkeypatch.delenv("ALL_PROXY", raising=False)
        proxy._saved_env = None
        proxy.configure("socks5://127.0.0.1:9050")
        assert os.environ["HTTPS_PROXY"] == "socks5h://127.0.0.1:9050"
        assert os.environ["all_proxy"] == "socks5h://127.0.0.1:9050"
        assert "NO_PROXY" not in os.environ
        proxy.configure(None)
        assert os.environ["NO_PROXY"] == "internal"
        assert "ALL_PROXY" not in os.environ

    def test_default_resolver_uses_dns_server(self):
        proxy.configure("127.0.0.1:9050", "9.9.9.9")
        assert dns.resolver.get_default_resolver().nameservers == ["9.9.9.9"]

    def test_bad_url_changes_nothing(self):
        with pytest.raises(ValueError):
            proxy.configure("http://x:1")
        assert proxy.active() is None

    def test_unreachable_proxy_raises(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]  # bound, not listening
        proxy.configure(f"127.0.0.1:{port}")
        with pytest.raises(proxy.ProxyUnavailableError):
            proxy.check_reachable(timeout=1)


class TestTraffic:
    def test_requests_go_through_proxy(self, socks_server, http_server):
        _use(socks_server)
        port = http_server.server_address[1]
        r = requests.get(f"http://localhost:{port}/", timeout=5)
        assert r.text.startswith("hello via proxy")
        # socks5h: the hostname went to the proxy unresolved.
        assert ("localhost", port) in socks_server.targets

    def test_port_scan_goes_through_proxy(self, socks_server, http_server):
        _use(socks_server)
        port = http_server.server_address[1]
        is_open, _ = probe_port("127.0.0.1", port)
        assert is_open
        assert ("127.0.0.1", port) in socks_server.targets

    def test_closed_port_via_proxy_is_closed(self, socks_server):
        _use(socks_server)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        assert probe_port("127.0.0.1", port) == (False, None)

    def test_dns_goes_over_tcp_through_proxy(self, socks_server, tcp_dns_server):
        _use(socks_server)
        dns_port = tcp_dns_server.server_address[1]
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["127.0.0.1"]
        resolver.port = dns_port
        answer = resolver.resolve("host.example.com", "A")
        assert [str(r) for r in answer] == ["192.0.2.7"]
        assert ("127.0.0.1", dns_port) in socks_server.targets

    def test_udp_dns_socket_refused_while_proxied(self):
        proxy.configure("127.0.0.1:9050")
        with pytest.raises(OSError):
            dns.query.socket_factory(socket.AF_INET, socket.SOCK_DGRAM, 0)

    def test_direct_when_no_proxy(self, http_server):
        port = http_server.server_address[1]
        assert requests.get(f"http://127.0.0.1:{port}/", timeout=5).status_code == 200


class TestVerify:
    def test_all_checks_pass_through_a_working_proxy(
        self, socks_server, http_server, tcp_dns_server, monkeypatch
    ):
        http_port = http_server.server_address[1]
        monkeypatch.setattr(proxy, "TEST_TRACE_URL", f"http://localhost:{http_port}/")
        host, port = socks_server.server_address
        settings = proxy.parse_proxy_url(f"{host}:{port}", "127.0.0.1")
        checks = proxy.verify_proxy(settings, timeout=5, dns_port=tcp_dns_server.server_address[1])
        assert [c.ok for c in checks] == [True, True, True], checks
        assert "192.0.2.7" in checks[2].detail
        assert ("localhost", http_port) in socks_server.targets
        assert proxy.active() is None  # testing never activates the proxy

    def test_unreachable_proxy_stops_after_first_check(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        checks = proxy.verify_proxy(proxy.parse_proxy_url(f"127.0.0.1:{port}"), timeout=1)
        assert len(checks) == 1 and not checks[0].ok

    def test_failed_request_is_reported(self, socks_server, monkeypatch):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            dead = s.getsockname()[1]
        monkeypatch.setattr(proxy, "TEST_TRACE_URL", f"http://127.0.0.1:{dead}/")
        host, port = socks_server.server_address
        checks = proxy.verify_proxy(proxy.parse_proxy_url(f"{host}:{port}", "127.0.0.1"),
                                    timeout=2, dns_port=dead)
        assert [c.ok for c in checks] == [True, False, False]


class TestTools:
    def test_untunnellable_sources_skip(self):
        proxy.configure("127.0.0.1:9050")
        with pytest.raises(SourceUnavailableError):
            PingSource().enrich("192.0.2.1", [])
        with pytest.raises(SourceUnavailableError):
            TheHarvesterSource().collect("example.com")

    def test_untunnellable_scanners_skip(self):
        proxy.configure("127.0.0.1:9050")
        with patch("shutil.which", return_value="/bin/x"), patch("subprocess.run") as run:
            assert NiktoScanner().scan(["http://a/"]) == []
            assert TakeoverScanner().scan(["a.example.com"]) == []
        run.assert_not_called()

    def test_tools_get_proxy_flag(self):
        proxy.configure("127.0.0.1:9050")
        with patch("shutil.which", return_value="/bin/x"), patch("subprocess.run") as run:
            run.return_value.stdout = ""
            NucleiScanner().scan(["http://a/"])
            SubfinderSource().discover("example.com")
            WpscanScanner().scan(["http://a/"])
        cmds = [c.args[0] for c in run.call_args_list]
        assert cmds[0][cmds[0].index("-proxy") + 1] == "socks5://127.0.0.1:9050"
        assert cmds[1][cmds[1].index("-proxy") + 1] == "socks5://127.0.0.1:9050"
        assert cmds[2][cmds[2].index("--proxy") + 1] == "socks5h://127.0.0.1:9050"

    def test_no_proxy_flag_without_proxy(self):
        with patch("shutil.which", return_value="/bin/x"), patch("subprocess.run") as run:
            run.return_value.stdout = ""
            NucleiScanner().scan(["http://a/"])
        assert "-proxy" not in run.call_args.args[0]


class TestSettings:
    def test_round_trip_and_apply(self, tmp_path, socks_server):
        host, port = socks_server.server_address
        with Database(tmp_path / "s.db") as db:
            db.init_schema()
            save_settings(db, AppSettings(proxy_url=f"{host}:{port}", proxy_dns_server="8.8.8.8"))
            loaded = load_settings(db)
            assert loaded.proxy_url == f"socks5h://{host}:{port}"
            apply_settings(db)
            assert proxy.active().dns_server == "8.8.8.8"
            save_settings(db, AppSettings())
            assert db.get_settings() == {}
            apply_settings(db)
            assert proxy.active() is None

    @pytest.mark.parametrize("field,value", [("proxy_url", "http://h:1"), ("proxy_dns_server", "dns.google")])
    def test_validation(self, field, value):
        with pytest.raises(ValueError):
            AppSettings(**{field: value})
