import http.server
import socket
import threading

import pytest

from posint_scanner.sources.portscan import (
    PortScanSource,
    parse_banner,
    probe_port,
)


class TestParseBanner:
    def test_parses_ssh_banner(self):
        product, version = parse_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
        assert product == "OpenSSH"
        assert version == "8.9p1"

    def test_parses_http_server_header(self):
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n"
        product, version = parse_banner(80, banner)
        assert product == "nginx"
        assert version == "1.18.0"

    def test_parses_server_header_without_version(self):
        banner = "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n"
        product, version = parse_banner(80, banner)
        assert product == "Apache"
        assert version is None

    def test_parses_ftp_banner(self):
        product, version = parse_banner(21, "220 (vsFTPd 3.0.5)\r\n")
        assert product == "vsFTPd"
        assert version == "3.0.5"

    def test_returns_none_none_for_unrecognized_banner(self):
        product, version = parse_banner(9999, "some random binary garbage\x00\x01")
        assert product is None
        assert version is None

    def test_empty_banner(self):
        assert parse_banner(80, "") == (None, None)


class TestProbePortAgainstRealLocalServer:
    """Real loopback tests rather than mocked sockets - more trustworthy for
    verifying actual socket/banner-read behavior than faithfully mocking the
    socket module would be."""

    @pytest.fixture
    def http_server(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield port
        server.shutdown()
        thread.join(timeout=2)

    def test_detects_open_port_and_grabs_http_banner(self, http_server):
        is_open, banner = probe_port("127.0.0.1", http_server)
        assert is_open is True
        assert banner is not None
        assert "Server" in banner or "HTTP" in banner

    def test_closed_port_is_not_open(self):
        # bind a socket to grab an ephemeral port, then close it so nothing
        # is listening there - almost certainly closed/refused.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        is_open, banner = probe_port("127.0.0.1", port)
        assert is_open is False
        assert banner is None


class TestPortScanSourceEnrich:
    def test_finds_the_open_port_among_common_ports(self, monkeypatch):
        server = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            import posint_scanner.sources.portscan as portscan_module

            monkeypatch.setattr(portscan_module, "COMMON_PORTS", [port, 9], raising=False)

            source = PortScanSource()
            result = source.enrich("127.0.0.1", [])
        finally:
            server.shutdown()
            thread.join(timeout=2)

        assert result.source == "portscan"
        assert result.target_type == "ip"
        found_ports = {s.port for s in result.services}
        assert port in found_ports

    def test_enrich_target_kind_is_ip(self):
        assert PortScanSource.enrich_target_kind == "ip"


def test_probes_share_a_process_wide_cap():
    import threading
    from unittest.mock import patch

    from posint_scanner.sources import portscan

    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_connect(ip, port):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        threading.Event().wait(0.01)
        with lock:
            active -= 1
        return None

    with (
        patch.object(portscan, "_PROBE_SLOTS", threading.BoundedSemaphore(3)),
        patch.object(portscan, "_connect", side_effect=fake_connect),
    ):
        threads = [threading.Thread(target=portscan.PortScanSource().enrich, args=("192.0.2.1", []))
                   for _ in range(3)]
        [t.start() for t in threads]
        [t.join() for t in threads]
    assert 0 < peak <= 3
