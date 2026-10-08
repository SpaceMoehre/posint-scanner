from unittest.mock import patch

import pytest

from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.ping import PingSource, parse_ping_output


class TestParsePingOutput:
    def test_alive_extracts_rtt(self):
        stdout = (
            "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
            "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.051 ms\n"
        )
        result = parse_ping_output(returncode=0, stdout=stdout)
        assert result == {"alive": True, "rtt_ms": 0.051}

    def test_unreachable_returncode_marks_not_alive(self):
        stdout = (
            "PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.\n"
            "\n--- 192.0.2.1 ping statistics ---\n"
            "1 packets transmitted, 0 received, 100% packet loss, time 0ms\n"
        )
        result = parse_ping_output(returncode=1, stdout=stdout)
        assert result == {"alive": False, "rtt_ms": None}

    def test_alive_with_larger_rtt(self):
        stdout = "64 bytes from 1.2.3.4: icmp_seq=1 ttl=54 time=123.4 ms\n"
        result = parse_ping_output(returncode=0, stdout=stdout)
        assert result == {"alive": True, "rtt_ms": 123.4}


class TestPingSourceEnrich:
    def test_raises_source_unavailable_when_binary_missing(self):
        source = PingSource()
        with patch("shutil.which", return_value=None):
            with pytest.raises(SourceUnavailableError):
                source.enrich("1.2.3.4", [])

    def test_runs_ping_and_returns_result(self):
        source = PingSource()
        fake_completed = type(
            "FakeCompleted",
            (),
            {"returncode": 0, "stdout": "64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=5.0 ms\n"},
        )()
        with patch("shutil.which", return_value="/usr/bin/ping"):
            with patch("subprocess.run", return_value=fake_completed) as mock_run:
                result = source.enrich("1.2.3.4", [])

        assert result.source == "ping"
        assert result.target_type == "ip"
        assert result.target == "1.2.3.4"
        assert result.data == {"alive": True, "rtt_ms": 5.0}
        args = mock_run.call_args[0][0]
        assert args[0] == "/usr/bin/ping"
        assert "1.2.3.4" in args

    def test_enrich_target_kind_is_ip(self):
        assert PingSource.enrich_target_kind == "ip"
