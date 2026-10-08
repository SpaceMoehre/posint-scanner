from unittest.mock import patch

import pytest

from posint_scanner.sources.base import SourceUnavailableError
from posint_scanner.sources.subfinder import SubfinderSource, parse_subfinder_output


class TestParseSubfinderOutput:
    def test_parses_one_hostname_per_line(self):
        raw = "api.example.com\nwww.example.com\n"
        result = parse_subfinder_output(raw)
        assert [h.name for h in result] == ["api.example.com", "www.example.com"]

    def test_tags_source_as_subfinder(self):
        result = parse_subfinder_output("api.example.com\n")
        assert result[0].source == "subfinder"

    def test_skips_blank_lines(self):
        raw = "api.example.com\n\n\nwww.example.com\n"
        result = parse_subfinder_output(raw)
        assert len(result) == 2

    def test_lowercases_hostnames(self):
        result = parse_subfinder_output("API.Example.com\n")
        assert result[0].name == "api.example.com"

    def test_empty_output(self):
        assert parse_subfinder_output("") == []


class TestSubfinderSourceDiscover:
    def test_raises_when_binary_missing(self):
        source = SubfinderSource()
        with patch("shutil.which", return_value=None):
            with pytest.raises(SourceUnavailableError):
                source.discover("example.com")

    def test_runs_subfinder_and_parses_stdout(self):
        source = SubfinderSource()
        fake_completed = type(
            "FakeCompleted", (), {"stdout": "api.example.com\n", "returncode": 0}
        )()
        with patch("shutil.which", return_value="/usr/bin/subfinder"):
            with patch("subprocess.run", return_value=fake_completed) as mock_run:
                result = source.discover("example.com")

        assert [h.name for h in result] == ["api.example.com"]
        args = mock_run.call_args[0][0]
        assert args[:2] == ["/usr/bin/subfinder", "-d"]
        assert "example.com" in args
