import json
from unittest.mock import patch

from posint_scanner.nuclei import NucleiScanner, parse_nuclei_line

FINDING = {
    "template-id": "CVE-2024-36401",
    "info": {
        "name": "GeoServer OGC Filter Evaluation RCE",
        "severity": "critical",
        "tags": ["cve", "rce", "geoserver"],
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2024-36401"],
        "classification": {"cve-id": ["CVE-2024-36401"], "cvss-score": 9.8},
    },
    "type": "http",
    "host": "http://geo.dns-net.de:8080",
    "matched-at": "http://geo.dns-net.de:8080/geoserver/ows",
}


class TestParse:
    def test_extracts_core_fields(self):
        f = parse_nuclei_line(json.dumps(FINDING))
        assert f == {
            "template_id": "CVE-2024-36401",
            "name": "GeoServer OGC Filter Evaluation RCE",
            "severity": "critical",
            "matched_at": "http://geo.dns-net.de:8080/geoserver/ows",
            "type": "http",
            "cves": ["CVE-2024-36401"],
            "cvss_score": 9.8,
            "tags": ["cve", "rce", "geoserver"],
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2024-36401"],
        }

    def test_minimal_finding_without_classification(self):
        line = json.dumps({"template-id": "tech-detect", "info": {"name": "X", "severity": "info"},
                           "matched-at": "http://h/"})
        f = parse_nuclei_line(line)
        assert f["template_id"] == "tech-detect"
        assert f["cves"] == []
        assert f["cvss_score"] is None

    def test_blank_and_malformed_lines_are_none(self):
        assert parse_nuclei_line("") is None
        assert parse_nuclei_line("  ") is None
        assert parse_nuclei_line("not json {") is None

    def test_line_without_template_id_is_none(self):
        assert parse_nuclei_line('{"info": {"name": "x"}}') is None


class TestScanner:
    def test_unavailable_without_binary(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.nuclei.shutil.which", lambda _: None)
        s = NucleiScanner()
        assert s.available is False
        assert s.scan(["http://h/"]) == []

    def test_no_targets_no_run(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.nuclei.shutil.which", lambda _: "/usr/bin/nuclei")
        with patch("posint_scanner.nuclei.subprocess.run") as run:
            assert NucleiScanner().scan([]) == []
        run.assert_not_called()

    def test_runs_and_parses_jsonl(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.nuclei.shutil.which", lambda _: "/usr/bin/nuclei")
        out = "\n".join([json.dumps(FINDING), "", "garbage", json.dumps(
            {"template-id": "ssl-dns-names", "info": {"name": "SSL", "severity": "info"},
             "matched-at": "http://h/"})])

        class Done:
            stdout = out
            returncode = 0

        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return Done()

        with patch("posint_scanner.nuclei.subprocess.run", side_effect=fake_run):
            findings = NucleiScanner().scan(["http://geo.dns-net.de:8080/geoserver/web/"])

        assert [f["template_id"] for f in findings] == ["CVE-2024-36401", "ssl-dns-names"]
        # runs headless/jsonl and never tries to self-update mid-scan
        assert "-jsonl" in captured["cmd"]
        assert "-disable-update-check" in captured["cmd"]

    def test_custom_templates_dir_is_passed(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.nuclei.shutil.which", lambda _: "/usr/bin/nuclei")

        class Done:
            stdout = ""
            returncode = 0

        captured = {}

        def fake_run(cmd, **k):
            captured["cmd"] = cmd
            return Done()

        with patch("posint_scanner.nuclei.subprocess.run", side_effect=fake_run):
            NucleiScanner(templates_dir="/data/nuclei-templates").scan(["http://h/"])
        assert "-t" in captured["cmd"]
        assert "/data/nuclei-templates" in captured["cmd"]

    def test_subprocess_failure_is_swallowed(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.nuclei.shutil.which", lambda _: "/usr/bin/nuclei")
        with patch("posint_scanner.nuclei.subprocess.run", side_effect=OSError("boom")):
            assert NucleiScanner().scan(["http://h/"]) == []
