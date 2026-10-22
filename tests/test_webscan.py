import json
from pathlib import Path
from unittest.mock import patch

from posint_scanner import proxy, toolrun
from posint_scanner.webscan import (
    NiktoScanner,
    Php2ShellScanner,
    TakeoverScanner,
    WpscanScanner,
    parse_nikto,
    parse_phpcheck,
    parse_takeover,
    parse_wpscan,
)

NIKTO_OUTPUT = [
    {
        "host": "example.com",
        "port": "443",
        "vulnerabilities": [
            {
                "id": "999957",
                "method": "GET",
                "url": "/",
                "msg": "The anti-clickjacking X-Frame-Options header is not present.",
                "references": "",
            },
            {
                "id": "600123",
                "method": "GET",
                "url": "/cgi-bin/status",
                "msg": "Vulnerable to CVE-2014-6271 (Shellshock).",
                "references": "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
            },
        ],
    }
]

WPSCAN_OUTPUT = {
    "version": {
        "number": "5.4.1",
        "vulnerabilities": [
            {
                "title": "WordPress 5.4 - Cross-Site Scripting",
                "fixed_in": "5.4.2",
                "references": {"cve": ["2020-11026"], "url": ["https://wpvulndb.com/x"]},
            }
        ],
    },
    "plugins": {
        "contact-form-7": {
            "version": {"number": "5.1.6"},
            "vulnerabilities": [
                {
                    "title": "Contact Form 7 - Unrestricted File Upload",
                    "references": {"cve": ["CVE-2020-35489"], "wpvulndb": ["10247"]},
                }
            ],
        }
    },
    "interesting_findings": [
        {"type": "headers", "to_s": "Headers", "url": "https://example.com/"}
    ],
}

TAKEOVER_OUTPUT = {
    "domains": {
        "assets.example.com": {"service": "github",
                               "error": "There isn't a GitHub Pages site here."},
    },
}


class TestParseNikto:
    def test_extracts_findings_and_cves(self):
        findings = parse_nikto(json.dumps(NIKTO_OUTPUT), "https://example.com:443/")
        assert len(findings) == 2
        clickjack, shellshock = findings
        assert clickjack["severity"] == "low"  # no CVE
        assert clickjack["tool"] == "nikto"
        assert clickjack["location"] == "GET /"
        assert shellshock["severity"] == "medium"  # CVE bumps it
        assert shellshock["cves"] == ["CVE-2014-6271"]

    def test_single_host_object(self):
        findings = parse_nikto(json.dumps(NIKTO_OUTPUT[0]), "https://example.com/")
        assert len(findings) == 2

    def test_malformed_is_empty(self):
        assert parse_nikto("not json", "x") == []
        assert parse_nikto("{}", "x") == []


class TestParseWpscan:
    def test_core_plugin_and_interesting(self):
        findings = parse_wpscan(json.dumps(WPSCAN_OUTPUT), "https://example.com/")
        by_kind = {f["kind"] for f in findings}
        assert by_kind == {"vulnerability", "info"}
        core = next(f for f in findings if "core" in f["resource"])
        assert core["cves"] == ["CVE-2020-11026"]  # bare number qualified
        assert core["severity"] == "high"
        assert "fixed in 5.4.2" == core["location"]
        plugin = next(f for f in findings if "contact-form-7" in f["resource"])
        assert plugin["cves"] == ["CVE-2020-35489"]

    def test_scan_aborted_is_empty(self):
        assert parse_wpscan(json.dumps({"scan_aborted": "not WordPress"}), "x") == []

    def test_malformed_is_empty(self):
        assert parse_wpscan("<html>", "x") == []


class TestParseTakeover:
    def test_report_entries(self):
        findings = parse_takeover(json.dumps(TAKEOVER_OUTPUT))
        assert len(findings) == 1
        f = findings[0]
        assert f["tool"] == "takeover"
        assert f["severity"] == "high"
        assert f["resource"] == "assets.example.com"
        assert f["id"] == "github"

    def test_several_hosts(self):
        report = {"domains": {"a.example.com": {"service": "heroku"},
                              "b.example.com": {"service": "github"}}}
        assert [f["resource"] for f in parse_takeover(json.dumps(report))] == [
            "a.example.com", "b.example.com"]

    def test_empty_or_malformed(self):
        assert parse_takeover('{"domains": {}}') == []
        assert parse_takeover("") == []
        assert parse_takeover("[1, 2]") == []


class TestScannersAbsent:
    def test_nikto_absent(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: None)
        s = NiktoScanner()
        assert s.available is False
        assert s.scan(["https://h/"]) == []

    def test_wpscan_absent(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: None)
        assert WpscanScanner().scan(["https://h/"]) == []

    def test_takeover_absent(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: None)
        assert TakeoverScanner().scan(["h"]) == []


class TestScannerRuns:
    def test_nikto_reads_output_file(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: "/usr/bin/nikto")

        def fake_run(cmd, **kwargs):
            out = Path(cmd[cmd.index("-output") + 1])
            out.write_text(json.dumps(NIKTO_OUTPUT))

            class Done:
                stdout = ""
                returncode = 0

            return Done()

        with patch("posint_scanner.toolrun.run_tool", side_effect=fake_run):
            findings = NiktoScanner().scan(["https://example.com:443/"])
        assert len(findings) == 2

    def test_wpscan_passes_token_and_parses(self, monkeypatch, wpscan_db):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: "/usr/bin/wpscan")
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd

            class Done:
                stdout = json.dumps(WPSCAN_OUTPUT)
                returncode = 1  # wpscan exits non-zero on findings

            return Done()

        with patch("posint_scanner.toolrun.run_tool", side_effect=fake_run):
            findings = WpscanScanner(api_token="TOK").scan(["https://example.com/"])
        assert findings  # parsed despite non-zero exit
        assert "--api-token" in captured["cmd"]
        assert "TOK" in captured["cmd"]

    def test_takeover_writes_list_and_parses(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: "/usr/bin/takeover")
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            list_file = Path(cmd[cmd.index("-l") + 1])
            captured["hosts"] = list_file.read_text().splitlines()
            Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(TAKEOVER_OUTPUT))

            class Done:
                stdout = ""
                returncode = 0

            return Done()

        with patch("posint_scanner.toolrun.run_tool", side_effect=fake_run):
            findings = TakeoverScanner().scan(["assets.example.com", "assets.example.com", ""])
        assert len(findings) == 1
        assert captured["hosts"] == ["assets.example.com"]  # deduped, blank dropped
        assert captured["cmd"][captured["cmd"].index("-o") + 1].endswith(".json")


def _phpcheck_json(status, version, code):
    return json.dumps({"patch_status": status, "php_version": version,
                       "reason": f"PHP {version}" if version else "PHP version not found",
                       "exit_code": code}) + "\n"


class TestParsePhpcheck:
    def test_vulnerable_is_critical(self):
        f = parse_phpcheck(_phpcheck_json("vulnerable", "8.4.26-1ubuntu1", 1), "https://a/")
        assert (f["tool"], f["severity"], f["patch_status"]) == ("php2shell", "critical", "vulnerable")
        assert f["php_version"] == "8.4.26-1ubuntu1"
        assert f["url"] == "https://a/"

    def test_ok_and_unknown_with_a_version_are_kept_as_info(self):
        assert parse_phpcheck(_phpcheck_json("ok", "8.4.27", 0), "u")["severity"] == "info"
        unknown = parse_phpcheck(_phpcheck_json("unknown", "9.0.0", 3), "u")
        assert (unknown["severity"], unknown["php_version"]) == ("unknown", "9.0.0")

    def test_no_version_or_garbage_is_nothing(self):
        assert parse_phpcheck(_phpcheck_json("unknown", None, 3), "u") is None
        assert parse_phpcheck("", "u") is None
        assert parse_phpcheck("Provide a URL or --local", "u") is None


class TestPhp2ShellScanner:
    def test_runs_per_url_and_stores_the_report(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: "/usr/bin/phpcheck")
        calls, stored = [], {}

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))

            class Done:
                returncode = 1
                stdout = _phpcheck_json("vulnerable", "8.4.26", 1)
                stderr = ""

            return Done()

        with patch("posint_scanner.toolrun.run_tool", side_effect=fake_run):
            findings = Php2ShellScanner().scan(
                ["https://a/", "https://a/", "http://b:8080/"],
                report=lambda target, rep: stored.__setitem__(target, rep),
            )
        assert [c[0][1] for c in calls] == ["https://a/", "http://b:8080/"]  # deduped
        assert "--json" in calls[0][0]
        assert calls[0][1]["env"] == {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}  # TLS not validated
        assert len(findings) == 2
        assert json.loads(toolrun.decompress(stored["https://a/"].data))["php_version"] == "8.4.26"

    def test_absent_or_proxied_is_skipped(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: None)
        assert Php2ShellScanner().scan(["https://a/"]) == []
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: "/usr/bin/phpcheck")
        proxy.configure("127.0.0.1:9050")
        try:
            with patch("posint_scanner.toolrun.run_tool") as run:
                assert Php2ShellScanner().scan(["https://a/"]) == []
            run.assert_not_called()
        finally:
            proxy.configure(None)
