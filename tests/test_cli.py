from unittest.mock import patch

from typer.testing import CliRunner

from posint_scanner.cli import app
from posint_scanner.models import DiscoveredHostname
from posint_scanner.sources.base import Source

runner = CliRunner()


class FakeDiscoverySource(Source):
    name = "fake-discovery"

    def discover(self, domain):
        return [DiscoveredHostname(name=f"api.{domain}", source=self.name)]


class TestDbInit:
    def test_creates_database_file(self, tmp_path):
        db_path = tmp_path / "test.db"
        result = runner.invoke(app, ["db", "init", "--db", str(db_path)])
        assert result.exit_code == 0
        assert db_path.exists()


class TestScanCommand:
    def test_errors_without_domain_or_file(self, tmp_path):
        db_path = tmp_path / "test.db"
        result = runner.invoke(app, ["scan", "--db", str(db_path)])
        assert result.exit_code == 1
        assert "provide a domain" in result.output

    def test_scan_then_query_roundtrip(self, tmp_path):
        db_path = tmp_path / "test.db"
        config_path = tmp_path / "config.yaml"
        config_path.write_text("shodan:\n  api_key: null\n")

        with patch(
            "posint_scanner.cli.build_sources", return_value=[FakeDiscoverySource()]
        ):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--db",
                    str(db_path),
                    "--config",
                    str(config_path),
                    "--report-output",
                    str(tmp_path / "vault"),
                ],
            )
        assert result.exit_code == 0, result.output

        query_result = runner.invoke(app, ["query", "--host", "api.example.com", "--db", str(db_path)])
        assert query_result.exit_code == 0
        assert "api.example.com" in query_result.output

    def test_scan_exports_markdown_report_with_report_flag(self, tmp_path):
        db_path = tmp_path / "test.db"
        report_dir = tmp_path / "vault"

        with patch("posint_scanner.cli.build_sources", return_value=[FakeDiscoverySource()]):
            result = runner.invoke(
                app,
                ["scan", "example.com", "--db", str(db_path), "--report-output", str(report_dir), "--report"],
            )

        assert result.exit_code == 0, result.output
        assert "markdown report exported" in result.output
        assert (report_dir / "Domains" / "example.com.md").exists()
        assert (report_dir / "Hosts" / "api.example.com.md").exists()

    def test_scan_skips_export_by_default(self, tmp_path):
        db_path = tmp_path / "test.db"
        report_dir = tmp_path / "vault"

        with patch("posint_scanner.cli.build_sources", return_value=[FakeDiscoverySource()]):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "example.com",
                    "--db",
                    str(db_path),
                    "--report-output",
                    str(report_dir),
                ],
            )

        assert result.exit_code == 0, result.output
        assert "markdown report exported" not in result.output
        assert not report_dir.exists()

    def test_no_netblock_sweep_flag_disables_sweep(self, tmp_path):
        db_path = tmp_path / "test.db"

        with patch("posint_scanner.cli.build_sources", return_value=[FakeDiscoverySource()]):
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                result = runner.invoke(
                    app,
                    [
                        "scan",
                        "example.com",
                        "--db",
                        str(db_path),
                        "--no-netblock-sweep",
                    ],
                )

        assert result.exit_code == 0, result.output
        assert mock_run_scan.call_args.kwargs["netblock_sweep"] is False


class TestExportCommand:
    def test_unknown_format_errors(self, tmp_path):
        db_path = tmp_path / "test.db"
        runner.invoke(app, ["db", "init", "--db", str(db_path)])
        result = runner.invoke(
            app, ["export", "--format", "yaml", "--output", str(tmp_path / "out"), "--db", str(db_path)]
        )
        assert result.exit_code == 1
        assert "unknown format" in result.output

    def test_json_export_writes_file(self, tmp_path):
        db_path = tmp_path / "test.db"
        runner.invoke(app, ["db", "init", "--db", str(db_path)])
        output_path = tmp_path / "out.json"
        result = runner.invoke(
            app, ["export", "--format", "json", "--output", str(output_path), "--db", str(db_path)]
        )
        assert result.exit_code == 0
        assert output_path.exists()


class TestQueryCommand:
    def test_unknown_host_returns_exit_code_1(self, tmp_path):
        db_path = tmp_path / "test.db"
        runner.invoke(app, ["db", "init", "--db", str(db_path)])
        result = runner.invoke(app, ["query", "--host", "nope.example.com", "--db", str(db_path)])
        assert result.exit_code == 1

    def test_shows_ip_level_results_like_ping_status(self, tmp_path):
        from posint_scanner.db import Database

        db_path = tmp_path / "test.db"
        with Database(db_path) as db:
            db.init_schema()
            domain_id = db.upsert_domain("example.com")
            hostname_id = db.upsert_hostname(domain_id, "api.example.com")
            ip_id = db.upsert_ip("1.2.3.4")
            db.upsert_resolution(hostname_id, ip_id)
            db.insert_result("ping", "ip", ip_id, {"alive": True, "rtt_ms": 5.0})

        result = runner.invoke(app, ["query", "--host", "api.example.com", "--db", str(db_path)])
        assert result.exit_code == 0
        assert "ping" in result.output
        assert "alive" in result.output

    def test_shows_service_version(self, tmp_path):
        from posint_scanner.db import Database

        db_path = tmp_path / "test.db"
        with Database(db_path) as db:
            db.init_schema()
            domain_id = db.upsert_domain("example.com")
            hostname_id = db.upsert_hostname(domain_id, "api.example.com")
            ip_id = db.upsert_ip("1.2.3.4")
            db.upsert_resolution(hostname_id, ip_id)
            db.upsert_service(ip_id, 443, "tcp", "nginx", "1.18.0")

        result = runner.invoke(app, ["query", "--host", "api.example.com", "--db", str(db_path)])
        assert result.exit_code == 0
        assert "nginx 1.18.0" in result.output


def scan_with_real_registry(tmp_path, *flags, config_text=""):
    """Run `scan` through the real registry with run_scan mocked out; return
    (names of the sources that would run, run_scan kwargs, CLI result)."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(config_text)
    with patch("posint_scanner.cli.run_scan") as mock_run_scan:
        result = runner.invoke(
            app,
            [
                "scan",
                "example.com",
                "--db",
                str(tmp_path / "test.db"),
                "--config",
                str(config_path),
                *flags,
            ],
        )
    if not mock_run_scan.called:
        return None, None, result
    sources = mock_run_scan.call_args.args[2]
    return {s.name for s in sources}, mock_run_scan.call_args.kwargs, result


class TestSourceSelectionFlags:
    def test_defaults(self, tmp_path):
        names, kwargs, _ = scan_with_real_registry(tmp_path)
        assert {"ping", "portscan", "crtsh", "shodan"} <= names
        assert "shodan_web" not in names
        assert kwargs["tech_fingerprint"] is True
        assert kwargs["fresh"] is False

    def test_source_flag_enables_opt_in_source(self, tmp_path):
        names, _, _ = scan_with_real_registry(tmp_path, "--source", "shodan_web")
        assert "shodan_web" in names

    def test_no_source_flag_is_repeatable(self, tmp_path):
        names, _, _ = scan_with_real_registry(
            tmp_path, "--no-source", "ping", "--no-source", "crtsh"
        )
        assert "ping" not in names
        assert "crtsh" not in names
        assert "portscan" in names

    def test_unknown_source_name_errors(self, tmp_path):
        names, _, result = scan_with_real_registry(tmp_path, "--source", "nope")
        assert names is None
        assert result.exit_code == 1
        assert "unknown source" in result.output

    def test_no_active_disables_active_sources_and_fingerprint(self, tmp_path):
        names, kwargs, _ = scan_with_real_registry(tmp_path, "--no-active")
        assert "ping" not in names
        assert "portscan" not in names
        assert "shodan" in names
        assert kwargs["tech_fingerprint"] is False

    def test_explicit_fingerprint_wins_over_no_active(self, tmp_path):
        _, kwargs, _ = scan_with_real_registry(tmp_path, "--no-active", "--fingerprint")
        assert kwargs["tech_fingerprint"] is True

    def test_config_active_default_off_disables_fingerprint(self, tmp_path):
        names, kwargs, _ = scan_with_real_registry(
            tmp_path, config_text="defaults:\n  active: false\n"
        )
        assert "ping" not in names
        assert kwargs["tech_fingerprint"] is False

    def test_config_enables_source(self, tmp_path):
        names, _, _ = scan_with_real_registry(
            tmp_path, config_text="sources:\n  shodan_web:\n    enabled: true\n"
        )
        assert "shodan_web" in names

    def test_fresh_flag(self, tmp_path):
        _, kwargs, _ = scan_with_real_registry(tmp_path, "--fresh")
        assert kwargs["fresh"] is True

    def test_authorize_scans_reaches_vmdr(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text("qualys_vmdr:\n  api_user: \"test\"\n  api_password: \"test\"\n")
        with patch("posint_scanner.cli.run_scan") as mock_run_scan:
            runner.invoke(
                app,
                ["scan", "example.com", "--db", str(tmp_path / "t.db"),
                 "--config", str(config_path), "--authorize-scans"],
            )
        vmdr = next(s for s in mock_run_scan.call_args.args[2] if s.name == "qualys_vmdr")
        assert vmdr.authorize_scans is True


class TestDeprecatedSourceFlags:
    def test_no_ping(self, tmp_path):
        names, _, _ = scan_with_real_registry(tmp_path, "--no-ping")
        assert "ping" not in names

    def test_ping_forces_it_on_despite_no_active(self, tmp_path):
        names, _, _ = scan_with_real_registry(tmp_path, "--no-active", "--ping")
        assert "ping" in names

    def test_no_scan_ports(self, tmp_path):
        names, _, _ = scan_with_real_registry(tmp_path, "--no-scan-ports")
        assert "portscan" not in names

    def test_shodan_web(self, tmp_path):
        names, _, _ = scan_with_real_registry(tmp_path, "--shodan-web")
        assert "shodan_web" in names


class TestFingerprintFlag:
    def test_no_fingerprint_flag_disables_it(self, tmp_path):
        _, kwargs, _ = scan_with_real_registry(tmp_path, "--no-fingerprint")
        assert kwargs["tech_fingerprint"] is False


class TestVulnLookupFlag:
    def test_no_vuln_lookup_flag_disables_lookup(self, tmp_path):
        db_path = tmp_path / "test.db"
        with patch("posint_scanner.cli.build_sources") as mock_build_sources:
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                mock_build_sources.return_value = [FakeDiscoverySource()]
                runner.invoke(
                    app,
                    ["scan", "example.com", "--db", str(db_path), "--no-vuln-lookup"],
                )
        assert mock_run_scan.call_args.kwargs["vuln_lookup"] is False

    def test_vuln_lookup_defaults_true(self, tmp_path):
        db_path = tmp_path / "test.db"
        with patch("posint_scanner.cli.build_sources") as mock_build_sources:
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                mock_build_sources.return_value = [FakeDiscoverySource()]
                runner.invoke(app, ["scan", "example.com", "--db", str(db_path)])
        assert mock_run_scan.call_args.kwargs["vuln_lookup"] is True


class TestConcurrencyFlags:
    def test_workers_flag_is_threaded_through(self, tmp_path):
        db_path = tmp_path / "test.db"
        with patch("posint_scanner.cli.build_sources") as mock_build_sources:
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                mock_build_sources.return_value = [FakeDiscoverySource()]
                runner.invoke(
                    app,
                    ["scan", "example.com", "--db", str(db_path), "--workers", "20"],
                )
        assert mock_run_scan.call_args.kwargs["workers"] == 20

    def test_workers_defaults_to_5(self, tmp_path):
        db_path = tmp_path / "test.db"
        with patch("posint_scanner.cli.build_sources") as mock_build_sources:
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                mock_build_sources.return_value = [FakeDiscoverySource()]
                runner.invoke(app, ["scan", "example.com", "--db", str(db_path)])
        assert mock_run_scan.call_args.kwargs["workers"] == 5

    def test_max_concurrent_domains_flag_is_threaded_through(self, tmp_path):
        db_path = tmp_path / "test.db"
        with patch("posint_scanner.cli.build_sources") as mock_build_sources:
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                mock_build_sources.return_value = [FakeDiscoverySource()]
                runner.invoke(
                    app,
                    [
                        "scan",
                        "example.com",
                        "--db",
                        str(db_path),
                        "--max-concurrent-domains",
                        "8",
                    ],
                )
        assert mock_run_scan.call_args.kwargs["max_concurrent_domains"] == 8

    def test_netblock_sweep_workers_flag_is_threaded_through(self, tmp_path):
        db_path = tmp_path / "test.db"
        with patch("posint_scanner.cli.build_sources") as mock_build_sources:
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                mock_build_sources.return_value = [FakeDiscoverySource()]
                runner.invoke(
                    app,
                    [
                        "scan",
                        "example.com",
                        "--db",
                        str(db_path),
                        "--netblock-sweep-workers",
                        "42",
                    ],
                )
        assert mock_run_scan.call_args.kwargs["netblock_sweep_workers"] == 42

    def test_netblock_sweep_resolvers_flag_is_parsed_and_threaded_through(self, tmp_path):
        db_path = tmp_path / "test.db"
        with patch("posint_scanner.cli.build_sources") as mock_build_sources:
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                mock_build_sources.return_value = [FakeDiscoverySource()]
                runner.invoke(
                    app,
                    [
                        "scan",
                        "example.com",
                        "--db",
                        str(db_path),
                        "--netblock-sweep-resolvers",
                        "4.4.4.4, 8.8.4.4",
                    ],
                )
        assert mock_run_scan.call_args.kwargs["netblock_sweep_resolvers"] == ["4.4.4.4", "8.8.4.4"]

    def test_netblock_sweep_resolvers_default_is_none(self, tmp_path):
        db_path = tmp_path / "test.db"
        with patch("posint_scanner.cli.build_sources") as mock_build_sources:
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                mock_build_sources.return_value = [FakeDiscoverySource()]
                runner.invoke(app, ["scan", "example.com", "--db", str(db_path)])
        assert mock_run_scan.call_args.kwargs["netblock_sweep_resolvers"] is None

    def test_invalid_resolver_ip_fails_fast_with_clear_error(self, tmp_path):
        db_path = tmp_path / "test.db"
        with patch("posint_scanner.cli.build_sources") as mock_build_sources:
            with patch("posint_scanner.cli.run_scan") as mock_run_scan:
                mock_build_sources.return_value = [FakeDiscoverySource()]
                result = runner.invoke(
                    app,
                    [
                        "scan",
                        "example.com",
                        "--db",
                        str(db_path),
                        "--netblock-sweep-resolvers",
                        "not-an-ip",
                    ],
                )
        assert result.exit_code == 1
        assert "invalid resolver IP" in result.output
        mock_run_scan.assert_not_called()
