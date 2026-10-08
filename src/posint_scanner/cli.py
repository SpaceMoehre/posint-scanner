"""Typer CLI: scan, export, query, db init."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Optional

import typer

from posint_scanner.config import load_config
from posint_scanner.db import Database
from posint_scanner.export.csv_export import write_csv
from posint_scanner.export.json_export import write_json
from posint_scanner.export.obsidian_export import export_obsidian
from posint_scanner.limits import raise_open_files_limit
from posint_scanner.logging_setup import setup_logging
from posint_scanner.orchestrator import run_scan
from posint_scanner.registry import SourceSelection, build_sources

app = typer.Typer(help="Modular passive OSINT scanner for domains.")
db_app = typer.Typer(help="Database management commands.")
app.add_typer(db_app, name="db")

DEFAULT_DB_PATH = "posint.db"
DEFAULT_CONFIG_PATH = "config.yaml"


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
    log_file: Optional[str] = typer.Option(
        None, "--log-file", help="Also write logs to this file."
    ),
) -> None:
    setup_logging(verbose=verbose, log_file=log_file)
    raise_open_files_limit()


@db_app.command("init")
def db_init(
    db_path: str = typer.Option(DEFAULT_DB_PATH, "--db", help="Path to the SQLite database."),
) -> None:
    """Create (or migrate) the SQLite schema."""
    with Database(db_path) as db:
        db.init_schema()
    typer.echo(f"initialized database at {db_path}")


@app.command()
def scan(
    domain: Optional[str] = typer.Argument(None, help="A single domain to scan."),
    domains_file: Optional[Path] = typer.Option(
        None, "--domains-file", help="File with one domain per line."
    ),
    db_path: str = typer.Option(DEFAULT_DB_PATH, "--db", help="Path to the SQLite database."),
    config_path: str = typer.Option(
        DEFAULT_CONFIG_PATH, "--config", help="Path to config.yaml."
    ),
    sources: Optional[str] = typer.Option(
        None,
        "--sources",
        help=(
            "Comma-separated list of source names to run - only these, out of "
            "whichever are enabled (default: all enabled)."
        ),
    ),
    enable_sources: Optional[list[str]] = typer.Option(
        None,
        "--source",
        help=(
            "Enable a source by name, overriding config and category defaults "
            "(repeatable). Also forces a *_web scraper to run alongside its "
            "configured API sibling."
        ),
    ),
    disable_sources: Optional[list[str]] = typer.Option(
        None, "--no-source", help="Disable a source by name (repeatable)."
    ),
    no_active: bool = typer.Option(
        False,
        "--no-active",
        help=(
            "Disable every active source and stage (ping, port scan, tech "
            "fingerprint) - the ones that send traffic straight to the target."
        ),
    ),
    fresh: bool = typer.Option(
        False,
        "--fresh",
        help=(
            "Ignore source TTLs and re-query targets a metered source answered "
            "for recently (quota budgets still apply)."
        ),
    ),
    authorize_scans: bool = typer.Option(
        False,
        "--authorize-scans",
        help=(
            "Allow Qualys VMDR to trigger new active scans. Off by default - "
            "only use against infrastructure you are authorized to scan."
        ),
    ),
    no_netblock_sweep: bool = typer.Option(
        False,
        "--no-netblock-sweep",
        help=(
            "Disable the reverse-DNS netblock sweep stage (looks up the ASN "
            "announcing each known IP and PTR-sweeps every prefix it "
            "announces, against 1.1.1.1 and the target's own nameserver if "
            "one was discovered)."
        ),
    ),
    netblock_sweep_max_addresses: int = typer.Option(
        20_000,
        "--netblock-sweep-max-addresses",
        help=(
            "Cap on total addresses swept per domain across all of a "
            "target's ASN prefixes, so a target hosted on a huge "
            "cloud-provider ASN doesn't turn into an unbounded sweep of "
            "unrelated infrastructure."
        ),
    ),
    netblock_sweep_workers: int = typer.Option(
        150,
        "--netblock-sweep-workers",
        help="Worker count for the netblock sweep's shared thread pool (all swept networks share one pool).",
    ),
    netblock_sweep_resolvers: Optional[str] = typer.Option(
        None,
        "--netblock-sweep-resolvers",
        help=(
            "Comma-separated resolver IPs for the netblock sweep "
            "(default: 1.1.1.1,8.8.8.8,9.9.9.9). The target's own "
            "nameserver, if discovered, is always added on top of these."
        ),
    ),
    workers: int = typer.Option(
        5,
        "--workers",
        help="Worker count for discovery/enrichment thread pools, per domain.",
    ),
    max_concurrent_domains: int = typer.Option(
        4,
        "--max-concurrent-domains",
        help="How many domains to process concurrently when scanning a --domains-file batch.",
    ),
    report_output: str = typer.Option(
        "./vault",
        "--report-output",
        help="Where to write the Obsidian markdown report (only if --report is given).",
    ),
    report: bool = typer.Option(
        False, "--report", help="Generate the Obsidian markdown report after the scan (off by default)."
    ),
    ping: Optional[bool] = typer.Option(
        None,
        "--ping/--no-ping",
        help="Deprecated: same as --source ping / --no-source ping.",
    ),
    scan_ports: Optional[bool] = typer.Option(
        None,
        "--scan-ports/--no-scan-ports",
        help="Deprecated: same as --source portscan / --no-source portscan.",
    ),
    fingerprint: Optional[bool] = typer.Option(
        None,
        "--fingerprint/--no-fingerprint",
        help=(
            "Visit every discovered port and fingerprint the "
            "technologies/versions running on it (web servers, languages, "
            "frameworks, CMSes, JS libraries), Wappalyzer-style; every "
            "version found is CVE-checked. An active stage (connects straight "
            "to the target), so it follows --no-active / config "
            "`defaults: {active: ...}` unless set explicitly."
        ),
    ),
    no_vuln_lookup: bool = typer.Option(
        False,
        "--no-vuln-lookup",
        help=(
            "Disable CVE lookup (via the free NVD API) for detected "
            "product/version pairs. Fully passive - queries NIST's public "
            "database, never touches the target - so this is on by "
            "default; disable it only to save the NVD rate-limit budget "
            "for a large scan."
        ),
    ),
    nuclei: bool = typer.Option(
        False,
        "--nuclei",
        help=(
            "Run Nuclei's active template scan against the web services found "
            "(needs the `nuclei` binary; templates via `cent` - see README). "
            "ACTIVE and intrusive - sends crafted requests to the target, so "
            "it's off by default and only for hosts you're authorized to test."
        ),
    ),
    nikto: bool = typer.Option(
        False,
        "--nikto",
        help=(
            "Run the Nikto web-server scanner against every resolved web "
            "service (needs the `nikto` binary, skipped if absent). ACTIVE and "
            "intrusive - only for hosts you're authorized to test."
        ),
    ),
    wpscan: bool = typer.Option(
        False,
        "--wpscan",
        help=(
            "Run WPScan against every resolved web service (a fast no-op on "
            "non-WordPress sites; needs the `wpscan` binary). Set a token via "
            "webscan.wpscan_api_token / OSINT_WPSCAN_API_TOKEN for CVE data. "
            "ACTIVE - only for hosts you're authorized to test."
        ),
    ),
    takeover: bool = typer.Option(
        False,
        "--takeover",
        help=(
            "Check every discovered hostname for a dangling, claimable service "
            "(subdomain takeover) with edoardottt/takeover (needs the "
            "`takeover` binary, skipped if absent)."
        ),
    ),
    cloud_scan: bool = typer.Option(
        False,
        "--cloud-scan",
        help=(
            "Credential-free artifact scanning: run Checkov + `trivy fs` on the "
            "public GitHub repos found for the domain, and `trivy image` on "
            "container images an exposed registry listed or config supplies. "
            "Needs the `trivy`/`checkov` binaries (skipped if absent)."
        ),
    ),
    cloud_audit: bool = typer.Option(
        False,
        "--cloud-audit",
        help=(
            "Authenticated cloud-account audit: run Prowler + ScoutSuite against "
            "the configured providers (cloudscan.providers) using credentials "
            "from your environment. ONLY for accounts you're authorized to "
            "audit. Needs the `prowler`/`scout` binaries (skipped if absent)."
        ),
    ),
    shodan_web: bool = typer.Option(
        False,
        "--shodan-web",
        help="Deprecated: same as --source shodan_web.",
    ),
) -> None:
    """Run discovery + enrichment for one or more domains, then export an
    Obsidian markdown report."""
    raw_domains: list[str] = []
    if domain:
        raw_domains.append(domain)
    if domains_file:
        raw_domains.extend(
            line.strip() for line in domains_file.read_text().splitlines() if line.strip()
        )
    if not raw_domains:
        typer.echo("error: provide a domain or --domains-file", err=True)
        raise typer.Exit(code=1)

    resolver_ips: Optional[list[str]] = None
    if netblock_sweep_resolvers:
        resolver_ips = [ip.strip() for ip in netblock_sweep_resolvers.split(",") if ip.strip()]
        for ip in resolver_ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                typer.echo(
                    f"error: invalid resolver IP {ip!r} in --netblock-sweep-resolvers", err=True
                )
                raise typer.Exit(code=1)

    selection = SourceSelection(
        enable=set(enable_sources or []), disable=set(disable_sources or [])
    )
    if no_active:
        selection.categories["active"] = False
    for flag, source_name in ((ping, "ping"), (scan_ports, "portscan")):
        if flag is not None:
            (selection.enable if flag else selection.disable).add(source_name)
    if shodan_web:
        selection.enable.add("shodan_web")

    config = load_config(config_path)
    try:
        all_sources = build_sources(
            config,
            selection,
            overrides={"qualys_vmdr": {"authorize_scans": True}} if authorize_scans else None,
        )
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1)
    if fingerprint is None:
        fingerprint = selection.categories.get("active", config.defaults.active)
    source_filter = [name.strip() for name in sources.split(",")] if sources else None

    with Database(db_path) as db:
        db.init_schema()
        run_scan(
            db,
            raw_domains,
            all_sources,
            source_filter=source_filter,
            netblock_sweep=not no_netblock_sweep,
            netblock_sweep_max_addresses=netblock_sweep_max_addresses,
            netblock_sweep_resolvers=resolver_ips,
            netblock_sweep_workers=netblock_sweep_workers,
            tech_fingerprint=fingerprint,
            vuln_lookup=not no_vuln_lookup,
            nuclei_scan=nuclei,
            nuclei_templates_dir=config.nuclei.templates_dir,
            nikto_scan=nikto,
            wpscan_scan=wpscan,
            takeover_scan=takeover,
            webscan_config=config.webscan,
            cloud_scan=cloud_scan,
            cloud_audit=cloud_audit,
            cloudscan_config=config.cloudscan,
            nvd_api_key=config.nvd.api_key,
            workers=workers,
            max_concurrent_domains=max_concurrent_domains,
            fresh=fresh,
        )
        if report:
            export_obsidian(db, Path(report_output))

    typer.echo(f"scan complete, results in {db_path}")
    if report:
        typer.echo(f"markdown report exported to {report_output}")


@app.command(name="export")
def export_command(
    format: str = typer.Option("obsidian", "--format", help="obsidian | json | csv"),
    output: str = typer.Option(
        ..., "--output", help="Output path (directory for obsidian, file for json/csv)."
    ),
    db_path: str = typer.Option(DEFAULT_DB_PATH, "--db", help="Path to the SQLite database."),
) -> None:
    """Export the current scan database to a report format."""
    with Database(db_path) as db:
        if format == "obsidian":
            export_obsidian(db, Path(output))
        elif format == "json":
            write_json(db, output)
        elif format == "csv":
            write_csv(db, output)
        else:
            typer.echo(
                f"error: unknown format {format!r} (expected obsidian, json, or csv)", err=True
            )
            raise typer.Exit(code=1)

    typer.echo(f"exported {format} to {output}")


@app.command()
def serve(
    db_path: str = typer.Option(DEFAULT_DB_PATH, "--db", help="Path to the SQLite database."),
    config_path: str = typer.Option(DEFAULT_CONFIG_PATH, "--config", help="Path to config.yaml."),
    report_output: str = typer.Option(
        "./vault", "--report-output", help="Vault directory the web UI regenerates after a scan."
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help=(
            "Address to bind. Defaults to localhost - the UI launches active "
            "scans, so only bind it to a non-local address on a network you "
            "control and trust."
        ),
    ),
    port: int = typer.Option(8000, "--port", help="Port to listen on."),
) -> None:
    """Launch the browser UI to start scans and read reports.

    Requires the web extra: `pip install -e '.[web]'`.
    """
    try:
        import uvicorn

        from posint_scanner.web.app import create_app
    except ImportError as exc:
        typer.echo(
            f"error: web dependencies not installed ({exc}). "
            "Install them with: pip install -e '.[web]'",
            err=True,
        )
        raise typer.Exit(code=1)

    application = create_app(db_path=db_path, config_path=config_path, vault_dir=report_output)
    typer.echo(f"posint-scanner UI on http://{host}:{port}  (db: {db_path})")
    uvicorn.run(application, host=host, port=port)


@app.command()
def query(
    host: str = typer.Option(..., "--host", help="Hostname to look up."),
    db_path: str = typer.Option(DEFAULT_DB_PATH, "--db", help="Path to the SQLite database."),
) -> None:
    """Quick lookup of what's known about a hostname."""
    with Database(db_path) as db:
        row = db.get_hostname_by_name(host)
        if row is None:
            typer.echo(f"no data for {host}")
            raise typer.Exit(code=1)

        typer.echo(f"{host} (first seen {row['first_seen']}, last seen {row['last_seen']})")

        for ip_row in db.list_ips_for_hostname(row["id"]):
            typer.echo(f"  -> {ip_row['address']}")
            for service in db.list_services_for_ip(ip_row["id"]):
                label = service["banner"] or ""
                if service["version"]:
                    label = f"{label} {service['version']}".strip()
                suffix = f" ({label})" if label else ""
                typer.echo(f"       {service['port']}/{service['protocol']}{suffix}")
            for result in db.list_results_for_target("ip", ip_row["id"]):
                typer.echo(f"       [{result['source']}] {result['data']}")

        for result in db.list_results_for_target("hostname", row["id"]):
            typer.echo(f"  [{result['source']}] {result['data']}")


@app.command()
def overview(
    domain: Optional[str] = typer.Option(None, "--domain", help="Filter to a specific domain."),
    db_path: str = typer.Option(DEFAULT_DB_PATH, "--db", help="Path to the SQLite database."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show the security overview (exposed services, vulnerabilities, critical findings) from the database."""
    from posint_scanner.web.views import build_overview
    import json as jsonlib

    with Database(db_path) as db:
        ov = build_overview(db, domain)

    if json_output:
        typer.echo(jsonlib.dumps(ov, indent=2, default=str))
        return

    typer.echo(f"Security Overview{f' for {domain}' if domain else ''}")
    typer.echo(f"  Total IPs: {ov['total_ips']}")
    typer.echo(f"  Hosts exposing sensitive services: {ov['hosts_with_exposure']}")
    typer.echo(f"  Sensitive service exposures: {len(ov['exposures'])}")
    typer.echo(f"  Hosts with known vulnerabilities: {ov['hosts_with_vulns']}")
    typer.echo(f"  Critical findings: {len(ov['criticals'])}")
    typer.echo()

    if ov["criticals"]:
        typer.echo("Critical findings:")
        for c in ov["criticals"]:
            names = ", ".join(c["hostnames"][:3]) + (f" +{len(c['hostnames'])-3} more" if len(c["hostnames"]) > 3 else "")
            typer.echo(f"  - {c['kind']} — {c['address']} ({names}): {c['detail']}")
        typer.echo()

    if ov["exposures"]:
        typer.echo("Exposed sensitive services:")
        for e in ov["exposures"]:
            names = ", ".join(e["hostnames"][:3]) + (f" +{len(e['hostnames'])-3} more" if len(e["hostnames"]) > 3 else "")
            typer.echo(f"  - {e['address']} ({names}) port {e['port']}/{e['protocol']} {e['service']} — {e['reason']}")
        typer.echo()

    if ov["vuln_rows"]:
        typer.echo("Hosts with known vulnerabilities:")
        for v in ov["vuln_rows"]:
            names = ", ".join(v["hostnames"][:3]) + (f" +{len(v['hostnames'])-3} more" if len(v["hostnames"]) > 3 else "")
            score = f"{v['max_score']:.1f}" if v["max_score"] else "-"
            port = f"{v['port']}" if v["port"] is not None else "-"
            typer.echo(f"  - {v['address']} ({names}) port {port} {v['component']} — {v['cve_count']} CVEs, max CVSS {score}, worst {v['worst']}")
        typer.echo()

    if not ov["criticals"] and not ov["exposures"] and not ov["vuln_rows"]:
        typer.echo("No findings.")


@app.command()
def dashboard(
    db_path: str = typer.Option(DEFAULT_DB_PATH, "--db", help="Path to the SQLite database."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show the dashboard summary (per-domain stats) from the database."""
    from posint_scanner.web.views import build_dashboard
    import json as jsonlib

    with Database(db_path) as db:
        dash = build_dashboard(db)

    if json_output:
        typer.echo(jsonlib.dumps(dash, indent=2, default=str))
        return

    typer.echo(f"Dashboard — {len(dash['domains'])} domains, {dash['total_hosts']} hostnames, {dash['total_ips']} IPs")
    typer.echo()
    for d in dash["domains"]:
        typer.echo(f"  {d['name']}: {d['hostname_count']} hostnames, {d['ip_count']} IPs, {d['service_count']} services, {d['exposure_count']} exposures, {d['cve_count']} CVEs, {d['critical_count']} critical, {d['secret_count']} secrets")


@app.command()
def domain(
    name: str = typer.Argument(..., help="Domain name to show details for."),
    db_path: str = typer.Option(DEFAULT_DB_PATH, "--db", help="Path to the SQLite database."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show detailed domain information from the database."""
    from posint_scanner.web.views import build_domain
    import json as jsonlib

    with Database(db_path) as db:
        data = build_domain(db, name)

    if data is None:
        typer.echo(f"no data for domain {name}")
        raise typer.Exit(code=1)

    if json_output:
        typer.echo(jsonlib.dumps(data, indent=2, default=str))
        return

    typer.echo(f"Domain: {data['name']}")
    typer.echo(f"  Hostnames: {len(data['hostnames'])}")
    typer.echo(f"  IPs: {data['ip_count']}")
    typer.echo(f"  Services: {len(data['services'])}")
    typer.echo(f"  Candidate domains: {len(data['candidates'])}")
    typer.echo(f"  Lookalikes: {len(data['lookalikes'])}")
    typer.echo(f"  Cloud assets: {len(data['cloud_assets'])}")
    typer.echo(f"  Code exposures: {len(data['code_exposures'])}")
    typer.echo(f"  Email addresses: {len(data['email_addresses'])}")
    typer.echo(f"  Takeovers: {len(data['takeovers'])}")


@app.command()
def ip(
    address: str = typer.Argument(..., help="IP address to show details for."),
    db_path: str = typer.Option(DEFAULT_DB_PATH, "--db", help="Path to the SQLite database."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show detailed IP information from the database."""
    from posint_scanner.web.views import build_ip
    import json as jsonlib

    with Database(db_path) as db:
        data = build_ip(db, address)

    if data is None:
        typer.echo(f"no data for IP {address}")
        raise typer.Exit(code=1)

    if json_output:
        typer.echo(jsonlib.dumps(data, indent=2, default=str))
        return

    typer.echo(f"IP: {data['address']}")
    typer.echo(f"  Hostnames: {len(data['hostnames'])}")
    typer.echo(f"  Services: {len(data['services'])}")
    typer.echo(f"  Vulnerabilities: {len(data['vulns'])}")
    typer.echo(f"  Nuclei findings: {len(data['nuclei'])}")
    typer.echo(f"  Web findings: {len(data['web_findings'])}")
    typer.echo(f"  Container exposures: {len(data['container_exposures'])}")
    typer.echo(f"  Code exposures: {len(data['code_exposures'])}")


if __name__ == "__main__":
    app()
