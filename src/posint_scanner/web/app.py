"""FastAPI application: dashboard to launch scans + browsable HTML reports.

`create_app` is a factory (not a module-level app) so tests can point it at a
temp DB and the CLI can wire in real paths. Read routes are served from one
shared Database (SQLite with an RLock, safe across request threads); scans
run on their own threads via ScanManager and write the same DB file, which
the read connection then sees on its next query.

Bind to localhost by default (see cli.serve). This UI launches active,
target-touching scans, so it is meant for the operator running it, not for
exposure to untrusted networks.
"""

from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.background import BackgroundTask

from posint_scanner import proxy, toolrun
from posint_scanner.config import load_config
from posint_scanner.db import Database
from posint_scanner.export.zip_export import write_zip
from posint_scanner.registry import describe_sources
from posint_scanner.settings import AppSettings, load_settings, save_settings
from posint_scanner.web import views
from posint_scanner.web.scans import ScanManager, ScanOptions

_TEMPLATES_DIR = Path(__file__).parent / "templates"
# Report formats that aren't plain JSON, for the download's file name.
_REPORT_EXTENSIONS = {"nuclei": "jsonl", "trufflehog": "jsonl", "scoutsuite": "js"}


def create_app(
    db_path: str = "posint.db",
    config_path: str = "config.yaml",
    resume_interrupted: bool = False,
) -> FastAPI:
    """`resume_interrupted` resumes scans the previous process was still
    running when it ended (see web/scans.py)."""
    app = FastAPI(title="posint-scanner")
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    # Clears scratch dirs a killed earlier process left next to the DB -
    # before any interrupted scan resumes and starts using them.
    toolrun.configure(db_path)
    manager = ScanManager(
        db_path=db_path, config_path=config_path, resume_interrupted=resume_interrupted
    )

    # One shared read connection; ensure the schema exists so pages render
    # (empty) even before the first scan has written anything.
    db = Database(db_path)
    db.init_schema()
    app.state.db = db
    app.state.manager = manager

    def page(name: str, request: Request, status_code: int = 200, **ctx) -> HTMLResponse:
        return templates.TemplateResponse(request, name, ctx, status_code=status_code)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        config = load_config(config_path)
        return page(
            "dashboard.html",
            request,
            data=views.build_dashboard(db),
            jobs=[j.as_dict() for j in manager.list()],
            sources=describe_sources(config),
            active_default=config.defaults.active,
        )

    @app.post("/scans")
    def start_scan(
        request: Request,
        domain: str = Form(...),
        source: list[str] = Form([]),
        sources_form: bool = Form(False),
        authorize_scans: bool = Form(False),
        fingerprint: bool = Form(False),
        netblock_sweep: bool = Form(False),
        vuln_lookup: bool = Form(False),
        nuclei: bool = Form(False),
        nikto: bool = Form(False),
        wpscan: bool = Form(False),
        takeover: bool = Form(False),
        php2shell: bool = Form(False),
        cloud_scan: bool = Form(False),
        cloud_audit: bool = Form(False),
        fresh: bool = Form(False),
    ) -> RedirectResponse:
        domain = domain.strip()
        if not domain:
            return RedirectResponse("/", status_code=303)
        options = ScanOptions(
            # The form always sends the `sources_form` marker, so no `source`
            # values means "none checked" rather than "not specified".
            sources=set(source) if sources_form else None,
            authorize_scans=authorize_scans,
            fingerprint=fingerprint,
            netblock_sweep=netblock_sweep,
            vuln_lookup=vuln_lookup,
            nuclei=nuclei,
            nikto=nikto,
            wpscan=wpscan,
            takeover=takeover,
            php2shell=php2shell,
            cloud_scan=cloud_scan,
            cloud_audit=cloud_audit,
            fresh=fresh,
        )
        job = manager.start(domain, options)
        return RedirectResponse(f"/scans/{job.id}", status_code=303)

    @app.get("/scans/{job_id}", response_class=HTMLResponse)
    def scan_status(request: Request, job_id: str) -> HTMLResponse:
        job = manager.get(job_id)
        if job is None:
            return page("not_found.html", request, status_code=404, what=f"scan {job_id}")
        return page("scan_status.html", request, job=job.as_dict())

    @app.post("/scans/{job_id}/cancel", response_model=None)
    def cancel_scan(job_id: str):
        if manager.cancel(job_id) is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return RedirectResponse(f"/scans/{job_id}", status_code=303)

    @app.post("/scans/{job_id}/resume", response_model=None)
    def resume_scan(request: Request, job_id: str):
        job = manager.get(job_id)
        if job is None:
            return page("not_found.html", request, status_code=404, what=f"scan {job_id}")
        if manager.resume(job_id) is None:
            return page(
                "message.html",
                request,
                status_code=409,
                heading="Can't resume",
                message=f"The scan of {job.domain} is {job.status} - only interrupted, "
                "cancelled or failed scans can be resumed.",
            )
        return RedirectResponse(f"/scans/{job_id}", status_code=303)

    @app.get("/api/scans/{job_id}")
    def scan_status_json(job_id: str) -> JSONResponse:
        job = manager.get(job_id)
        if job is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(job.as_dict())

    @app.get("/export.zip")
    def export_zip(domain: list[str] = Query([])) -> FileResponse:
        """`domain` (repeatable) limits the export to those domains; none
        means everything."""
        fd, path = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        try:
            write_zip(db, path, domains=domain or None)
        except Exception:
            os.unlink(path)
            raise
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return FileResponse(
            path,
            media_type="application/zip",
            filename=f"posint-export-{stamp}.zip",
            background=BackgroundTask(os.unlink, path),
        )

    @app.post("/domains/{name}/delete", response_model=None)
    def delete_domain(request: Request, name: str):
        row = db.get_domain_by_name(name)
        if row is None:
            return page("not_found.html", request, status_code=404, what=f"domain {name}")
        if manager.busy():
            return page(
                "message.html",
                request,
                status_code=409,
                heading="Scan running",
                message=f"Not deleting {name} while a scan is running - try again once it finishes.",
            )
        db.delete_domain(row["id"])
        return RedirectResponse("/", status_code=303)

    @app.get("/reports/{output_id}", response_model=None)
    def download_report(request: Request, output_id: int):
        """A stored tool report, decompressed on the fly - nothing hits disk."""
        row = db.get_tool_output(output_id)
        if row is None:
            return page("not_found.html", request, status_code=404, what=f"report {output_id}")
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{row['tool']}-{row['target']}").strip("_")
        return StreamingResponse(
            toolrun.decompress_chunks(row["content"]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": (
                f'attachment; filename="{name[:120]}.{_REPORT_EXTENSIONS.get(row["tool"], "json")}"'
            )},
        )

    def settings_page(request: Request, form: dict, status_code: int = 200, **ctx) -> HTMLResponse:
        return page("settings.html", request, status_code=status_code, form=form,
                     default_dns=proxy.DEFAULT_DNS_SERVER, **ctx)

    @app.get("/settings", response_class=HTMLResponse)
    def settings_view(request: Request) -> HTMLResponse:
        return settings_page(request, load_settings(db).model_dump())

    @app.post("/settings", response_class=HTMLResponse)
    def settings_save(
        request: Request, proxy_url: str = Form(""), proxy_dns_server: str = Form("")
    ) -> HTMLResponse:
        form = {"proxy_url": proxy_url, "proxy_dns_server": proxy_dns_server}
        if manager.busy():
            # Switching the proxy mid-scan would send the rest of it another way.
            return settings_page(request, form, status_code=409,
                                 error="a scan is running - try again once it finishes.")
        try:
            settings = AppSettings(**form)
        except ValidationError as exc:
            error = "; ".join(e["msg"].removeprefix("Value error, ") for e in exc.errors())
            return settings_page(request, form, status_code=400, error=error)
        save_settings(db, settings)
        warning = None
        if settings.proxy_url:
            try:
                proxy.check_reachable(proxy.parse_proxy_url(settings.proxy_url))
            except proxy.ProxyUnavailableError as exc:
                warning = str(exc)
        return settings_page(request, settings.model_dump(), saved=True, warning=warning)

    @app.post("/settings/test", response_class=HTMLResponse)
    def settings_test(
        request: Request, proxy_url: str = Form(""), proxy_dns_server: str = Form("")
    ) -> HTMLResponse:
        """Try the proxy in the form (saved or not) without saving or
        activating it."""
        form = {"proxy_url": proxy_url, "proxy_dns_server": proxy_dns_server}
        try:
            settings = AppSettings(**form)
        except ValidationError as exc:
            error = "; ".join(e["msg"].removeprefix("Value error, ") for e in exc.errors())
            return settings_page(request, form, status_code=400, error=error)
        if not settings.proxy_url:
            return settings_page(request, form, status_code=400, error="enter a proxy to test.")
        checks = proxy.verify_proxy(proxy.parse_proxy_url(settings.proxy_url, settings.proxy_dns_server))
        return settings_page(request, form, checks=checks)

    @app.get("/overview", response_class=HTMLResponse)
    def overview(request: Request, domain: str | None = None) -> HTMLResponse:
        return page("overview.html", request, ov=views.build_overview(db, domain or None))

    @app.get("/domains/{name}", response_class=HTMLResponse)
    def domain(request: Request, name: str) -> HTMLResponse:
        data = views.build_domain(db, name)
        if data is None:
            return page("not_found.html", request, status_code=404, what=f"domain {name}")
        return page(
            "domain.html",
            request,
            d=data,
            active_default=load_config(config_path).defaults.active,
        )

    @app.get("/hosts/{name}", response_class=HTMLResponse)
    def host(request: Request, name: str) -> HTMLResponse:
        data = views.build_host(db, name)
        if data is None:
            return page("not_found.html", request, status_code=404, what=f"host {name}")
        # Hostname detail lives on the IP page; only unresolved names get their own.
        if data["ips"]:
            return RedirectResponse(f"/ips/{data['ips'][0]}#host-{name}", status_code=302)
        return page("host.html", request, h=data)

    @app.get("/ips/{address}", response_class=HTMLResponse)
    def ip(request: Request, address: str) -> HTMLResponse:
        data = views.build_ip(db, address)
        if data is None:
            return page("not_found.html", request, status_code=404, what=f"IP {address}")
        return page("ip.html", request, ip=data)

    return app
