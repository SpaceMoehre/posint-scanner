"""App settings edited in the web UI, persisted in the DB's `settings` table.

Unlike config.yaml (sources, keys, per-tool args), these are operator
toggles changed at runtime from the Settings page. Being in the DB, they
apply to every scan written to it - web or CLI.
"""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, field_validator

from posint_scanner import proxy
from posint_scanner.db import Database

PROXY_URL = "proxy_url"
PROXY_DNS_SERVER = "proxy_dns_server"


class AppSettings(BaseModel):
    # SOCKS5 proxy every scan connection is tunnelled through (see proxy.py).
    proxy_url: str | None = None
    # DNS server queried (over TCP, through the proxy) while proxied.
    proxy_dns_server: str | None = None

    @field_validator("proxy_url", "proxy_dns_server", mode="before")
    @classmethod
    def _blank_is_none(cls, value: str | None) -> str | None:
        return (value or "").strip() or None

    @field_validator("proxy_url")
    @classmethod
    def _valid_proxy(cls, value: str | None) -> str | None:
        return proxy.parse_proxy_url(value).url() if value else None

    @field_validator("proxy_dns_server")
    @classmethod
    def _valid_dns_server(cls, value: str | None) -> str | None:
        if value is not None:
            ipaddress.ip_address(value)  # ValueError -> ValidationError
        return value


def load_settings(db: Database) -> AppSettings:
    stored = db.get_settings()
    return AppSettings.model_construct(
        proxy_url=stored.get(PROXY_URL), proxy_dns_server=stored.get(PROXY_DNS_SERVER)
    )


def save_settings(db: Database, settings: AppSettings) -> None:
    db.set_setting(PROXY_URL, settings.proxy_url)
    db.set_setting(PROXY_DNS_SERVER, settings.proxy_dns_server)


def apply_settings(db: Database) -> None:
    """Make the stored settings take effect for this process: route traffic
    through the proxy (or stop), and refuse to go on if it's unreachable."""
    settings = load_settings(db)
    proxy.configure(settings.proxy_url, settings.proxy_dns_server)
    proxy.check_reachable()
