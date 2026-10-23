"""App settings edited in the web UI, persisted in the DB's `settings` table.

Unlike config.yaml (sources, keys, per-tool args), these are operator
toggles changed at runtime from the Settings page. Being in the DB, they
apply to every scan written to it - web or CLI.

API keys and other per-source credentials can also be set here (stored under
`source.<name>.<field>` keys) instead of in config.yaml / env vars, and are
merged into the Config before a scan builds its sources (see
`apply_source_secrets`). Precedence stays `env > web UI (DB) > config.yaml`.
"""

from __future__ import annotations

import ipaddress
import os
from typing import TYPE_CHECKING

from pydantic import BaseModel, field_validator

from posint_scanner import proxy
from posint_scanner.db import Database

if TYPE_CHECKING:
    from posint_scanner.config import Config

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


# -- per-source API keys / credentials ------------------------------------

# Settings-table key prefix for a credential: `source.<name>.<field>`.
_SOURCE_PREFIX = "source."

# Field names (on a source's settings model) treated as a secret worth
# offering in the web UI. Matched by exact name or by suffix so new sources
# need no change here.
_SECRET_NAMES = {"api_key", "api_secret", "api_id", "api_user", "api_password", "token"}
_SECRET_SUFFIXES = ("_token", "_key", "_secret", "_password")

# Credentials that live in their own Config section rather than under
# `sources:` (they aren't registry sources). Each maps (name, field) to the
# (env var, config section, attribute) it targets - the table alone drives
# apply_source_secrets, so a new standalone credential just adds a row. The
# env var keeps winning over the DB value (matching load_config).
_SPECIAL_SECRETS = {
    ("nvd", "api_key"): ("OSINT_NVD_API_KEY", "nvd", "api_key"),
    ("wpscan", "wpscan_api_token"): ("OSINT_WPSCAN_API_TOKEN", "webscan", "wpscan_api_token"),
}

_LABELS = {
    "api_key": "API key", "api_secret": "API secret", "api_id": "API ID",
    "api_user": "API user", "api_password": "API password", "token": "Token",
    "wpscan_api_token": "WPScan API token",
}


def _is_secret_field(name: str) -> bool:
    return name in _SECRET_NAMES or name.endswith(_SECRET_SUFFIXES)


def _secret_key(source: str, field: str) -> str:
    return f"{_SOURCE_PREFIX}{source}.{field}"


def source_secret_fields() -> list[tuple[str, str]]:
    """Every (source, field) credential that can be set from the web UI, in a
    stable order: each registry source's secret fields, then the standalone
    sections (NVD, WPScan)."""
    from posint_scanner.registry import SOURCE_CLASSES

    fields = [
        (cls.name, name)
        for cls in SOURCE_CLASSES
        for name in cls.settings_model.model_fields
        if _is_secret_field(name)
    ]
    return fields + list(_SPECIAL_SECRETS)


def secret_field_label(field: str) -> str:
    return _LABELS.get(field, field.replace("_", " ").capitalize())


def load_source_secrets(db: Database) -> dict[str, dict[str, str]]:
    """Stored credentials as {source: {field: value}} (only non-empty ones)."""
    stored = db.get_settings()
    out: dict[str, dict[str, str]] = {}
    for source, field in source_secret_fields():
        value = stored.get(_secret_key(source, field))
        if value:
            out.setdefault(source, {})[field] = value
    return out


def save_source_secrets(db: Database, values: dict[str, dict[str, str | None]]) -> None:
    """Persist only the credentials present in `values` - a field left out is
    untouched, so a partial submit can't wipe keys it didn't carry. A field
    present with a blank/None value clears that one stored key."""
    valid = set(source_secret_fields())
    for source, fields in values.items():
        for field, value in fields.items():
            if (source, field) in valid:
                db.set_setting(_secret_key(source, field), (value or "").strip() or None)


def apply_source_secrets(config: Config, db: Database) -> None:
    """Merge DB-stored credentials into `config` so a scan picks them up.
    Registry sources get the value in `config.sources` (env still wins, applied
    last by Config.source_settings); the standalone sections only take it when
    their env var is unset, matching load_config's own precedence."""
    secrets = load_source_secrets(db)
    for source, field in source_secret_fields():
        value = (secrets.get(source) or {}).get(field)
        if not value:
            continue
        special = _SPECIAL_SECRETS.get((source, field))
        if special is None:
            config.sources.setdefault(source, {})[field] = value
            continue
        env_var, section, attr = special
        if not os.environ.get(env_var):
            setattr(getattr(config, section), attr, value)


def source_key_groups(db: Database) -> list[dict]:
    """The settings page's view model: one group per source with secret
    fields, each field carrying its form name, label, and whether a value is
    stored. The secret itself is deliberately not returned, so it never gets
    echoed back into the page HTML."""
    secrets = load_source_secrets(db)
    groups: dict[str, list[dict]] = {}
    for source, field in source_secret_fields():
        groups.setdefault(source, []).append(
            {
                "field": field,
                "label": secret_field_label(field),
                "name": _secret_key(source, field),
                "configured": bool((secrets.get(source) or {}).get(field)),
            }
        )
    return [{"source": source, "fields": fields} for source, fields in groups.items()]
