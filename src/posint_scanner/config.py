"""Config loading: a YAML file plus environment-variable overrides per source.

Every source is configured under one generic map, and each source class owns
its settings model (see sources/base.py SourceSettings):

    defaults: {passive: true, scrape: false, active: true}
    sources:
      shodan: {api_key: "..."}
      shodan_web: {enabled: true}

Any field can also be set via `OSINT_<SOURCE>_<FIELD>` (e.g.
OSINT_SHODAN_API_KEY), derived from the source's settings model, so a new
source needs no config.py change. Top-level source sections (`shodan:`,
`censys:`, `qualys_vmdr:` - the pre-`sources:` layout) still work as aliases;
the `sources:` entry wins per field when both are present.

A source with a missing/empty key is skipped at runtime (see orchestrator.py)
rather than crashing the whole scan.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, Field

from posint_scanner.sources.base import SourceSettings

S = TypeVar("S", bound=SourceSettings)


class NvdConfig(BaseModel):
    # Optional: NVD works with no key at all (5 req/30s), a free key
    # (nvd.nist.gov/developers/request-an-api-key) raises that to 50/30s.
    # Not a registry source (it's the CVE-lookup stage), so it keeps its own
    # section.
    api_key: str | None = None


class NucleiConfig(BaseModel):
    # Active template scan (opt-in via --nuclei). templates_dir is passed to
    # nuclei's -t; None uses nuclei's own default template directory (the one
    # `cent` populates - see the Dockerfile/README). Not a registry source
    # (it's its own post-fingerprint stage), so it keeps its own section.
    templates_dir: str | None = None


class WebScanConfig(BaseModel):
    """Nikto / WPScan / takeover settings (see webscan.py). Three independent,
    opt-in active stages that scan the resolved web services and hostnames the
    passive stages surfaced. Like nuclei, each is its own post-discovery stage
    rather than a registry source, so they share this section.

    `wpscan_api_token` (or OSINT_WPSCAN_API_TOKEN) unlocks WPScan's vulnerability
    database; without it WPScan still enumerates versions but reports no CVEs.
    The `*_extra_args` lists pass advanced flags straight through to each binary
    (e.g. a Nikto `-Tuning` selector, or `--plugins-detection aggressive`)."""

    wpscan_api_token: str | None = None
    nikto_extra_args: list[str] = Field(default_factory=list)
    wpscan_extra_args: list[str] = Field(default_factory=list)
    takeover_extra_args: list[str] = Field(default_factory=list)


class CloudScanConfig(BaseModel):
    """Trivy / Checkov / Prowler / ScoutSuite settings (see cloudscan.py).

    Two independent stages share this section:

      * artifact scanning (`--cloud-scan`): Trivy + Checkov over public repos
        and container images - credential-free. `repos`/`images` are extra
        targets to add on top of what the pipeline discovers (GitHub repos
        the code-exposure stage found, images an exposed registry listed);
        `guess_image_orgs` turns the domain label into candidate Docker Hub /
        GHCR image names to try.

      * cloud account auditing (`--cloud-audit`): Prowler + ScoutSuite against
        `providers`, using credentials from the ambient environment. Only for
        accounts you're authorized to audit.
    """

    # Cloud providers to audit with Prowler/ScoutSuite (aws|azure|gcp|kubernetes).
    providers: list[str] = Field(default_factory=lambda: ["aws"])
    # Extra artifact targets on top of what the pipeline discovers.
    repos: list[str] = Field(default_factory=list)   # git URLs to clone + scan
    images: list[str] = Field(default_factory=list)  # container image references
    # Orgs/namespaces to guess image names under (e.g. "acme" -> acme/<label>).
    guess_image_orgs: list[str] = Field(default_factory=list)
    # Per-tool extra CLI args (advanced; e.g. ["--insecure"] for Trivy against
    # a plain-HTTP registry, or a Prowler compliance framework selector).
    trivy_extra_args: list[str] = Field(default_factory=list)
    checkov_extra_args: list[str] = Field(default_factory=list)
    prowler_extra_args: list[str] = Field(default_factory=list)
    scoutsuite_extra_args: list[str] = Field(default_factory=list)
    # Bounds so a scan can't clone/scan an unbounded number of artifacts.
    clone_timeout_seconds: int = 180
    max_repos: int = 25
    max_images: int = 25


class CategoryDefaults(BaseModel):
    """Whether a source of each category runs when nothing more specific
    (config `enabled:`, CLI flag) says otherwise."""

    passive: bool = True
    scrape: bool = False
    active: bool = True


class Config(BaseModel):
    defaults: CategoryDefaults = CategoryDefaults()
    sources: dict[str, dict[str, Any]] = Field(default_factory=dict)
    nvd: NvdConfig = NvdConfig()
    nuclei: NucleiConfig = NucleiConfig()
    webscan: WebScanConfig = WebScanConfig()
    cloudscan: CloudScanConfig = CloudScanConfig()

    def source_settings(self, name: str, model: type[S]) -> S:
        """Resolve one source's settings: its config section, then any
        `OSINT_<NAME>_<FIELD>` env var over it. Raises ValidationError on an
        unknown key or a badly-typed value."""
        raw = dict(self.sources.get(name) or {})
        prefix = f"OSINT_{name.upper()}_"
        for field in model.model_fields:
            value = os.environ.get(prefix + field.upper())
            if value:
                raw[field] = value
        return model(**raw)


_RESERVED_TOP_LEVEL = {"defaults", "sources", "nvd", "nuclei", "webscan", "cloudscan"}


def load_config(path: str | Path | None) -> Config:
    raw: dict = {}
    if path is not None and Path(path).exists():
        raw = yaml.safe_load(Path(path).read_text()) or {}

    sources: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        if key not in _RESERVED_TOP_LEVEL and isinstance(value, dict):
            sources[key] = dict(value)  # legacy top-level source section
    for name, section in (raw.get("sources") or {}).items():
        sources.setdefault(name, {}).update(section or {})

    config = Config.model_validate(
        {"defaults": raw.get("defaults") or {}, "sources": sources,
         "nvd": raw.get("nvd") or {}, "nuclei": raw.get("nuclei") or {},
         "webscan": raw.get("webscan") or {},
         "cloudscan": raw.get("cloudscan") or {}}
    )
    nvd_key = os.environ.get("OSINT_NVD_API_KEY")
    if nvd_key:
        config.nvd.api_key = nvd_key
    templates_dir = os.environ.get("OSINT_NUCLEI_TEMPLATES_DIR")
    if templates_dir:
        config.nuclei.templates_dir = templates_dir
    wpscan_token = os.environ.get("OSINT_WPSCAN_API_TOKEN")
    if wpscan_token:
        config.webscan.wpscan_api_token = wpscan_token
    providers = os.environ.get("OSINT_CLOUDSCAN_PROVIDERS")
    if providers:
        config.cloudscan.providers = [p.strip() for p in providers.split(",") if p.strip()]
    return config
