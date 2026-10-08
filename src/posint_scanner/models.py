"""In-memory data models produced by sources, before they're persisted to SQLite."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DiscoveredHostname(BaseModel):
    """A hostname found by a discovery source."""

    name: str
    source: str
    parent_hostname: str | None = None
    data: dict = Field(default_factory=dict)


class ServiceInfo(BaseModel):
    """A single service observed on an IP address."""

    port: int
    protocol: str = "tcp"
    banner: str | None = None
    version: str | None = None
    cpe: str | None = None  # Common Platform Enumeration, e.g. "cpe:2.3:a:nginx:nginx:1.18.0:..."


class CloudAsset(BaseModel):
    """A cloud storage bucket found for a domain."""

    provider: str  # "s3" | "gcs" | "azure"
    name: str
    url: str
    exposure: str  # "public" (listable) | "private" (exists, access denied)


class CodeExposure(BaseModel):
    """A public code file (GitHub) mentioning a target, or a secret found in
    such a file."""

    kind: str  # "reference" (the target is named in the file) | "secret"
    target: str  # the hostname/IP named - for a secret, the one searched for
    repo: str  # owner/name
    path: str
    commit: str
    url: str  # permalink, pinned to `commit` (and the line when known)
    line: int | None = None
    snippet: str | None = None  # the line naming the target
    rule: str | None = None  # secrets: which rule matched
    secret: str | None = None  # secrets: the full value


class EmailAddress(BaseModel):
    """An email address at the target domain (or one of its subdomains)."""

    address: str  # lowercased
    name: str | None = None  # person's name, when the source knows it
    position: str | None = None  # job title
    confidence: int | None = None  # 0-100, from sources that score addresses
    url: str | None = None  # a page the address was seen on


class EnrichmentResult(BaseModel):
    """Data returned by an enrichment source for one target (an IP or a hostname)."""

    source: str
    target_type: str  # "ip" | "hostname"
    target: str
    data: dict = Field(default_factory=dict)
    services: list[ServiceInfo] = Field(default_factory=list)
    # Other hostnames the source associates with this target (reverse-IP
    # neighbours, PTR names, hosts seen serving it). The orchestrator feeds
    # in-scope ones back into the pipeline and records the rest as candidate
    # domains (see scope.py).
    related_hostnames: list[str] = Field(default_factory=list)
    # Cloud storage buckets found for the target (domain-level sources).
    cloud_assets: list[CloudAsset] = Field(default_factory=list)
    # Code files naming the target, and secrets in them (GitHub sources).
    code_exposures: list[CodeExposure] = Field(default_factory=list)
    # Email addresses at the target domain (domain-level sources).
    email_addresses: list[EmailAddress] = Field(default_factory=list)
