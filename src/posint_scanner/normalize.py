"""Domain input normalization and validation."""

from __future__ import annotations

import re

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_LABEL_RE = re.compile(r"^[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?$")


class InvalidDomainError(ValueError):
    """Raised when input can't be normalized into a plausible domain name."""


def normalize_domain(raw: str) -> str:
    """Normalize a raw user-supplied domain string.

    Lowercases, strips scheme/path (if a full URL was pasted in), strips a
    trailing dot and a leading wildcard label, then validates the result
    looks like a domain name.
    """
    value = raw.strip()
    if not value:
        raise InvalidDomainError("empty domain")

    value = _SCHEME_RE.sub("", value)
    value = value.split("/", 1)[0]
    value = value.lower().rstrip(".")

    if value.startswith("*."):
        value = value[2:]

    if not value or "." not in value:
        raise InvalidDomainError(f"not a valid domain: {raw!r}")

    labels = value.split(".")
    for label in labels:
        if not label or not _LABEL_RE.match(label):
            raise InvalidDomainError(f"not a valid domain: {raw!r}")

    return value


def dedup_domains(domains: list[str]) -> list[str]:
    """Deduplicate normalized domains case-insensitively, preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for domain in domains:
        key = domain.lower()
        if key not in seen:
            seen.add(key)
            result.append(domain)
    return result
