"""What's in scope for a scan, and what a related out-of-scope name points at.

A scan of `example.com` covers the domain and every name under it. Names
outside it that sources relate to the target (reverse-IP neighbours, cert
SANs, WHOIS siblings) are reduced to their registrable domain (per the Public
Suffix List: `shop.brand.co.uk` -> `brand.co.uk`) and recorded as candidate
domains for a human to review - never scanned automatically, since that's
how a scan wanders onto infrastructure nobody authorized.

The one exception is a TLD sibling: the same registrable name under a
different public suffix (`example.com` -> `example.net`, `example.co.uk`).
Those count as the target's own and are scanned in the same run.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

import tldextract

from posint_scanner.normalize import InvalidDomainError, normalize_domain

# Bundled PSL snapshot only - no network fetch at runtime. Private suffixes
# included so `team.github.io` counts as its own site, not `github.io`.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


def in_scope(hostname: str, domain: str) -> bool:
    return hostname == domain or hostname.endswith("." + domain)


def registrable_domain(hostname: str) -> str | None:
    """`a.b.brand.co.uk` -> `brand.co.uk`; None for IPs, bare TLDs and
    single-label names."""
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    result = _EXTRACT(hostname)
    return result.top_domain_under_public_suffix or None


def tld_family(domain: str) -> str | None:
    """The name `domain` shares with its TLD siblings (`example` for
    `example.com` and `example.co.uk`), or None when it has none: IPs,
    subdomains and names under a private suffix (see is_tld_sibling)."""
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    result = _EXTRACT(domain)
    if not result.domain or not result.suffix or result.subdomain or result.is_private:
        return None
    return result.domain


def is_tld_sibling(candidate: str, domain: str) -> bool:
    """True if registrable `candidate` is `domain` under another public suffix
    (`example.net` for `example.com`). Only ICANN suffixes: names under a
    private suffix (`example.github.io`) belong to whoever registered them."""
    a, b = _EXTRACT(candidate), _EXTRACT(domain)
    return (
        bool(a.domain)
        and a.domain == b.domain
        and a.suffix != b.suffix
        and not a.subdomain
        and not b.subdomain
        and not a.is_private
        and not b.is_private
    )


def split_related(domain: str, names: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split related names into (in-scope hostnames, out-of-scope registrable
    domains), each normalized, deduped and in first-seen order."""
    hostnames: list[str] = []
    candidates: list[str] = []
    for raw in names:
        try:
            name = normalize_domain(raw)
        except InvalidDomainError:
            continue
        if in_scope(name, domain):
            if name not in hostnames:
                hostnames.append(name)
            continue
        registrable = registrable_domain(name)
        if registrable and registrable != domain and registrable not in candidates:
            candidates.append(registrable)
    return hostnames, candidates


# Domains a tool report names for reasons other than the target: advisories
# and CVE databases, tool and software vendors, package registries, and the
# CDNs, fonts, analytics and social widgets a scanned page embeds.
REPORT_NOISE_DOMAINS = frozenset("""
    nist.gov mitre.org cve.org first.org cisa.gov cert.org cert.at bsi.bund.de
    exploit-db.com packetstormsecurity.com securityfocus.com rapid7.com tenable.com
    snyk.io vulners.com cvedetails.com hackerone.com huntr.dev huntr.com wpscan.com
    wpvulndb.com patchstack.com wordfence.com owasp.org portswigger.net
    projectdiscovery.io aquasec.com bridgecrew.io checkov.io prowler.com nccgroup.com
    cirt.net zaproxy.org
    github.com githubusercontent.com gitlab.com bitbucket.org
    sourceforge.net
    apache.org nginx.org php.net python.org golang.org go.dev nodejs.org npmjs.com
    npmjs.org pypi.org rubygems.org packagist.org maven.org crates.io nuget.org
    docker.com docker.io quay.io gcr.io k8s.io kubernetes.io
    microsoft.com windows.com oracle.com redhat.com fedoraproject.org debian.org
    ubuntu.com canonical.com suse.com opensuse.org alpinelinux.org centos.org
    wordpress.org wordpress.com wp.com w.org drupal.org joomla.org
    openssl.org openssh.com curl.se haxx.se mozilla.org mozilla.net
    w3.org ietf.org rfc-editor.org iana.org schema.org ogp.me json-schema.org
    wikipedia.org stackoverflow.com stackexchange.com medium.com
    google.com googleapis.com gstatic.com googleusercontent.com google-analytics.com
    googletagmanager.com googlesyndication.com doubleclick.net recaptcha.net
    youtube.com ytimg.com
    cloudflare.com cloudflareinsights.com jsdelivr.net unpkg.com jquery.com
    bootstrapcdn.com fontawesome.com typekit.net gravatar.com
    facebook.com facebook.net fbcdn.net instagram.com twitter.com x.com twimg.com
    linkedin.com licdn.com pinterest.com tiktok.com
    hotjar.com segment.com segment.io newrelic.com nr-data.net sentry.io
    example.com example.net example.org
""".split())

# Public suffixes that are also common file extensions (README.md, setup.py,
# main.tf, Makefile.in, module.info, a Struts login.do): a bare two-label
# name with one of these outside a URL is a file name.
_FILE_LIKE_SUFFIXES = frozenset(
    "md py sh tf zip mov pl pm rs ps so in am ac cc mk ms info me sc ws do ai app mp".split()
)

_HOSTNAME = re.compile(
    r"(?<![\w-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(?![\w-])",
    re.IGNORECASE,
)


def domains_in_report(text: str, domain: str) -> list[str]:
    """The registrable domains other than `domain`'s own that a tool's raw
    report names (redirect targets, CNAMEs, contact addresses, linked
    sites), in first-seen order - minus REPORT_NOISE_DOMAINS and names that
    are really file names. TLD siblings are included."""
    found: list[str] = []
    for match in _HOSTNAME.finditer(text):
        name = match.group(1).lower().rstrip(".")
        if in_scope(name, domain):
            continue
        labels = name.split(".")
        in_url = text[max(0, match.start() - 2):match.start()] == "//"
        if not in_url and len(labels) == 2 and labels[1] in _FILE_LIKE_SUFFIXES:
            continue
        # Every parent: googleapis.com is a private suffix, so
        # fonts.googleapis.com is registrable on its own.
        if any(".".join(labels[i:]) in REPORT_NOISE_DOMAINS for i in range(len(labels))):
            continue
        registrable = registrable_domain(name)
        if registrable and registrable != domain and registrable not in found:
            found.append(registrable)
    return found
