"""Active source: HTTP(S) technology fingerprinting of discovered services.

For every web-serving port other stages already found on a host (Shodan,
Censys, the port scanner), this visits the service directly and identifies
the technologies and versions running on it - a Wappalyzer/WhatWeb-style
fingerprint from the response's headers, cookies and HTML.

Like `ping` and `portscan`, this connects straight to the target rather than
querying a resolver or third-party API. Runs by default; opt out with
`--no-fingerprint`. It runs as its own pipeline stage *after* enrichment rather than
as a normal `Source.enrich`, because it consumes the ports other enrichment
sources discovered - and those all run concurrently, so no single source can
see another's results (same structural reason the NVD vuln lookup is a
post-enrichment stage, see orchestrator._run_vulnerability_lookup).

The fingerprint ruleset below is a curated subset - the common web servers,
languages, frameworks, CMSes, self-hosted applications (GeoServer,
Grafana, Jenkins, ...), CDNs and JS libraries - not the full
Wappalyzer database (thousands of entries, network-fetched). It's modelled on
Wappalyzer's own shape (per-technology header/cookie/HTML patterns, plus
`version_header`/`version_html` for markers that give a version but aren't
distinctive enough to detect on, and `implies` edges) so it's easy to extend:
add a `_fp(...)` entry - no per-application code path. Every technology
identified with a version is CVE-checked by the NVD stage (see
orchestrator._run_vulnerability_lookup) via its `cpe` mapping. The web-server
product is also written back onto the service row.

Detection follows HTTP redirects (see WebTechFingerprinter._get): a service
whose root 3xx's to where the app actually lives - GeoServer's `/` ->
`/geoserver/web/` is the canonical case - is fingerprinted at the redirect
target, with no path list or app-specific handling. The result records that
final URL.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import requests
from posint_scanner.retry import FOLLOW_REDIRECTS, VERIFY_TLS, with_retry
from posint_scanner.sources.portscan import TLS_PORTS

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 10
# Self-identifying UA, consistent with the rest of the project (shodan_web) -
# deliberately not a spoofed browser string, and never the user's email.
USER_AGENT = "posint-scanner/0.1 (+web technology fingerprint)"
# Cap the body we read/scan. Fingerprints live in the <head> and early markup;
# reading a whole multi-megabyte page (or a non-HTML download served on an
# open port) buys nothing and risks pulling a lot over the wire.
MAX_HTML_BYTES = 512 * 1024

# The category names below are informational (grouped in the report); only
# "web-server" is load-bearing - it's how the stage decides which fingerprint
# is the service's product for the CVE lookup.
_WEB_SERVER_CATEGORY = "web-server"

# TLS verification is off project-wide (see retry.VERIFY_TLS) - scanning
# against self-signed / hostname-mismatched certs is expected on infrastructure
# discovered by IP. The InsecureRequestWarning is silenced there too.


@dataclass(frozen=True)
class TechFingerprint:
    """One technology's detection rules. A regex's first capture group, when
    it has one and it matched, is taken as the version. `implies` names other
    technologies whose presence is guaranteed by this one (e.g. WordPress
    implies PHP + MySQL) - they're added even when not independently matched,
    with no version.

    `cpe` lists NVD CPE-dictionary "vendor:product" candidates. NVD's
    cpeName lookup only matches exact dictionary entries, so the vendor must
    be right (nginx is `f5:nginx`, not `nginx:nginx` - the vendor==product
    guess returns zero CVEs). Several candidates where NVD has filed a product
    under more than one vendor over time; all are checked.

    `version_html` patterns are consulted only to fill in a version once the
    technology has already been detected (by a header/cookie/html/`version_header`
    signal). This lets a shared, non-distinctive version marker be used for its
    version without it also triggering detection - e.g. Atlassian's
    `ajs-version-number` meta appears on both Jira and Confluence, so it can't
    be a detection pattern for either, but it is each one's version once the
    product's own header identifies which it is.

    `version_header` is the same idea for a header: consulted for the version
    only after detection, never for detection itself."""

    name: str
    categories: tuple[str, ...]
    headers: tuple[tuple[str, re.Pattern[str]], ...] = ()
    cookies: tuple[re.Pattern[str], ...] = ()
    html: tuple[re.Pattern[str], ...] = ()
    version_header: tuple[tuple[str, re.Pattern[str]], ...] = ()
    version_html: tuple[re.Pattern[str], ...] = ()
    implies: tuple[str, ...] = field(default=())
    cpe: tuple[str, ...] = ()


def _fp(
    name: str,
    categories: list[str],
    *,
    headers: dict[str, str] | None = None,
    cookies: list[str] | None = None,
    html: list[str] | None = None,
    version_header: dict[str, str] | None = None,
    version_html: list[str] | None = None,
    implies: list[str] | None = None,
    cpe: list[str] | None = None,
) -> TechFingerprint:
    """Compile a fingerprint from raw regex strings. Header names are matched
    case-insensitively (stored lowercased); every pattern is IGNORECASE."""
    return TechFingerprint(
        name=name,
        categories=tuple(categories),
        headers=tuple(
            (h.lower(), re.compile(p, re.IGNORECASE)) for h, p in (headers or {}).items()
        ),
        cookies=tuple(re.compile(p, re.IGNORECASE) for p in (cookies or [])),
        html=tuple(re.compile(p, re.IGNORECASE) for p in (html or [])),
        version_header=tuple(
            (h.lower(), re.compile(p, re.IGNORECASE)) for h, p in (version_header or {}).items()
        ),
        version_html=tuple(re.compile(p, re.IGNORECASE) for p in (version_html or [])),
        implies=tuple(implies or []),
        cpe=tuple(cpe or []),
    )


# Curated ruleset. `(?:...([\d.]+))?` groups make the version optional: the
# technology is still detected when only its name (no version) is exposed.
_FINGERPRINTS: tuple[TechFingerprint, ...] = (
    # -- web servers --------------------------------------------------------
    _fp("nginx", ["web-server"], headers={"server": r"nginx(?:/([\d.]+))?"}, cpe=["f5:nginx", "nginx:nginx"]),
    _fp("Apache", ["web-server"], headers={"server": r"Apache(?:/([\d.]+))?"}, cpe=["apache:http_server"]),
    _fp("Microsoft IIS", ["web-server"], headers={"server": r"(?:Microsoft-)?IIS/([\d.]+)"}, cpe=["microsoft:internet_information_services"]),
    _fp("LiteSpeed", ["web-server"], headers={"server": r"LiteSpeed"}, cpe=["litespeedtech:litespeed_web_server"]),
    _fp("Caddy", ["web-server"], headers={"server": r"Caddy"}, cpe=["caddyserver:caddy"]),
    _fp("OpenResty", ["web-server"], headers={"server": r"openresty(?:/([\d.]+))?"}, implies=["nginx"], cpe=["openresty:openresty"]),
    _fp("Apache Tomcat", ["web-server"], headers={"server": r"(?:Apache-Coyote|Tomcat)(?:/([\d.]+))?"}, cpe=["apache:tomcat"]),
    _fp("Jetty", ["web-server"], headers={"server": r"Jetty(?:[/(]([\d.]+))?"}, cpe=["eclipse:jetty"]),
    _fp("Werkzeug", ["web-server"], headers={"server": r"Werkzeug(?:/([\d.]+))?"}, implies=["Python"], cpe=["palletsprojects:werkzeug"]),
    _fp("Gunicorn", ["web-server"], headers={"server": r"gunicorn(?:/([\d.]+))?"}, implies=["Python"], cpe=["gunicorn:gunicorn"]),
    _fp("uvicorn", ["web-server"], headers={"server": r"uvicorn"}, implies=["Python"]),
    _fp("Kestrel", ["web-server"], headers={"server": r"Kestrel"}),
    _fp("Envoy", ["web-server"], headers={"server": r"envoy"}, cpe=["envoyproxy:envoy"]),
    # -- languages / runtimes ----------------------------------------------
    _fp("PHP", ["programming-language"],
        headers={"x-powered-by": r"PHP/([\d.]+)"}, cookies=[r"^PHPSESSID$"], cpe=["php:php"]),
    _fp("ASP.NET", ["web-framework"],
        headers={"x-powered-by": r"ASP\.NET", "x-aspnet-version": r"([\d.]+)"},
        cookies=[r"^ASP\.NET_SessionId$"], cpe=["microsoft:.net_framework"]),
    _fp("Java", ["programming-language"], cookies=[r"^JSESSIONID$"]),
    _fp("Python", ["programming-language"]),
    _fp("Node.js", ["programming-language"], headers={"x-powered-by": r"Express"}, cpe=["nodejs:node.js"]),
    # -- web frameworks -----------------------------------------------------
    _fp("Express", ["web-framework"], headers={"x-powered-by": r"Express"}, implies=["Node.js"], cpe=["expressjs:express", "openjsf:express"]),
    _fp("Laravel", ["web-framework"], cookies=[r"^laravel_session$", r"^XSRF-TOKEN$"], implies=["PHP"], cpe=["laravel:framework"]),
    _fp("Django", ["web-framework"], cookies=[r"^csrftoken$", r"^django_language$"], implies=["Python"], cpe=["djangoproject:django"]),
    _fp("Ruby on Rails", ["web-framework"],
        headers={"x-powered-by": r"Phusion Passenger"}, cookies=[r"^_rails", r"session_id"], cpe=["rubyonrails:rails"]),
    _fp("Next.js", ["web-framework"],
        headers={"x-powered-by": r"Next\.js(?:\s*([\d.]+))?"},
        html=[r'id="__next"'], implies=["React", "Node.js"], cpe=["vercel:next.js", "zeit:next.js"]),
    # -- CMS ----------------------------------------------------------------
    _fp("WordPress", ["cms"],
        html=[r'<meta name="generator" content="WordPress ?([\d.]+)?', r"/wp-(?:content|includes)/"],
        implies=["PHP"], cpe=["wordpress:wordpress"]),
    _fp("Drupal", ["cms"],
        headers={"x-generator": r"Drupal(?:\s*([\d.]+))?", "x-drupal-cache": r".+"},
        html=[r'<meta name="Generator" content="Drupal ?([\d.]+)?'], implies=["PHP"], cpe=["drupal:drupal"]),
    _fp("Joomla", ["cms"],
        html=[r'<meta name="generator" content="Joomla! ?-? ?([\d.]+)?'], implies=["PHP"], cpe=["joomla:joomla\\!"]),
    # -- JS libraries -------------------------------------------------------
    _fp("jQuery", ["javascript-library"],
        html=[r"jquery[.-]([\d.]+)(?:\.min)?\.js", r"/jquery/([\d.]+)/"], cpe=["jquery:jquery"]),
    _fp("React", ["javascript-library"], html=[r'data-reactroot', r"react(?:-dom)?[.-]([\d.]+)"], cpe=["facebook:react"]),
    _fp("Vue.js", ["javascript-library"], html=[r"vue[.-]([\d.]+)(?:\.min)?\.js", r'data-v-[0-9a-f]{8}'], cpe=["vuejs:vue.js"]),
    _fp("Bootstrap", ["ui-framework"], html=[r"bootstrap[.-]([\d.]+)(?:\.min)?\.(?:css|js)"], cpe=["getbootstrap:bootstrap"]),
    # -- self-hosted applications ------------------------------------------
    # These print their own version in the page body or a custom header -
    # visiting the site and reading the HTML is the point (the version isn't
    # in the Server header). All are CVE-checked when a version is found.
    _fp("GeoServer", ["application"],
        # GeoServer serves its UI at /geoserver/web/ and its root 3xx's there;
        # redirects are followed, so the fingerprint sees that page like any
        # other. Version-capturing patterns first (the footer/link/plain forms
        # real pages use), then a bare-name fallback so a version-hidden
        # instance is still surfaced.
        html=[r"GeoServer[^<]*?(?:is running )?version\s*([\d.]+)",
              r"GeoServer</a>\s*v?\.?\s*([\d]+\.[\d]+(?:\.[\d]+)?)",
              r"GeoServer[\s/]+v?([\d]+\.[\d]+(?:\.[\d]+)?)",
              r"\bGeoServer\b"],
        cpe=["geoserver:geoserver", "osgeo:geoserver"]),
    _fp("Grafana", ["application"],
        headers={"x-grafana-version": r"([\d.]+)"},
        html=[r"Grafana v([\d.]+)", r'"grafanaVersion"\s*:\s*"([\d.]+)"'],
        cpe=["grafana:grafana"]),
    _fp("Jenkins", ["application"],
        headers={"x-jenkins": r"([\d.]+)"},
        html=[r"Jenkins ver\.?\s*([\d.]+)"], cpe=["jenkins:jenkins"]),
    _fp("GitLab", ["application"],
        headers={"x-gitlab-feature-category": r".+"},
        html=[r"GitLab (?:Community|Enterprise) Edition[^<]*?([\d.]+)"], cpe=["gitlab:gitlab"]),
    _fp("phpMyAdmin", ["application"],
        html=[r"phpMyAdmin[^<]*?([\d.]+)", r"PMA_VERSION[\"']?\s*[:=]\s*[\"']([\d.]+)"],
        implies=["PHP"], cpe=["phpmyadmin:phpmyadmin"]),
    _fp("Kibana", ["application"],
        headers={"kbn-version": r"([\d.]+)"}, cpe=["elastic:kibana", "elasticsearch:kibana"]),
    # Confluence and Jira share the `ajs-version-number` meta, so it can't be a
    # detection pattern for either (it'd cross-match). Each is detected by its
    # own header or product name, and the shared meta only fills the version.
    _fp("Confluence", ["application"],
        headers={"x-confluence-request-time": r".+"},
        html=[r"Atlassian Confluence(?:\s+([\d.]+))?"],
        version_html=[r'name="ajs-version-number" content="([\d.]+)"'],
        cpe=["atlassian:confluence"]),
    _fp("Jira", ["application"],
        headers={"x-arequestid": r".+"},
        html=[r"Atlassian Jira", r"JIRA[^<]*?\(v([\d.]+)\)"],
        version_html=[r'name="ajs-version-number" content="([\d.]+)"'],
        cpe=["atlassian:jira"]),
    _fp("Elasticsearch", ["application", "database"],
        # The root JSON's tagline is distinctive; the version key is consulted
        # only after that (version_html), so unrelated JSON can't false-match.
        html=[r'"tagline"\s*:\s*"You Know, for Search"'],
        version_html=[r'"number"\s*:\s*"([\d.]+)"'],
        cpe=["elastic:elasticsearch", "elasticsearch:elasticsearch"]),
    # -- CDN / proxy --------------------------------------------------------
    _fp("Cloudflare", ["cdn"], headers={"server": r"cloudflare", "cf-ray": r".+"}),
    _fp("Varnish", ["caching"], headers={"via": r"varnish", "x-varnish": r".+"}, cpe=["varnish-software:varnish_cache", "varnish-cache:varnish"]),
    _fp("Amazon CloudFront", ["cdn"], headers={"x-amz-cf-id": r".+", "via": r"CloudFront"}),
    _fp("Fastly", ["cdn"], headers={"x-served-by": r"cache-", "x-fastly-request-id": r".+"}),
)

_BY_NAME = {fp.name: fp for fp in _FINGERPRINTS}


def _version_from_match(match: re.Match[str]) -> str | None:
    """A fingerprint regex's first capture group is its version, when it has
    one and it actually captured (optional groups can match nothing)."""
    if match.re.groups >= 1:
        return match.group(1)
    return None


def _match_patterns(
    patterns: tuple[re.Pattern[str], ...], text: str
) -> tuple[bool, str | None]:
    matched = False
    version = None
    for pattern in patterns:
        found = pattern.search(text)
        if found is None:
            continue
        matched = True
        version = version or _version_from_match(found)
    return matched, version


def fingerprint(
    headers: dict[str, str], cookie_names: list[str], html: str
) -> dict[str, str | None]:
    """Match every fingerprint against one response and return {technology:
    version-or-None}. `headers` keys must be lowercased; `cookie_names` is the
    set of Set-Cookie names seen (across redirects). Best-effort and total -
    it never raises on odd input, it just detects less."""
    detected: dict[str, str | None] = {}

    for fp in _FINGERPRINTS:
        matched = False
        version: str | None = None

        for header_name, pattern in fp.headers:
            value = headers.get(header_name)
            if value is None:
                continue
            found = pattern.search(value)
            if found is not None:
                matched = True
                version = version or _version_from_match(found)

        for pattern in fp.cookies:
            if any(pattern.search(name) for name in cookie_names):
                matched = True

        html_matched, html_version = _match_patterns(fp.html, html)
        matched = matched or html_matched
        version = version or html_version

        if matched:
            # Only now that the tech is confirmed present, consult the
            # version-only patterns to fill a still-missing version. These
            # never influence detection (see TechFingerprint), so a shared or
            # non-distinctive version marker can't cause a false positive.
            if version is None:
                for header_name, pattern in fp.version_header:
                    value = headers.get(header_name)
                    found = pattern.search(value) if value is not None else None
                    if found is not None:
                        version = _version_from_match(found)
                        break
            if version is None:
                _, version = _match_patterns(fp.version_html, html)
            detected[fp.name] = version

    # Add implied technologies not already detected on their own, with no
    # version. A tech that was detected directly keeps whatever version it
    # found rather than being clobbered by an implication.
    for name in list(detected):
        for implied in _BY_NAME[name].implies if name in _BY_NAME else ():
            detected.setdefault(implied, None)

    return detected


def _categories_of(name: str) -> tuple[str, ...]:
    fp = _BY_NAME.get(name)
    return fp.categories if fp else ()


def cpes_for(name: str, version: str | None) -> list[str]:
    """Full CPE 2.3 names to check NVD against for one detected technology.
    Empty when there's no version (a versionless CPE would match every CVE
    ever filed against the product) or no known vendor:product mapping."""
    fp = _BY_NAME.get(name)
    if not version or fp is None:
        return []
    return [f"cpe:2.3:a:{vendor_product}:{version}:*:*:*:*:*:*:*" for vendor_product in fp.cpe]


def pick_server_product(technologies: dict[str, str | None]) -> tuple[str | None, str | None]:
    """Choose the one web-server technology to attribute to the service row
    (product, version) so the NVD stage can build a CPE and look up CVEs.
    Returns (None, None) when nothing web-server-ish was detected."""
    for name, version in technologies.items():
        if _WEB_SERVER_CATEGORY in _categories_of(name):
            return name, version
    return None, None


class WebTechFingerprinter:
    """Stateless HTTP fingerprint client. Holds only read-only config, so one
    instance is shared across the whole (thread-pooled) scan the same way
    NvdClient is - there's no per-machine rate limit to serialize here (each
    request goes to a different target host), so no lock is needed."""

    def __init__(self, timeout: int = TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    @with_retry
    def _get(self, url: str) -> requests.Response:
        return requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=self.timeout,
            # Follow redirects (project default): a bare host/port routinely
            # 3xx's to where the app actually lives, and that final response is
            # what carries the fingerprint and version.
            allow_redirects=FOLLOW_REDIRECTS,
            verify=VERIFY_TLS,
            stream=True,
        )

    def fetch(self, url: str) -> tuple[int, str, dict[str, str], list[str], str] | None:
        """GET `url`, following redirects, and return (status, final-url,
        lowercased-headers, cookie-names, html), or None if it isn't reachable /
        isn't speaking HTTP. `final-url` is where the redirect chain landed (the
        app's real location). Reads at most MAX_HTML_BYTES of body. Never raises
        - a port that isn't a web server is an expected, logged-at-debug
        non-result, not an error."""
        try:
            with self._get(url) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                # Cookies set anywhere in the redirect chain, not just the
                # final hop - a framework's session cookie is often set on the
                # first response before a redirect to a login page.
                cookie_names = [cookie.name for cookie in response.cookies]
                for hop in response.history:
                    cookie_names.extend(cookie.name for cookie in hop.cookies)
                raw = response.raw.read(MAX_HTML_BYTES, decode_content=True)
                html = raw.decode(response.encoding or "utf-8", errors="replace")
                final_url = str(response.url) or url
                return response.status_code, final_url, headers, cookie_names, html
        except (requests.RequestException, OSError, ValueError) as exc:
            logger.debug("webtech: %s not fingerprintable: %s", url, exc)
            return None

    def scan_service(
        self, ip: str, port: int, protocol: str, hostnames: list[str]
    ) -> dict | None:
        """Fingerprint one open service. Fetches by hostname when one is known
        (so name-based virtual hosts serve the right site), falling back to the
        IP. Redirects are followed, so an app served off a subpath (its root
        3xx'ing to e.g. /app/web/) is fingerprinted at wherever it lands - no
        per-app path list. Returns a result dict for persistence, or None if
        the port didn't answer as a web server."""
        if protocol != "tcp":
            return None

        host = hostnames[0] if hostnames else ip
        # Guess the scheme from the port, then try the other one if that
        # fails - HTTPS commonly runs on non-standard ports and vice versa.
        primary = "https" if port in TLS_PORTS else "http"
        alternate = "http" if primary == "https" else "https"

        for scheme in (primary, alternate):
            fetched = self.fetch(f"{scheme}://{host}:{port}/")
            if fetched is None:
                continue
            status, final_url, headers, cookie_names, html = fetched
            technologies = fingerprint(headers, cookie_names, html)
            if not technologies:
                return None
            product, version = pick_server_product(technologies)
            return {
                "url": final_url,
                "status": status,
                "technologies": technologies,
                "categories": {
                    name: list(_categories_of(name)) for name in technologies
                },
                # Only versioned technologies with a known CPE mapping - what
                # the vuln lookup stage checks against NVD.
                "cpes": {
                    name: cpes
                    for name, tech_version in technologies.items()
                    if (cpes := cpes_for(name, tech_version))
                },
                "server_product": product,
                "server_version": version,
            }
        return None
