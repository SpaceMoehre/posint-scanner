from unittest.mock import patch

import requests

from posint_scanner.sources.webtech import (
    WebTechFingerprinter,
    cpes_for,
    fingerprint,
    pick_server_product,
)


class TestFingerprint:
    def test_server_header_product_and_version(self):
        techs = fingerprint({"server": "nginx/1.18.0"}, [], "")
        assert techs == {"nginx": "1.18.0"}

    def test_server_header_without_version(self):
        techs = fingerprint({"server": "nginx"}, [], "")
        assert techs == {"nginx": None}

    def test_x_powered_by_php_version(self):
        techs = fingerprint({"x-powered-by": "PHP/8.2.4"}, [], "")
        assert techs["PHP"] == "8.2.4"

    def test_header_match_is_case_insensitive(self):
        # real responses vary Server casing; headers arrive already lowercased
        # from fetch(), but the value regex itself must be case-insensitive too
        techs = fingerprint({"server": "APACHE/2.4.52"}, [], "")
        assert techs == {"Apache": "2.4.52"}

    def test_iis_version(self):
        techs = fingerprint({"server": "Microsoft-IIS/10.0"}, [], "")
        assert techs["Microsoft IIS"] == "10.0"

    def test_cookie_detects_framework(self):
        techs = fingerprint({}, ["laravel_session"], "")
        assert "Laravel" in techs
        assert techs["Laravel"] is None

    def test_php_session_cookie(self):
        techs = fingerprint({}, ["PHPSESSID"], "")
        assert "PHP" in techs

    def test_meta_generator_wordpress_version(self):
        html = '<meta name="generator" content="WordPress 6.4.2" />'
        techs = fingerprint({}, [], html)
        assert techs["WordPress"] == "6.4.2"

    def test_wordpress_wp_content_path_without_version(self):
        techs = fingerprint({}, [], '<link href="/wp-content/themes/x/style.css">')
        assert techs["WordPress"] is None

    def test_jquery_version_from_script_src(self):
        html = '<script src="/js/jquery-3.6.0.min.js"></script>'
        techs = fingerprint({}, [], html)
        assert techs["jQuery"] == "3.6.0"

    def test_bootstrap_version(self):
        html = '<link rel="stylesheet" href="/css/bootstrap-5.3.2.min.css">'
        techs = fingerprint({}, [], html)
        assert techs["Bootstrap"] == "5.3.2"

    def test_cloudflare_cdn(self):
        techs = fingerprint({"server": "cloudflare", "cf-ray": "abc123-FRA"}, [], "")
        assert "Cloudflare" in techs

    def test_no_match_returns_empty(self):
        assert fingerprint({"server": "some-obscure-thing/1.0"}, ["RANDOMCOOKIE"], "<html></html>") == {}

    def test_implies_adds_php_for_wordpress(self):
        techs = fingerprint({}, [], '<meta name="generator" content="WordPress 6.4.2" />')
        assert techs["PHP"] is None  # implied, no version

    def test_implies_does_not_clobber_directly_detected_version(self):
        # WordPress implies PHP; an explicit PHP version header must survive
        html = '<meta name="generator" content="WordPress 6.4.2" />'
        techs = fingerprint({"x-powered-by": "PHP/8.2.4"}, [], html)
        assert techs["PHP"] == "8.2.4"

    def test_express_implies_nodejs(self):
        techs = fingerprint({"x-powered-by": "Express"}, [], "")
        assert "Express" in techs
        assert techs["Node.js"] is None

    def test_openresty_version_and_implies_nginx(self):
        techs = fingerprint({"server": "openresty/1.21.4.1"}, [], "")
        assert techs["OpenResty"] == "1.21.4.1"
        assert "nginx" in techs

    def test_multiple_technologies_on_one_response(self):
        techs = fingerprint(
            {"server": "nginx/1.25.3", "x-powered-by": "PHP/8.1.0"},
            ["PHPSESSID"],
            '<script src="/jquery-3.7.1.min.js"></script>',
        )
        assert techs["nginx"] == "1.25.3"
        assert techs["PHP"] == "8.1.0"
        assert techs["jQuery"] == "3.7.1"


class TestPickServerProduct:
    def test_picks_web_server_over_library(self):
        product, version = pick_server_product({"jQuery": "3.6.0", "nginx": "1.18.0"})
        assert (product, version) == ("nginx", "1.18.0")

    def test_none_when_no_web_server(self):
        assert pick_server_product({"jQuery": "3.6.0", "PHP": "8.2.4"}) == (None, None)

    def test_empty(self):
        assert pick_server_product({}) == (None, None)


def _fake_response(status=200, headers=None, cookies=None, body=b"", history=None,
                   encoding="utf-8", url="http://1.2.3.4/"):
    """A stand-in for requests.Response supporting the exact surface fetch()
    uses: context-manager, .headers, .cookies (name-bearing), .history,
    .raw.read(n, decode_content=...), .encoding, .status_code."""

    class _Cookie:
        def __init__(self, name):
            self.name = name

    class _Raw:
        def __init__(self, data):
            self._data = data

        def read(self, amt, decode_content=True):
            return self._data[:amt]

    class _Resp:
        def __init__(self):
            self.status_code = status
            self.headers = headers or {}
            self.cookies = [_Cookie(n) for n in (cookies or [])]
            self.history = history or []
            self.raw = _Raw(body)
            self.encoding = encoding
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return _Resp()


class TestFetch:
    def test_fetch_returns_lowercased_headers_and_body(self):
        fp = WebTechFingerprinter()
        resp = _fake_response(
            headers={"Server": "nginx/1.18.0", "Content-Type": "text/html"},
            body=b"<html><body>hi</body></html>",
        )
        with patch("posint_scanner.sources.webtech.requests.get", return_value=resp):
            result = fp.fetch("http://1.2.3.4:80/")
        assert result is not None
        status, final_url, hdrs, cookies, html = result
        assert status == 200
        assert hdrs["server"] == "nginx/1.18.0"
        assert "hi" in html

    def test_fetch_reports_final_url_after_redirect(self):
        fp = WebTechFingerprinter()
        resp = _fake_response(body=b"ok", url="http://h/geoserver/web/")
        with patch("posint_scanner.sources.webtech.requests.get", return_value=resp):
            _, final_url, _, _, _ = fp.fetch("http://h/")
        assert final_url == "http://h/geoserver/web/"

    def test_get_follows_redirects(self):
        fp = WebTechFingerprinter()
        with patch("posint_scanner.sources.webtech.requests.get",
                   return_value=_fake_response()) as get:
            fp.fetch("http://h/")
        assert get.call_args.kwargs["allow_redirects"] is True

    def test_fetch_collects_cookies_across_redirects(self):
        fp = WebTechFingerprinter()
        hop = _fake_response(cookies=["laravel_session"])
        resp = _fake_response(cookies=["XSRF-TOKEN"], history=[hop])
        with patch("posint_scanner.sources.webtech.requests.get", return_value=resp):
            _, _, _, cookie_names, _ = fp.fetch("http://1.2.3.4/")
        assert "laravel_session" in cookie_names
        assert "XSRF-TOKEN" in cookie_names

    def test_fetch_returns_none_on_connection_error(self):
        fp = WebTechFingerprinter()
        with patch(
            "posint_scanner.sources.webtech.requests.get",
            side_effect=requests.ConnectionError("refused"),
        ):
            assert fp.fetch("http://1.2.3.4:22/") is None

    def test_fetch_caps_body_at_max_bytes(self):
        fp = WebTechFingerprinter()
        resp = _fake_response(body=b"x" * (2 * 1024 * 1024))
        with patch("posint_scanner.sources.webtech.requests.get", return_value=resp):
            _, _, _, _, html = fp.fetch("http://1.2.3.4/")
        assert len(html) <= 512 * 1024


class TestScanService:
    def test_scan_service_fingerprints_and_picks_product(self):
        fp = WebTechFingerprinter()
        resp = _fake_response(
            headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.2.4"},
            body=b"<html></html>",
            url="https://example.com:443/",
        )
        with patch("posint_scanner.sources.webtech.requests.get", return_value=resp):
            result = fp.scan_service("1.2.3.4", 443, "tcp", ["example.com"])
        assert result["url"] == "https://example.com:443/"
        assert result["technologies"]["nginx"] == "1.18.0"
        assert result["server_product"] == "nginx"
        assert result["server_version"] == "1.18.0"

    def test_scan_service_uses_ip_when_no_hostname(self):
        fp = WebTechFingerprinter()
        resp = _fake_response(headers={"Server": "Apache/2.4.52"}, body=b"",
                              url="http://1.2.3.4:80/")
        with patch("posint_scanner.sources.webtech.requests.get", return_value=resp):
            result = fp.scan_service("1.2.3.4", 80, "tcp", [])
        assert result["url"] == "http://1.2.3.4:80/"

    def test_scan_service_falls_back_to_alternate_scheme(self):
        fp = WebTechFingerprinter()
        good = _fake_response(headers={"Server": "nginx/1.20.0"}, body=b"")
        calls = []

        # port 8443 -> primary scheme https (fails) -> alternate http (succeeds)
        def fake_get(url, **kwargs):
            calls.append(url)
            if url.startswith("https://"):
                raise requests.ConnectionError("no tls here")
            return good

        with patch("posint_scanner.sources.webtech.requests.get", side_effect=fake_get):
            result = fp.scan_service("1.2.3.4", 8443, "tcp", [])
        assert result is not None
        assert calls[0].startswith("https://")
        assert result["url"].startswith("http://")

    def test_scan_service_returns_none_when_unreachable(self):
        fp = WebTechFingerprinter()
        with patch(
            "posint_scanner.sources.webtech.requests.get",
            side_effect=requests.ConnectionError("refused"),
        ):
            assert fp.scan_service("1.2.3.4", 22, "tcp", []) is None

    def test_scan_service_returns_none_when_nothing_fingerprinted(self):
        fp = WebTechFingerprinter()
        resp = _fake_response(headers={"Server": "totally-unknown/9"}, body=b"<html></html>")
        with patch("posint_scanner.sources.webtech.requests.get", return_value=resp):
            assert fp.scan_service("1.2.3.4", 80, "tcp", []) is None

    def test_scan_service_skips_non_tcp(self):
        fp = WebTechFingerprinter()
        assert fp.scan_service("1.2.3.4", 53, "udp", []) is None

    def test_scan_service_fingerprints_the_redirect_target(self):
        # geo.dns-net.de: the root 3xx's to /geoserver/web/. Redirect-following
        # (not a per-app path list) means the fingerprint sees that page, and
        # the result URL reflects where the app actually lives - no GeoServer-
        # specific handling anywhere.
        fp = WebTechFingerprinter()
        landed = _fake_response(
            headers={"Server": "Jetty(9.4.z)"},
            body=b'<div id="footer"><a href="https://geoserver.org">GeoServer</a> 2.23.1</div>',
            url="http://geo.dns-net.de:8080/geoserver/web/",
        )
        with patch("posint_scanner.sources.webtech.requests.get", return_value=landed):
            result = fp.scan_service("212.91.231.250", 8080, "tcp", ["geo.dns-net.de"])

        assert result is not None
        assert result["url"] == "http://geo.dns-net.de:8080/geoserver/web/"
        assert result["technologies"]["GeoServer"] == "2.23.1"
        assert "Jetty" in result["technologies"]  # server picked up too
        assert result["cpes"]["GeoServer"] == [
            "cpe:2.3:a:geoserver:geoserver:2.23.1:*:*:*:*:*:*:*",
            "cpe:2.3:a:osgeo:geoserver:2.23.1:*:*:*:*:*:*:*",
        ]


class TestCpesFor:
    def test_uses_real_nvd_vendor_not_product_guess(self):
        # NVD files nginx under f5 - the vendor==product guess finds nothing
        assert cpes_for("nginx", "1.18.0") == [
            "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        ]

    def test_non_server_technology(self):
        assert cpes_for("jQuery", "3.6.0") == ["cpe:2.3:a:jquery:jquery:3.6.0:*:*:*:*:*:*:*"]

    def test_no_version_means_no_cpe(self):
        # a versionless CPE would match every CVE ever filed for the product
        assert cpes_for("jQuery", None) == []

    def test_unmapped_or_unknown_technology(self):
        assert cpes_for("Cloudflare", "1.0") == []
        assert cpes_for("NotATech", "1.0") == []

    def test_scan_service_result_lists_cpes_for_every_versioned_tech(self):
        fp = WebTechFingerprinter()
        resp = _fake_response(
            headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.2.4"},
            body=b'<script src="/jquery-3.6.0.min.js"></script><link href="/wp-content/x.css">',
        )
        with patch("posint_scanner.sources.webtech.requests.get", return_value=resp):
            result = fp.scan_service("1.2.3.4", 80, "tcp", [])
        assert set(result["cpes"]) == {"nginx", "PHP", "jQuery"}  # WordPress: no version
        assert result["cpes"]["PHP"] == ["cpe:2.3:a:php:php:8.2.4:*:*:*:*:*:*:*"]


class TestApplicationVersionFingerprints:
    """Self-hosted apps that print their version in the page body - visiting
    the site and reading the HTML is the only way to get these."""

    def test_geoserver_version_from_body(self):
        html = '<html><body><div id="footer">GeoServer instance is running version 2.21.0</div></body></html>'
        techs = fingerprint({}, [], html)
        assert techs["GeoServer"] == "2.21.0"

    def test_geoserver_version_is_cve_checkable(self):
        # a versioned CPE is what the NVD stage looks up
        cpes = cpes_for("GeoServer", "2.21.0")
        assert cpes
        assert all("2.21.0" in c and "geoserver" in c for c in cpes)

    def test_geoserver_footer_link_version(self):
        # real welcome/login footer: <a href=...>GeoServer</a> 2.23.1
        html = '<div id="footer"><a href="https://geoserver.org">GeoServer</a> 2.23.1</div>'
        assert fingerprint({}, [], html)["GeoServer"] == "2.23.1"

    def test_geoserver_plain_name_space_version(self):
        assert fingerprint({}, [], "<title>GeoServer 2.24.1</title>")["GeoServer"] == "2.24.1"

    def test_geoserver_detected_without_a_parseable_version(self):
        # hardened installs hide the version; still worth surfacing the app
        techs = fingerprint({}, [], '<a href="/geoserver/web/">GeoServer</a>')
        assert "GeoServer" in techs and techs["GeoServer"] is None

    def test_grafana_version_from_meta(self):
        html = '<meta name="application-name" content="Grafana"/><div>Grafana v9.5.1 (abc)</div>'
        techs = fingerprint({}, [], html)
        assert techs["Grafana"] == "9.5.1"

    def test_jenkins_version_from_header(self):
        techs = fingerprint({"x-jenkins": "2.426.1"}, [], "")
        assert techs["Jenkins"] == "2.426.1"

    def test_confluence_and_jira_do_not_cross_match_on_shared_meta(self):
        # both apps carry <meta name="ajs-version-number"> - detection must key
        # on each product's own header, not the shared meta, or they'd both fire
        meta = '<meta name="ajs-version-number" content="8.5.4">'
        conf = fingerprint({"x-confluence-request-time": "12"}, [], meta)
        assert conf.get("Confluence") == "8.5.4"
        assert "Jira" not in conf

        jira = fingerprint({"x-arequestid": "abc"}, [], meta)
        assert jira.get("Jira") == "8.5.4"
        assert "Confluence" not in jira

    def test_shared_meta_alone_detects_neither(self):
        techs = fingerprint({}, [], '<meta name="ajs-version-number" content="8.5.4">')
        assert "Confluence" not in techs and "Jira" not in techs

    def test_confluence_version_from_powered_by_footer(self):
        techs = fingerprint({}, [], "<footer>Powered by Atlassian Confluence 7.19.1</footer>")
        assert techs["Confluence"] == "7.19.1"

    def test_elasticsearch_version_only_read_after_tagline_detection(self):
        body = '{"name":"n","version":{"number":"7.10.2"},"tagline":"You Know, for Search"}'
        assert fingerprint({}, [], body)["Elasticsearch"] == "7.10.2"
        # a stray "number" key without the tagline must not detect Elasticsearch
        assert "Elasticsearch" not in fingerprint({}, [], '{"number":"9.9.9"}')

    def test_new_servers_from_server_header(self):
        assert "uvicorn" in fingerprint({"server": "uvicorn"}, [], "")
        assert "Kestrel" in fingerprint({"server": "Kestrel"}, [], "")
        assert "Envoy" in fingerprint({"server": "envoy"}, [], "")

    def test_no_false_positive_on_plain_page(self):
        techs = fingerprint({}, [], "<html><body>welcome</body></html>")
        assert techs == {}
