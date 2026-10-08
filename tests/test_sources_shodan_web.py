import pytest
import time
from unittest.mock import Mock, patch

from posint_scanner.sources.base import ScrapeParseError
from posint_scanner.sources.shodan_web import (
    MIN_REQUEST_INTERVAL_SECONDS,
    ShodanWebSource,
    parse_shodan_domain_page,
    parse_shodan_host_page,
)

HOST_HTML = """
<html><body>
<div class="host-grid">
  <div class="left-column">
    <div class="card"><a name="general"></a>
      <div class="grid-table">
<label>Hostnames</label>
<div class="font-mono">

tst-27.aws.<b>agilent.com</b><br/>
<b>dns.google</b>
</div>
          <label>Domains</label>
          <div class="domains"><a href="/domain/agilent.com" class="font-mono">agilent.com</a><a href="/domain/dns.google" class="font-mono">dns.google</a>
          </div>
<label>Country</label>
<div><strong><a href="#" class="text-dark">United States</a></strong>
</div>
<label>City</label>
<div><strong><a href="#" class="text-dark">Mountain View</a></strong>
</div>
<label>Organization</label>
<div><strong><a href="#" class="text-dark">Google LLC</a></strong>
</div>
<label>ISP</label>
<div><strong><a href="#" class="text-dark">Google LLC</a></strong>
</div>
<label>ASN</label>
<div><strong><a href="#" class="text-dark">AS15169</a></strong>
</div>
      </div>
    </div>
  </div>
  <div class="right-column">
    <div id="ports"><a href="#53">53</a><a href="#443">443</a></div><a name="53"></a>
<h6 id="53" class="grid-heading">
  <div class="flex gap-1.5"><span data-clipboard="8.8.8.8:53" class="tooltip"><strong>53</strong> /
tcp</span>
  </div>
</h6>
<div class="card card-padding banner">
  <pre>
Recursion: enabled</pre>
</div><a name="53"></a>
<h6 id="53" class="grid-heading">
  <div class="flex gap-1.5"><span data-clipboard="8.8.8.8:53" class="tooltip"><strong>53</strong> /
udp</span>
  </div>
</h6>
<div class="card card-padding banner">
  <pre>
Recursion: enabled</pre>
</div><a name="443"></a>
<h6 id="443" class="grid-heading">
  <div class="flex gap-1.5"><span data-clipboard="8.8.8.8:443" class="tooltip"><strong>443</strong> /
tcp</span>
  </div>
</h6>
<div class="card card-padding banner">
  <pre>HTTP/1.1 200 OK
Server: nginx</pre>
</div>
  </div>
</div>
</body></html>
"""

# The Vulnerabilities card is built client-side and omitted from the page
# entirely when a host has no known vulns (see HOST_HTML above, which has
# none). As observed on a real host with vulns, the data is assigned to a
# local `const VULNS = {...}` and `setupVulns(VULNS)` is called with the
# bare variable name, not an inline object literal.
_VULNS_CONST_SCRIPT = (
    "<script>(() => {\n"
    '    const VULNS = {"CVE-2025-23419":{"cvss":5.3,"ports":[80,443],'
    '"summary":"session resumption can bypass client cert auth","verified":false},'
    '"CVE-2021-23017":{"cvss":7.7,"ports":[80,443],'
    '"summary":"nginx resolver 1-byte memory overwrite","verified":false}};\n'
    "    setupBannerCve();\n"
    "    setupVulns(VULNS);\n"
    "})();</script>\n"
)
HOST_HTML_WITH_VULNS = HOST_HTML.replace("</body></html>", _VULNS_CONST_SCRIPT + "</body></html>")

# Kept as a fallback pattern in _parse_vulns in case Shodan ever inlines
# the object directly into the call instead of via a `const VULNS` local.
_VULNS_INLINE_SCRIPT = (
    '<script>setupVulns({"CVE-2021-44228": {"ports": [443], "cvss": 10.0, '
    '"summary": "Log4Shell RCE"}});</script>\n'
)
HOST_HTML_WITH_INLINE_VULNS = HOST_HTML.replace(
    "</body></html>", _VULNS_INLINE_SCRIPT + "</body></html>"
)

# A service Shodan has fingerprinted a product/version for (observed on a
# real host: nginx on port 80) - the banner card gets a `.banner-title`
# ahead of the raw <pre> response text.
HOST_HTML_WITH_PRODUCT = """
<html><body>
<div class="host-grid">
  <div class="right-column">
    <div id="ports"><a href="#80">80</a></div><a name="80"></a>
<h6 id="80" class="grid-heading">
  <div class="flex gap-1.5"><span data-clipboard="212.91.231.250:80" class="tooltip"><strong>80</strong> /
tcp</span>
  </div>
</h6>
<div class="card card-padding banner">
  <h1 class="banner-title"><a href="/search?query=product%3A%22nginx%22" class="text-dark"><em>nginx</em></a><a href="/search?query=product%3A%22nginx%22+version%3A%221.18.0%22" class="text-secondary"><span>1.18.0</span></a>
  </h1>
  <pre>HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0</pre>
</div>
  </div>
</div>
</body></html>
"""

DOMAIN_HTML = """
<html><body>
<div class="domain-grid">
  <div>
    <table class="u-full-width">
      <tbody>
        <tr><td></td><td>A</td><td><strong><a href="/host/1.2.3.4">1.2.3.4</a></strong></td></tr>
        <tr><td>www</td><td>A</td><td><strong><a href="/host/1.2.3.5">1.2.3.5</a></strong></td></tr>
      </tbody>
    </table>
  </div>
  <div>
    <ul id="subdomains">
      <li>www</li>
      <li>mail</li>
    </ul>
  </div>
</div>
</body></html>
"""


class TestParseShodanHostPage:
    def test_extracts_hostnames_split_on_br(self):
        result = parse_shodan_host_page(HOST_HTML, "8.8.8.8")
        assert result.data["hostnames"] == ["tst-27.aws.agilent.com", "dns.google"]

    def test_extracts_domains(self):
        result = parse_shodan_host_page(HOST_HTML, "8.8.8.8")
        assert result.data["domains"] == ["agilent.com", "dns.google"]

    def test_extracts_general_info_fields(self):
        result = parse_shodan_host_page(HOST_HTML, "8.8.8.8")
        assert result.data["country"] == "United States"
        assert result.data["city"] == "Mountain View"
        assert result.data["organization"] == "Google LLC"
        assert result.data["isp"] == "Google LLC"
        assert result.data["asn"] == "AS15169"

    def test_extracts_services_with_protocol_and_banner(self):
        result = parse_shodan_host_page(HOST_HTML, "8.8.8.8")
        by_proto = {(s.port, s.protocol): s.banner for s in result.services}
        assert by_proto[(53, "tcp")] == "Recursion: enabled"
        assert by_proto[(53, "udp")] == "Recursion: enabled"
        assert by_proto[(443, "tcp")] == "HTTP/1.1 200 OK\nServer: nginx"

    def test_target_type_and_source(self):
        result = parse_shodan_host_page(HOST_HTML, "8.8.8.8")
        assert result.source == "shodan_web"
        assert result.target_type == "ip"
        assert result.target == "8.8.8.8"

    def test_missing_fields_default_to_none(self):
        result = parse_shodan_host_page("<html><body></body></html>", "1.2.3.4")
        assert result.data["country"] is None
        assert result.data["hostnames"] == []
        assert result.services == []

    def test_no_vulns_script_gives_empty_vulns_dict(self):
        result = parse_shodan_host_page(HOST_HTML, "8.8.8.8")
        assert result.data["vulns"] == {}

    def test_extracts_vulns_from_const_vulns_assignment(self):
        result = parse_shodan_host_page(HOST_HTML_WITH_VULNS, "212.91.231.250")
        vulns = result.data["vulns"]
        assert set(vulns) == {"CVE-2025-23419", "CVE-2021-23017"}
        assert vulns["CVE-2025-23419"]["cvss"] == 5.3
        assert vulns["CVE-2025-23419"]["ports"] == [80, 443]
        assert vulns["CVE-2025-23419"]["verified"] is False
        assert "bypass" in vulns["CVE-2025-23419"]["summary"]

    def test_vulns_ports_tie_a_cve_to_its_affected_service(self):
        result = parse_shodan_host_page(HOST_HTML_WITH_VULNS, "212.91.231.250")
        vulns = result.data["vulns"]
        assert vulns["CVE-2021-23017"]["ports"] == [80, 443]

    def test_falls_back_to_inline_setupvulns_literal(self):
        result = parse_shodan_host_page(HOST_HTML_WITH_INLINE_VULNS, "8.8.8.8")
        vulns = result.data["vulns"]
        assert set(vulns) == {"CVE-2021-44228"}
        assert vulns["CVE-2021-44228"]["cvss"] == 10.0

    def test_uses_banner_title_product_and_version_when_fingerprinted(self):
        result = parse_shodan_host_page(HOST_HTML_WITH_PRODUCT, "212.91.231.250")
        service = result.services[0]
        assert service.banner == "nginx"
        assert service.version == "1.18.0"

    def test_malformed_setupvulns_json_falls_back_to_empty_dict(self):
        html = HOST_HTML.replace(
            "</body></html>", "<script>setupVulns({not valid json});</script></body></html>"
        )
        result = parse_shodan_host_page(html, "8.8.8.8")
        assert result.data["vulns"] == {}


class TestParseShodanDomainPage:
    def test_extracts_subdomains_list(self):
        result = parse_shodan_domain_page(DOMAIN_HTML, "example.com")
        names = {h.name for h in result}
        assert "www.example.com" in names
        assert "mail.example.com" in names

    def test_extracts_dns_table_labels_including_apex(self):
        result = parse_shodan_domain_page(DOMAIN_HTML, "example.com")
        names = {h.name for h in result}
        assert "example.com" in names

    def test_dedupes_across_table_and_subdomain_list(self):
        result = parse_shodan_domain_page(DOMAIN_HTML, "example.com")
        names = [h.name for h in result]
        assert names.count("www.example.com") == 1

    def test_source_tagged_shodan_web(self):
        result = parse_shodan_domain_page(DOMAIN_HTML, "example.com")
        assert all(h.source == "shodan_web" for h in result)

    def test_empty_page_returns_empty_list(self):
        assert parse_shodan_domain_page("<html><body></body></html>", "example.com") == []


class TestShodanWebSourceEnrich:
    def test_calls_host_url(self):
        source = ShodanWebSource()
        response = Mock(status_code=200, text=HOST_HTML)
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response) as mock_get:
            result = source.enrich("8.8.8.8", [])
        url = mock_get.call_args[0][0]
        assert "8.8.8.8" in url
        assert result.target == "8.8.8.8"

    def test_sends_user_agent_header(self):
        source = ShodanWebSource()
        response = Mock(status_code=200, text=HOST_HTML)
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response) as mock_get:
            source.enrich("8.8.8.8", [])
        headers = mock_get.call_args[1]["headers"]
        assert "User-Agent" in headers

    def test_host_hostnames_are_related_hostnames(self):
        response = Mock(status_code=200, text=HOST_HTML)
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            result = ShodanWebSource().enrich("8.8.8.8", [])
        assert result.related_hostnames == ["tst-27.aws.agilent.com", "dns.google"]

    def test_page_with_none_of_the_expected_fields_is_a_parse_error(self):
        response = Mock(status_code=200, text="<html><body>redesigned</body></html>")
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response):
            with pytest.raises(ScrapeParseError):
                ShodanWebSource().enrich("8.8.8.8", [])

    def test_404_returns_empty_result_without_raising(self):
        source = ShodanWebSource()
        response = Mock(status_code=404, text="")
        with patch("requests.get", return_value=response):
            result = source.enrich("9.9.9.9", [])
        assert result.data == {}
        assert result.services == []


class TestShodanWebSourceDiscover:
    def test_calls_domain_url(self):
        source = ShodanWebSource()
        response = Mock(status_code=200, text=DOMAIN_HTML)
        response.raise_for_status = Mock()
        with patch("requests.get", return_value=response) as mock_get:
            result = source.discover("example.com")
        url = mock_get.call_args[0][0]
        assert "example.com" in url
        assert any(h.name == "example.com" for h in result)

    def test_404_returns_empty_list(self):
        source = ShodanWebSource()
        response = Mock(status_code=404, text="")
        with patch("requests.get", return_value=response):
            result = source.discover("nonexistent.example")
        assert result == []


class TestShodanWebSourceRateLimiting:
    # Sets `_last_request_at` directly (rather than mocking time.monotonic
    # globally) since tenacity's own retry bookkeeping calls
    # time.monotonic() too, on the same global `time` module - a global
    # patch would also feed tenacity, making call counts an implementation
    # detail this test would be coupled to.
    def test_second_request_waits_for_crawl_delay(self):
        source = ShodanWebSource()
        source._last_request_at = time.monotonic() - 1.0
        response = Mock(status_code=200, text=HOST_HTML)
        response.raise_for_status = Mock()

        with patch("requests.get", return_value=response):
            with patch("time.sleep") as mock_sleep:
                source.enrich("8.8.8.8", [])

        assert mock_sleep.call_count == 1
        slept = mock_sleep.call_args[0][0]
        assert MIN_REQUEST_INTERVAL_SECONDS - 1.5 < slept <= MIN_REQUEST_INTERVAL_SECONDS

    def test_no_wait_when_interval_already_elapsed(self):
        source = ShodanWebSource()
        source._last_request_at = time.monotonic() - (MIN_REQUEST_INTERVAL_SECONDS + 5)
        response = Mock(status_code=200, text=HOST_HTML)
        response.raise_for_status = Mock()

        with patch("requests.get", return_value=response):
            with patch("time.sleep") as mock_sleep:
                source.enrich("8.8.8.8", [])

        mock_sleep.assert_not_called()
