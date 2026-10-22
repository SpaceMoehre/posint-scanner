from posint_scanner.sources.leakix import parse_events, parse_subdomains


def _host_payload():
    return {
        "Services": [
            {
                "event_type": "service",
                "event_source": "HTTPPlugin",
                "protocol": "https",
                "port": "443",
                "ip": "1.2.3.4",
                "host": "www.example.com",
                "reverse": "host.example.com",
                "service": {"software": {"name": "nginx", "version": "1.18.0"}},
                "ssl": {"certificate": {"domain": ["www.example.com", "api.example.com"]}},
                "summary": "nginx server",
            }
        ],
        "Leaks": [
            {
                "event_type": "leak",
                "event_source": "DotEnvConfigPlugin",
                "protocol": "https",
                "port": "443",
                "ip": "1.2.3.4",
                "host": "www.example.com",
                "leak": {"severity": "high"},
                "summary": "Exposed .env file with credentials",
            }
        ],
    }


class TestParseEvents:
    def test_extracts_services(self):
        services, _, _ = parse_events(_host_payload())
        assert len(services) == 1
        assert services[0].port == 443
        assert services[0].protocol == "https"
        assert services[0].banner == "nginx"
        assert services[0].version == "1.18.0"

    def test_leaks_become_findings(self):
        _, findings, _ = parse_events(_host_payload())
        assert len(findings) == 1
        assert findings[0]["id"] == "DotEnvConfigPlugin"
        assert findings[0]["severity"] == "high"
        assert "env" in findings[0]["title"].lower()

    def test_related_hostnames_from_host_reverse_and_cert(self):
        _, _, related = parse_events(_host_payload())
        assert {"www.example.com", "host.example.com", "api.example.com"} <= set(related)

    def test_bare_list_is_classified_by_event_type(self):
        payload = [
            {"event_type": "leak", "event_source": "GitConfigPlugin",
             "leak": {"severity": "medium"}, "summary": "exposed .git", "port": "80"},
            {"event_type": "service", "event_source": "HTTPPlugin", "port": "80",
             "service": {"software": {"name": "Apache"}}, "summary": "web"},
        ]
        services, findings, _ = parse_events(payload)
        assert len(services) == 1 and len(findings) == 1

    def test_findings_sorted_by_severity(self):
        payload = {"Leaks": [
            {"event_type": "leak", "event_source": "a", "leak": {"severity": "low"},
             "summary": "x", "port": "1"},
            {"event_type": "leak", "event_source": "b", "leak": {"severity": "critical"},
             "summary": "y", "port": "2"},
        ]}
        _, findings, _ = parse_events(payload)
        assert [f["severity"] for f in findings] == ["critical", "low"]

    def test_non_numeric_port_is_skipped_for_service(self):
        payload = {"Services": [{"event_type": "service", "event_source": "p",
                                 "port": "", "summary": "s"}]}
        services, _, _ = parse_events(payload)
        assert services == []

    def test_null_ssl_certificate_does_not_crash(self):
        payload = {"Services": [{"event_type": "service", "event_source": "p", "port": "443",
                                 "host": "a.example.com", "ssl": {"certificate": None},
                                 "summary": "s"}]}
        _, _, related = parse_events(payload)
        assert related == ["a.example.com"]

    def test_bare_list_skips_non_dict_elements(self):
        payload = ["oops", None, {"event_type": "leak", "event_source": "p",
                                  "leak": {"severity": "low"}, "summary": "x", "port": "1"}]
        _, findings, _ = parse_events(payload)
        assert len(findings) == 1

    def test_empty_payload(self):
        assert parse_events({}) == ([], [], [])
        assert parse_events([]) == ([], [], [])


class TestParseSubdomains:
    def test_extracts_subdomain_field(self):
        payload = [{"subdomain": "a.example.com"}, {"subdomain": "b.example.com"}]
        assert parse_subdomains(payload) == ["a.example.com", "b.example.com"]

    def test_ignores_malformed_rows(self):
        assert parse_subdomains([{"x": 1}, {"subdomain": "ok.example.com"}]) == ["ok.example.com"]

    def test_empty(self):
        assert parse_subdomains([]) == []
