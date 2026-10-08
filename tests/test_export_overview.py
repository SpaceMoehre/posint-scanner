from posint_scanner.export.overview import (
    SENSITIVE_PORTS,
    render_overview_note,
    severity_of,
)


class TestSeverityOf:
    def test_uses_textual_severity_when_present(self):
        assert severity_of({"cvss_severity": "HIGH", "cvss_score": 5.0}) == "HIGH"

    def test_falls_back_to_score_when_no_label(self):
        assert severity_of({"cvss_severity": None, "cvss_score": 9.8}) == "CRITICAL"
        assert severity_of({"cvss_score": 7.5}) == "HIGH"
        assert severity_of({"cvss_score": 4.0}) == "MEDIUM"
        assert severity_of({"cvss_score": 2.0}) == "LOW"

    def test_none_severity_label_falls_back_to_score(self):
        assert severity_of({"cvss_severity": "NONE", "cvss_score": 9.1}) == "CRITICAL"

    def test_unknown_when_no_signal(self):
        assert severity_of({}) == "UNKNOWN"
        assert severity_of({"cvss_severity": None, "cvss_score": None}) == "UNKNOWN"


class TestRenderOverviewNote:
    def _smb_host(self, smbv1=True):
        banner = "SMB Status:\n  SMB Version: 1\n  OS: Windows Server 2016" if smbv1 else "SMB"
        return {
            "address": "212.86.33.249",
            "hostnames": ["diamant-db.dns-net.de"],
            "services": [{"port": 445, "protocol": "tcp", "banner": banner, "version": None}],
            "vulns": [],
        }

    def test_summary_counts(self):
        hosts = [
            self._smb_host(),
            {"address": "10.0.0.1", "hostnames": [], "services": [], "vulns": []},
        ]
        note = render_overview_note(hosts)
        assert "| Hosts (IPs) scanned | 2 |" in note
        assert "| Hosts exposing sensitive services | 1 |" in note
        assert "| Sensitive service exposures | 1 |" in note

    def test_smbv1_is_a_critical_finding(self):
        note = render_overview_note([self._smb_host()])
        assert "SMBv1 enabled" in note
        assert "[[212.86.33.249]]" in note
        assert "SMB (SMBv1)" in note  # exposure table marks the dialect

    def test_plain_smb_exposed_but_not_smbv1_critical(self):
        note = render_overview_note([self._smb_host(smbv1=False)])
        # SMB still shows as an exposed sensitive service...
        assert "| 445/tcp | SMB |" in note
        # ...but with no SMBv1, it isn't in the critical list
        assert "SMBv1 enabled" not in note
        assert "None. No SMBv1" in note

    def test_exposed_services_table_lists_db_and_rdp(self):
        hosts = [
            {
                "address": "1.2.3.4",
                "hostnames": ["db.example.com"],
                "services": [
                    {"port": 3306, "protocol": "tcp", "banner": "MySQL", "version": None},
                    {"port": 3389, "protocol": "tcp", "banner": None, "version": None},
                    {"port": 443, "protocol": "tcp", "banner": "nginx", "version": None},
                ],
                "vulns": [],
            }
        ]
        note = render_overview_note(hosts)
        assert "| 3306/tcp | MySQL |" in note
        assert "| 3389/tcp | RDP |" in note
        assert "443/tcp" not in note  # web ports are intentionally not "sensitive"

    def test_vuln_table_groups_by_component_with_max_score(self):
        hosts = [
            {
                "address": "1.2.3.4",
                "hostnames": ["x.example.com"],
                "services": [],
                "vulns": [
                    {"port": 443, "technology": "nginx", "cpe": "c",
                     "cve_id": "CVE-1", "cvss_score": 5.0, "cvss_severity": "MEDIUM", "summary": "a"},
                    {"port": 443, "technology": "nginx", "cpe": "c",
                     "cve_id": "CVE-2", "cvss_score": 9.8, "cvss_severity": "CRITICAL", "summary": "b"},
                ],
            }
        ]
        note = render_overview_note(hosts)
        # one grouped row: 2 CVEs, max score 9.8, worst CRITICAL
        assert "| 443 | nginx | 2 | 9.8 | CRITICAL |" in note
        # and the CRITICAL one is called out individually
        assert "CVE-2" in note
        assert "CVE-1" not in note.split("## Critical findings")[1].split("## Exposed")[0]

    def test_smbv1_sorts_above_cvss_ten_cve(self):
        hosts = [
            {
                "address": "9.9.9.9",
                "hostnames": [],
                "services": [{"port": 445, "protocol": "tcp",
                              "banner": "SMB Version: 1", "version": None}],
                "vulns": [{"port": 80, "technology": "Drupal", "cpe": "c",
                           "cve_id": "CVE-BIG", "cvss_score": 10.0,
                           "cvss_severity": "CRITICAL", "summary": "x"}],
            }
        ]
        crit_section = render_overview_note(hosts).split("## Critical findings")[1]
        assert crit_section.index("SMBv1 enabled") < crit_section.index("CVE-BIG")

    def test_empty_scan_still_renders(self):
        note = render_overview_note([])
        assert "# Security Overview" in note
        assert "| Hosts (IPs) scanned | 0 |" in note
        assert "None. No SMBv1" in note
        assert note.count("None found.") == 2  # both tables empty

    def test_sensitive_ports_excludes_web_ports(self):
        assert 80 not in SENSITIVE_PORTS
        assert 443 not in SENSITIVE_PORTS
        assert 445 in SENSITIVE_PORTS
