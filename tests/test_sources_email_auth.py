from posint_scanner.sources.email_auth import (
    assess,
    clean_txt_records,
    dkim_selectors_present,
    find_ids,
    grade_caa,
    grade_dmarc,
    grade_spf,
)


def find_ids_of(findings):
    return {f["id"] for f in findings}


class TestCleanTxtRecords:
    def test_strips_surrounding_quotes(self):
        assert clean_txt_records(['"v=spf1 -all"']) == ["v=spf1 -all"]

    def test_joins_split_chunks(self):
        # dnspython renders a long TXT record as several quoted chunks.
        assert clean_txt_records(['"v=DKIM1; k=rsa; " "p=MIGf..."']) == ["v=DKIM1; k=rsa; p=MIGf..."]

    def test_passes_unquoted_through(self):
        assert clean_txt_records(["v=spf1 -all"]) == ["v=spf1 -all"]


class TestGradeSpf:
    def test_missing_is_flagged(self):
        g = grade_spf([], mx_present=True)
        assert g["found"] is False
        assert "spf_missing" in find_ids(g["findings"])

    def test_missing_without_mx_is_lower_severity(self):
        with_mx = grade_spf([], mx_present=True)
        without_mx = grade_spf([], mx_present=False)
        sev = {f["id"]: f["severity"] for f in with_mx["findings"]}["spf_missing"]
        sev_no = {f["id"]: f["severity"] for f in without_mx["findings"]}["spf_missing"]
        assert sev == "high"
        assert sev_no == "medium"

    def test_hard_fail_all_is_clean(self):
        g = grade_spf(["v=spf1 include:_spf.google.com -all"], mx_present=True)
        assert g["found"] is True
        assert g["all_qualifier"] == "-all"
        assert g["findings"] == []

    def test_softfail_is_low(self):
        g = grade_spf(["v=spf1 include:_spf.google.com ~all"], mx_present=True)
        assert g["all_qualifier"] == "~all"
        assert find_ids_of(g["findings"]) == {"spf_softfail"}

    def test_neutral_is_medium(self):
        g = grade_spf(["v=spf1 ?all"], mx_present=True)
        assert {f["id"]: f["severity"] for f in g["findings"]}["spf_neutral"] == "medium"

    def test_pass_all_is_critical(self):
        g = grade_spf(["v=spf1 +all"], mx_present=True)
        assert {f["id"]: f["severity"] for f in g["findings"]}["spf_pass_all"] == "critical"

    def test_bare_all_means_pass(self):
        # `all` with no qualifier is an implicit `+all`.
        g = grade_spf(["v=spf1 all"], mx_present=True)
        assert g["all_qualifier"] == "+all"
        assert "spf_pass_all" in find_ids(g["findings"])

    def test_multiple_records_is_permerror(self):
        g = grade_spf(["v=spf1 -all", "v=spf1 ~all"], mx_present=True)
        assert "spf_multiple_records" in find_ids(g["findings"])

    def test_counts_dns_lookup_mechanisms(self):
        record = (
            "v=spf1 include:a.com include:b.com a mx "
            "exists:%{i}.c.com redirect=d.com -all"
        )
        g = grade_spf([record], mx_present=True)
        # include x2, a, mx, exists, redirect = 6
        assert g["lookup_count"] == 6

    def test_too_many_lookups_flagged(self):
        record = "v=spf1 " + " ".join(f"include:h{i}.com" for i in range(11)) + " -all"
        g = grade_spf([record], mx_present=True)
        assert g["lookup_count"] == 11
        assert "spf_too_many_lookups" in find_ids(g["findings"])


class TestGradeDmarc:
    def test_missing_is_high(self):
        g = grade_dmarc([])
        assert g["found"] is False
        assert {f["id"]: f["severity"] for f in g["findings"]}["dmarc_missing"] == "high"

    def test_reject_with_rua_is_clean(self):
        g = grade_dmarc(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])
        assert g["policy"] == "reject"
        assert g["findings"] == []

    def test_policy_none_is_monitoring_only(self):
        g = grade_dmarc(["v=DMARC1; p=none; rua=mailto:d@example.com"])
        assert g["policy"] == "none"
        assert "dmarc_policy_none" in find_ids(g["findings"])

    def test_record_without_policy_is_flagged(self):
        g = grade_dmarc(["v=DMARC1; rua=mailto:d@example.com"])
        assert g["found"] is True
        assert g["policy"] is None
        assert {f["id"]: f["severity"] for f in g["findings"]}["dmarc_no_policy"] == "high"

    def test_partial_pct_flagged(self):
        g = grade_dmarc(["v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com"])
        assert g["pct"] == 50
        assert "dmarc_partial_pct" in find_ids(g["findings"])

    def test_no_rua_flagged(self):
        g = grade_dmarc(["v=DMARC1; p=reject"])
        assert "dmarc_no_reporting" in find_ids(g["findings"])

    def test_multiple_records_flagged(self):
        g = grade_dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"])
        assert "dmarc_multiple_records" in find_ids(g["findings"])

    def test_parses_subdomain_policy(self):
        g = grade_dmarc(["v=DMARC1; p=reject; sp=none; rua=mailto:d@e.com"])
        assert g["subdomain_policy"] == "none"
        assert "dmarc_subdomain_none" in find_ids(g["findings"])


class TestGradeCaa:
    def test_missing_is_flagged_low(self):
        g = grade_caa([])
        assert g["found"] is False
        assert {f["id"]: f["severity"] for f in g["findings"]}["caa_missing"] == "low"

    def test_present_is_clean(self):
        g = grade_caa(['0 issue "letsencrypt.org"'])
        assert g["found"] is True
        assert g["findings"] == []


class TestDkim:
    def test_detects_selectors_with_keys(self):
        probed = {
            "google": ["v=DKIM1; k=rsa; p=MIGf..."],
            "selector1": [],
            "default": ["not a dkim record"],
        }
        assert dkim_selectors_present(probed) == ["google"]


class TestAssess:
    def _clean_mail(self):
        return assess(
            spf_txt=["v=spf1 include:_spf.google.com -all"],
            dmarc_txt=["v=DMARC1; p=reject; rua=mailto:d@example.com"],
            caa_records=['0 issue "letsencrypt.org"'],
            dkim_probed={"google": ["v=DKIM1; k=rsa; p=abc"]},
            mx_present=True,
        )

    def test_well_configured_domain_is_not_spoofable(self):
        a = self._clean_mail()
        assert a["spoofable"] is False
        assert a["findings"] == []

    def test_no_dmarc_is_spoofable(self):
        a = assess(
            spf_txt=["v=spf1 -all"],
            dmarc_txt=[],
            caa_records=[],
            dkim_probed={},
            mx_present=True,
        )
        assert a["spoofable"] is True

    def test_dmarc_none_is_spoofable_even_with_strict_spf(self):
        a = assess(
            spf_txt=["v=spf1 -all"],
            dmarc_txt=["v=DMARC1; p=none"],
            caa_records=[],
            dkim_probed={},
            mx_present=True,
        )
        assert a["spoofable"] is True

    def test_findings_sorted_by_severity(self):
        a = assess(
            spf_txt=[],
            dmarc_txt=[],
            caa_records=[],
            dkim_probed={},
            mx_present=True,
        )
        severities = [f["severity"] for f in a["findings"]]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        assert severities == sorted(severities, key=lambda s: rank[s])
