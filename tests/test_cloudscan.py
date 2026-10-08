import json

from posint_scanner.cloudscan import (
    CheckovScanner,
    ProwlerScanner,
    ScoutSuiteScanner,
    TrivyScanner,
    clone_repo,
    count_by_severity,
    parse_checkov,
    parse_prowler,
    parse_scoutsuite,
    parse_trivy,
    severity_rank,
)

TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "app/package-lock.json",
            "Class": "lang-pkgs",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-23337",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.11",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                    "Title": "Command injection in lodash",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-23337",
                }
            ],
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image runs as root",
                    "Severity": "MEDIUM",
                    "Message": "Specify a non-root USER",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                    "CauseMetadata": {"Resource": "Dockerfile"},
                }
            ],
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Title": "AWS Access Key ID",
                    "Severity": "CRITICAL",
                    "StartLine": 12,
                }
            ],
        }
    ]
}


class TestParseTrivy:
    def test_extracts_vuln_misconfig_and_secret(self):
        findings = parse_trivy(json.dumps(TRIVY_OUTPUT), "acme/api:latest")
        kinds = {f["kind"] for f in findings}
        assert kinds == {"vulnerability", "misconfig", "secret"}

    def test_vulnerability_fields(self):
        vuln = next(f for f in parse_trivy(json.dumps(TRIVY_OUTPUT), "img") if f["kind"] == "vulnerability")
        assert vuln["tool"] == "trivy"
        assert vuln["id"] == "CVE-2021-23337"
        assert vuln["severity"] == "high"
        assert vuln["cves"] == ["CVE-2021-23337"]
        assert vuln["resource"] == "lodash 4.17.11"
        assert vuln["location"] == "fixed in 4.17.21"
        assert vuln["target"] == "img"

    def test_secret_is_critical(self):
        secret = next(f for f in parse_trivy(json.dumps(TRIVY_OUTPUT), "img") if f["kind"] == "secret")
        assert secret["severity"] == "critical"
        assert secret["location"] == "line 12"

    def test_empty_and_malformed(self):
        assert parse_trivy("", "img") == []
        assert parse_trivy("not json", "img") == []
        assert parse_trivy(json.dumps({"Results": None}), "img") == []


CHECKOV_OUTPUT = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_20",
                "check_name": "S3 Bucket has an ACL defined which allows public access",
                "severity": "HIGH",
                "resource": "aws_s3_bucket.data",
                "file_path": "/main.tf",
                "file_line_range": [10, 20],
                "guideline": "https://docs.bridgecrew.io/docs/s3_1",
            }
        ],
        "passed_checks": [{"check_id": "CKV_AWS_21"}],
    },
}


class TestParseCheckov:
    def test_extracts_failed_checks_only(self):
        findings = parse_checkov(json.dumps(CHECKOV_OUTPUT), "repo")
        assert len(findings) == 1
        f = findings[0]
        assert f["tool"] == "checkov"
        assert f["id"] == "CKV_AWS_20"
        assert f["severity"] == "high"
        assert f["resource"] == "aws_s3_bucket.data"
        assert f["location"] == "/main.tf:10"

    def test_list_of_framework_documents(self):
        findings = parse_checkov(json.dumps([CHECKOV_OUTPUT, CHECKOV_OUTPUT]), "repo")
        assert len(findings) == 2

    def test_missing_severity_defaults_unknown(self):
        doc = {"check_type": "tf", "results": {"failed_checks": [{"check_id": "X", "check_name": "n"}]}}
        assert parse_checkov(json.dumps(doc), "repo")[0]["severity"] == "unknown"

    def test_empty_and_malformed(self):
        assert parse_checkov("", "repo") == []
        assert parse_checkov(json.dumps({"results": {}}), "repo") == []


class TestParseProwler:
    def test_ocsf_v4_shape_keeps_only_failures(self):
        data = [
            {
                "status_code": "FAIL",
                "severity": "High",
                "finding_info": {"title": "S3 bucket public", "uid": "s3_bucket_public_access"},
                "resources": [{"uid": "arn:aws:s3:::my-bucket"}],
                "region": "us-east-1",
            },
            {"status_code": "PASS", "severity": "high", "finding_info": {"title": "fine"}},
        ]
        findings = parse_prowler(json.dumps(data), "aws")
        assert len(findings) == 1
        f = findings[0]
        assert f["tool"] == "prowler"
        assert f["severity"] == "high"
        assert f["id"] == "s3_bucket_public_access"
        assert f["resource"] == "arn:aws:s3:::my-bucket"
        assert f["location"] == "us-east-1"
        assert f["target"] == "aws"

    def test_v3_native_pascalcase_shape(self):
        data = [
            {
                "Status": "FAIL",
                "Severity": "critical",
                "CheckID": "iam_root_mfa_enabled",
                "CheckTitle": "Ensure MFA is enabled for the root account",
                "ResourceId": "root",
                "Region": "us-east-1",
            }
        ]
        f = parse_prowler(json.dumps(data), "aws")[0]
        assert f["id"] == "iam_root_mfa_enabled"
        assert f["severity"] == "critical"
        assert f["resource"] == "root"

    def test_empty_and_malformed(self):
        assert parse_prowler("", "aws") == []
        assert parse_prowler(json.dumps([]), "aws") == []


class TestParseScoutSuite:
    JS = (
        "scoutsuite_results ="
        + json.dumps(
            {
                "services": {
                    "s3": {
                        "findings": {
                            "s3-bucket-world-listable": {
                                "flagged_items": 3,
                                "level": "danger",
                                "description": "S3 bucket is world listable",
                                "rationale": "Buckets should not be public",
                            }
                        }
                    },
                    "iam": {
                        "findings": {
                            "iam-user-no-mfa": {
                                "flagged_items": 0,
                                "level": "warning",
                                "description": "no MFA",
                            }
                        }
                    },
                }
            }
        )
    )

    def test_only_flagged_findings(self):
        findings = parse_scoutsuite(self.JS, "aws")
        assert len(findings) == 1
        f = findings[0]
        assert f["tool"] == "scoutsuite"
        assert f["id"] == "s3-bucket-world-listable"
        assert f["severity"] == "high"  # danger -> high
        assert "3 affected" in f["resource"]

    def test_warning_maps_to_medium(self):
        js = "scoutsuite_results = " + json.dumps(
            {"services": {"ec2": {"findings": {"x": {"flagged_items": 1, "level": "warning", "description": "d"}}}}}
        )
        assert parse_scoutsuite(js, "aws")[0]["severity"] == "medium"

    def test_empty_and_malformed(self):
        assert parse_scoutsuite("", "aws") == []
        assert parse_scoutsuite("no object here", "aws") == []


class TestHelpers:
    def test_count_by_severity_omits_zero_buckets(self):
        findings = [{"severity": "high"}, {"severity": "high"}, {"severity": "low"}]
        assert count_by_severity(findings) == {"high": 2, "low": 1}

    def test_severity_rank_orders_critical_first(self):
        assert severity_rank("critical") < severity_rank("low")
        assert severity_rank(None) == severity_rank("unknown")


class TestScannersGracefulWhenAbsent:
    def test_trivy_absent(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: None)
        s = TrivyScanner()
        assert s.available is False
        assert s.scan_image("img") == []
        assert s.scan_fs("/path") == []

    def test_checkov_absent(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: None)
        assert CheckovScanner().scan_dir("/path") == []

    def test_prowler_absent(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: None)
        assert ProwlerScanner().scan("aws") == []

    def test_scoutsuite_absent(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: None)
        assert ScoutSuiteScanner().scan("aws") == []

    def test_clone_repo_without_git(self, monkeypatch):
        monkeypatch.setattr("posint_scanner.cloudscan.shutil.which", lambda _: None)
        assert clone_repo("https://github.com/x/y.git", "/tmp/nope") is False
