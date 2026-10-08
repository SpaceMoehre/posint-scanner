from posint_scanner.secret_scan import find_secrets


def rules(text):
    return {(m.rule, m.value, m.line) for m in find_secrets(text, use_gitleaks=False)}


class TestBuiltinRules:
    def test_aws_access_key_with_line_number(self):
        text = "region = eu-central-1\naws_access_key_id = AKIAZ7Q3R4N5M6P7Q8R9\n"
        assert ("aws_access_key_id", "AKIAZ7Q3R4N5M6P7Q8R9", 2) in rules(text)

    def test_generic_password_needs_entropy_and_no_placeholder(self):
        text = (
            'db_password = "Xk9#mQ2vLp7zR4"\n'
            'password = "changeme123"\n'
            "password: ${DB_PASSWORD}\n"
            'api_key = os.environ.get("KEY")\n'
            "password = aaaaaaaa\n"
        )
        assert rules(text) == {("generic_secret", "Xk9#mQ2vLp7zR4", 1)}

    def test_private_key_block_is_captured_whole(self):
        text = "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END RSA PRIVATE KEY-----\n"
        (match,) = find_secrets(text, use_gitleaks=False)
        assert match.rule == "private_key"
        assert match.line == 2
        assert match.value.endswith("-----END RSA PRIVATE KEY-----")

    def test_credentials_in_connection_url(self):
        text = "DATABASE_URL=postgres://app:s3cr3tpw@db.example.com:5432/app\n"
        assert ("credentials_in_url", "postgres://app:s3cr3tpw@db.example.com:5432/app", 1) in rules(text)

    def test_plain_text_has_no_secrets(self):
        assert rules("server db.example.com\nlisten 10.0.0.1:443\npassword reset link\n") == set()


FAKE_GITLEAKS = """#!/bin/sh
# Fake gitleaks: writes a fixed report to the path after --report-path.
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then shift; REPORT="$1"; fi
  shift
done
cat > "$REPORT" <<'JSON'
[{"RuleID": "twilio-api-key", "Secret": "SKtest0000000000000000000000000000", "StartLine": 3},
 {"RuleID": "aws-access-token", "Secret": "AKIAZ7Q3R4N5M6P7Q8R9", "StartLine": 1}]
JSON
"""


class TestGitleaks:
    def test_findings_are_merged_and_deduped_with_builtin(self, tmp_path, monkeypatch):
        binary = tmp_path / "gitleaks"
        binary.write_text(FAKE_GITLEAKS)
        binary.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        found = {(m.rule, m.value, m.line) for m in find_secrets("key=AKIAZ7Q3R4N5M6P7Q8R9\n")}
        assert found == {
            ("aws_access_key_id", "AKIAZ7Q3R4N5M6P7Q8R9", 1),
            ("gitleaks:twilio-api-key", "SKtest0000000000000000000000000000", 3),
        }

    def test_missing_binary_falls_back_to_builtin(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PATH", str(tmp_path))
        assert [m.rule for m in find_secrets("AKIAZ7Q3R4N5M6P7Q8R9")] == ["aws_access_key_id"]


FAKE_TRUFFLEHOG = """#!/bin/sh
# Fake trufflehog: refuses to run without --no-verification, then prints JSONL.
echo "$@" | grep -q -- --no-verification || { echo "verification not disabled" >&2; exit 2; }
cat <<'JSONL'
{"DetectorName":"Twilio","Raw":"SKtest0000000000000000000000000000","SourceMetadata":{"Data":{"Filesystem":{"line":3}}}}
{"DetectorName":"AWS","Raw":"AKIAZ7Q3R4N5M6P7Q8R9","SourceMetadata":{"Data":{"Filesystem":{"line":1}}}}
{"DetectorName":"URI","Raw":"https://x:y@h.example","SourceMetadata":{"Data":{"Filesystem":{"line":9}}}}
JSONL
"""


class TestTrufflehog:
    def _install(self, tmp_path, monkeypatch):
        binary = tmp_path / "trufflehog"
        binary.write_text(FAKE_TRUFFLEHOG)
        binary.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    def test_findings_merged_and_deduped_with_builtin(self, tmp_path, monkeypatch):
        self._install(tmp_path, monkeypatch)
        found = {
            (m.rule, m.value, m.line)
            for m in find_secrets("key=AKIAZ7Q3R4N5M6P7Q8R9\n",
                                  use_gitleaks=False, use_trufflehog=True)
        }
        assert found == {
            ("aws_access_key_id", "AKIAZ7Q3R4N5M6P7Q8R9", 1),  # built-in wins for this value
            ("trufflehog:Twilio", "SKtest0000000000000000000000000000", 3),
            ("trufflehog:URI", "https://x:y@h.example", 9),
        }

    def test_runs_with_verification_disabled(self, tmp_path, monkeypatch):
        # the fake binary exits non-zero if --no-verification is absent; a
        # crash would drop all findings, so a result proves the flag was sent
        self._install(tmp_path, monkeypatch)
        found = find_secrets("nothing here\n", use_gitleaks=False, use_trufflehog=True)
        assert any(m.rule == "trufflehog:AWS" for m in found)

    def test_off_by_default(self, tmp_path, monkeypatch):
        self._install(tmp_path, monkeypatch)
        assert [m.rule for m in find_secrets("AKIAZ7Q3R4N5M6P7Q8R9", use_gitleaks=False)] == [
            "aws_access_key_id"
        ]

    def test_missing_binary_is_silent_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PATH", str(tmp_path))
        assert [m.rule for m in find_secrets("AKIAZ7Q3R4N5M6P7Q8R9",
                                             use_gitleaks=False, use_trufflehog=True)] == [
            "aws_access_key_id"
        ]


class TestTrufflehogRawV2:
    def test_rawv2_only_finding_is_not_dropped(self, tmp_path, monkeypatch):
        binary = tmp_path / "trufflehog"
        binary.write_text(
            "#!/bin/sh\n"
            'echo \'{"DetectorName":"URI","RawV2":"https://u:p@h.example",'
            '"SourceMetadata":{"Data":{"Filesystem":{"line":2}}}}\'\n'
        )
        binary.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        found = find_secrets("x\n", use_gitleaks=False, use_trufflehog=True)
        assert any(m.value == "https://u:p@h.example" for m in found)


class TestCrossEngineDedup:
    def test_whitespace_differing_duplicates_collapse(self, tmp_path, monkeypatch):
        # gitleaks reports the same AWS key the built-in rule found, but with a
        # trailing newline; it must not appear twice.
        binary = tmp_path / "gitleaks"
        binary.write_text(
            "#!/bin/sh\n"
            'while [ "$#" -gt 0 ]; do [ "$1" = "--report-path" ] && { shift; R="$1"; }; shift; done\n'
            'printf \'[{"RuleID":"aws","Secret":"AKIAZ7Q3R4N5M6P7Q8R9\\n","StartLine":1}]\' > "$R"\n'
        )
        binary.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        found = find_secrets("key=AKIAZ7Q3R4N5M6P7Q8R9\n")
        aws = [m for m in found if m.value.strip() == "AKIAZ7Q3R4N5M6P7Q8R9"]
        assert len(aws) == 1
