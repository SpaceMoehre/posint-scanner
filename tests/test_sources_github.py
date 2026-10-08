import json

import pytest
import responses

from conftest import load_fixture
from posint_scanner.sources import github
from posint_scanner.sources.github import RAW_URL, SEARCH_URL, GitHubSettings, GitHubSource

NGINX_CONF = "server {\n    listen 443;\n    server_name api.example.com;\n    proxy_pass http://10.0.0.5;\n}\n"


def raw(repo, commit, path):
    return RAW_URL.format(repo=repo, ref=commit, path=path)


def make_source(**settings):
    return GitHubSource.from_settings(GitHubSettings(token="ghp_test", use_gitleaks=False, **settings))


@pytest.fixture
def search_fixture():
    responses.get(SEARCH_URL, json=json.loads(load_fixture("github", "search_example.com.json")))
    responses.get(raw("acme-dev/infra", "a" * 40, "deploy/nginx.conf"), body=NGINX_CONF)


class TestCollect:
    @responses.activate
    def test_file_naming_a_hostname_is_a_reference(self, search_fixture):
        result = make_source().collect("example.com")
        refs = [e for e in result.code_exposures if e.repo == "acme-dev/infra"]
        assert [(e.kind, e.target, e.path, e.line) for e in refs] == [
            ("reference", "api.example.com", "deploy/nginx.conf", 3)
        ]
        assert refs[0].url == (
            "https://github.com/acme-dev/infra/blob/" + "a" * 40 + "/deploy/nginx.conf#L3"
        )
        assert refs[0].snippet == "server_name api.example.com;"

    @responses.activate
    def test_forks_and_unrelated_and_docs_are_dropped(self, search_fixture):
        result = make_source().collect("example.com")
        repos = {e.repo for e in result.code_exposures}
        assert "copycat/infra" not in repos       # fork
        assert "someone/unrelated" not in repos    # "example com" tokenized false positive
        assert "acme-dev/website" not in repos      # README.md denied path
        assert "acme-dev/app" in repos              # kept: has a secret

    @responses.activate
    def test_related_hostnames_fed_back(self, search_fixture):
        result = make_source().collect("example.com")
        assert "api.example.com" in result.related_hostnames

    @responses.activate
    def test_secret_in_fetched_file_is_reported_in_full(self):
        responses.get(SEARCH_URL, json=json.loads(load_fixture("github", "search_example.com.json")))
        responses.get(raw("acme-dev/infra", "a" * 40, "deploy/nginx.conf"), body=NGINX_CONF)
        secrets = [e for e in make_source().collect("example.com").code_exposures if e.kind == "secret"]
        assert len(secrets) == 1
        assert secrets[0].repo == "acme-dev/app"
        assert secrets[0].rule == "credentials_in_url"
        assert secrets[0].secret == "postgres://app:Pr0dS3cret!@db.internal.example.com:5432/app"

    @responses.activate
    def test_private_ip_is_not_searched(self):
        result = make_source().enrich("10.0.0.5", [])
        assert result.code_exposures == []
        assert len(responses.calls) == 0

    @responses.activate
    def test_shared_ip_with_many_hostnames_skipped(self):
        result = make_source(skip_asns=[]).enrich("8.8.8.8", [f"h{i}.example.com" for i in range(30)])
        assert result.data["searched"] is False
        assert len(responses.calls) == 0


class TestOverflow:
    @responses.activate
    def test_collect_flags_overflow_when_total_exceeds_result_cap(self):
        responses.get(SEARCH_URL, json={"total_count": 5000, "incomplete_results": True, "items": []})
        data = make_source().collect("example.com").data
        assert data["overflowed"] is True
        assert data["total_hits"] == 5000

    @responses.activate
    def test_collect_not_overflowed_for_small_result(self):
        responses.get(SEARCH_URL, json={"total_count": 3, "items": []})
        assert make_source().collect("example.com").data["overflowed"] is False

    @responses.activate
    def test_public_ip_is_searched(self):
        responses.get(SEARCH_URL, json={"total_count": 0, "items": []})
        result = make_source(skip_asns=[]).enrich("8.8.8.8", ["one.example.com"])
        assert result.data["searched"] is True
        assert len(responses.calls) == 1


class TestErrors:
    @responses.activate
    def test_missing_token_is_unavailable(self):
        from posint_scanner.sources.base import SourceUnavailableError
        source = GitHubSource.from_settings(GitHubSettings())
        assert source.is_configured is False
        with pytest.raises(SourceUnavailableError):
            source.collect("example.com")

    @responses.activate
    def test_bad_token_raises_auth_error(self):
        from posint_scanner.retry import AuthError
        responses.get(SEARCH_URL, status=401, json={"message": "Bad credentials"})
        with pytest.raises(AuthError):
            make_source().collect("example.com")

    @responses.activate
    def test_long_rate_limit_stops_the_run(self):
        from posint_scanner.sources.base import QuotaExhaustedError
        responses.get(SEARCH_URL, status=403,
                      headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "99999999999"},
                      json={"message": "rate limited"})
        with pytest.raises(QuotaExhaustedError):
            make_source().collect("example.com")

    @responses.activate
    def test_422_past_result_window_stops_paging_cleanly(self):
        responses.get(SEARCH_URL, status=422, json={"message": "Validation Failed"})
        result = make_source().collect("example.com")
        assert result.code_exposures == []
