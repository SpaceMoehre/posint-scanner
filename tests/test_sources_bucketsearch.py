import pytest

from posint_scanner.sources.bucketsearch import (
    BucketSearchSource,
    bucket_url,
    candidate_bucket_names,
    classify,
)


class TestCandidateNames:
    def test_derives_from_domain_label_and_permutations(self):
        names = candidate_bucket_names("example.com", extra=[], permutations=["", "-dev", "-backups"])
        assert "example" in names
        assert "example-dev" in names
        assert "example-backups" in names

    def test_includes_user_supplied_names(self):
        names = candidate_bucket_names("example.com", extra=["corp-secret"], permutations=[""])
        assert "corp-secret" in names

    def test_deduped_and_lowercased(self):
        names = candidate_bucket_names("Example.com", extra=["Example"], permutations=["", ""])
        assert names.count("example") == 1


class TestClassify:
    @pytest.mark.parametrize("provider", ["s3", "gcs", "azure"])
    def test_200_is_public(self, provider):
        assert classify(provider, 200) == "public"

    @pytest.mark.parametrize("provider,status", [("s3", 403), ("gcs", 401), ("azure", 403)])
    def test_access_denied_is_private(self, provider, status):
        assert classify(provider, status) == "private"

    @pytest.mark.parametrize("provider", ["s3", "gcs", "azure"])
    def test_404_is_none(self, provider):
        assert classify(provider, 404) is None


class TestBucketUrl:
    def test_provider_endpoints(self):
        assert bucket_url("s3", "b") == "https://b.s3.amazonaws.com/"
        assert bucket_url("gcs", "b") == "https://storage.googleapis.com/b/"
        assert bucket_url("azure", "b") == "https://b.blob.core.windows.net/?comp=list&maxresults=1"


class TestDiscoverBuckets:
    def _source(self, statuses, **kw):
        # statuses: url -> HTTP status; missing url treated as connection error (None)
        def head(url):
            return statuses.get(url)

        return BucketSearchSource(
            permutations=["", "-backups"], providers=["s3"], http_status=head, **kw
        )

    def test_finds_public_and_private_skips_missing(self):
        statuses = {
            "https://example.s3.amazonaws.com/": 200,          # public
            "https://example-backups.s3.amazonaws.com/": 403,  # private
        }
        result = self._source(statuses).collect("example.com")
        assert result.target_type == "domain"
        by_name = {a.name: a for a in result.cloud_assets}
        assert by_name["example"].exposure == "public"
        assert by_name["example"].provider == "s3"
        assert by_name["example-backups"].exposure == "private"
        assert set(by_name) == {"example", "example-backups"}  # 404s/errors dropped

    def test_data_summarises_counts(self):
        statuses = {"https://example.s3.amazonaws.com/": 200}
        result = self._source(statuses).collect("example.com")
        assert result.data == {"buckets_checked": 2, "public": 1, "private": 0}

    def test_is_active_and_opt_in(self):
        assert BucketSearchSource.category == "active"
        assert BucketSearchSource.default_enabled is False
