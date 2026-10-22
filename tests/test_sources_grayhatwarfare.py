from posint_scanner.sources.grayhatwarfare import parse_buckets


class TestParseBuckets:
    def test_maps_provider_types(self):
        payload = {"buckets": [
            {"id": 1, "bucket": "ex.s3-eu-west-1.amazonaws.com", "type": "aws", "fileCount": 5},
            {"id": 2, "bucket": "ex.blob.core.windows.net", "type": "azure", "fileCount": 0},
            {"id": 3, "bucket": "ex.storage.googleapis.com", "type": "gcp", "fileCount": 2},
        ]}
        assets = parse_buckets(payload)
        assert [(a.provider, a.name) for a in assets] == [
            ("s3", "ex.s3-eu-west-1.amazonaws.com"),
            ("azure", "ex.blob.core.windows.net"),
            ("gcs", "ex.storage.googleapis.com"),
        ]

    def test_marks_public_and_builds_url(self):
        assets = parse_buckets({"buckets": [{"bucket": "ex.s3.amazonaws.com", "type": "aws"}]})
        assert assets[0].exposure == "public"
        assert assets[0].url == "http://ex.s3.amazonaws.com"

    def test_unknown_type_passed_through(self):
        assets = parse_buckets({"buckets": [{"bucket": "ex.example", "type": "dos"}]})
        assert assets[0].provider == "dos"

    def test_skips_rows_without_bucket(self):
        assert parse_buckets({"buckets": [{"id": 1, "type": "aws"}]}) == []

    def test_empty(self):
        assert parse_buckets({}) == []
        assert parse_buckets({"buckets": []}) == []
