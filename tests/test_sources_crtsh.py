from posint_scanner.sources.crtsh import parse_crtsh_response


class TestParseCrtshResponse:
    def test_extracts_names_from_name_value_field(self):
        raw = [
            {"name_value": "api.example.com"},
            {"name_value": "www.example.com"},
        ]
        result = parse_crtsh_response(raw)
        assert {h.name for h in result} == {"api.example.com", "www.example.com"}

    def test_splits_multiple_names_in_one_entry(self):
        raw = [{"name_value": "api.example.com\nwww.example.com"}]
        result = parse_crtsh_response(raw)
        assert {h.name for h in result} == {"api.example.com", "www.example.com"}

    def test_dedups_names(self):
        raw = [{"name_value": "api.example.com"}, {"name_value": "api.example.com"}]
        result = parse_crtsh_response(raw)
        assert len(result) == 1

    def test_strips_wildcard_prefix(self):
        raw = [{"name_value": "*.example.com"}]
        result = parse_crtsh_response(raw)
        assert result[0].name == "example.com"

    def test_tags_source_as_crtsh(self):
        result = parse_crtsh_response([{"name_value": "api.example.com"}])
        assert result[0].source == "crtsh"

    def test_empty_response(self):
        assert parse_crtsh_response([]) == []
