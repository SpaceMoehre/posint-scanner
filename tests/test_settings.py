import pytest

from posint_scanner.config import Config
from posint_scanner.db import Database
from posint_scanner.settings import (
    apply_source_secrets,
    load_source_secrets,
    save_source_secrets,
    source_key_groups,
    source_secret_fields,
)


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "s.db") as database:
        database.init_schema()
        yield database


class TestSecretFields:
    def test_includes_api_key_sources(self):
        fields = source_secret_fields()
        assert ("shodan", "api_key") in fields
        assert ("leakix", "api_key") in fields

    def test_includes_multi_credential_sources(self):
        fields = source_secret_fields()
        assert ("censys", "api_id") in fields
        assert ("censys", "api_secret") in fields
        assert ("qualys_vmdr", "api_user") in fields
        assert ("qualys_vmdr", "api_password") in fields

    def test_includes_standalone_sections(self):
        fields = source_secret_fields()
        assert ("nvd", "api_key") in fields
        assert ("wpscan", "wpscan_api_token") in fields

    def test_excludes_non_secret_fields(self):
        fields = source_secret_fields()
        assert not any(field in ("enabled", "ttl_days", "max_hits", "limit", "platform_url")
                       for _, field in fields)


class TestRoundTrip:
    def test_save_then_load(self, db):
        save_source_secrets(db, {"shodan": {"api_key": "sk-123"},
                                 "censys": {"api_id": "id", "api_secret": "sec"}})
        assert load_source_secrets(db) == {
            "shodan": {"api_key": "sk-123"},
            "censys": {"api_id": "id", "api_secret": "sec"},
        }

    def test_present_blank_field_clears(self, db):
        save_source_secrets(db, {"shodan": {"api_key": "sk-123"}})
        save_source_secrets(db, {"shodan": {"api_key": "  "}})  # present, blank -> clear
        assert load_source_secrets(db) == {}

    def test_absent_field_is_untouched(self, db):
        save_source_secrets(db, {"shodan": {"api_key": "sk-123"}})
        # A save that doesn't mention shodan must not wipe it.
        save_source_secrets(db, {"leakix": {"api_key": "lk"}})
        assert load_source_secrets(db)["shodan"] == {"api_key": "sk-123"}
        assert load_source_secrets(db)["leakix"] == {"api_key": "lk"}


class TestApply:
    def test_registry_source_merged_into_sources(self, db):
        save_source_secrets(db, {"shodan": {"api_key": "sk-123"}})
        config = Config()
        apply_source_secrets(config, db)
        assert config.sources["shodan"]["api_key"] == "sk-123"

    def test_standalone_sections(self, db):
        save_source_secrets(db, {"nvd": {"api_key": "nvd-k"},
                                 "wpscan": {"wpscan_api_token": "wp-t"}})
        config = Config()
        apply_source_secrets(config, db)
        assert config.nvd.api_key == "nvd-k"
        assert config.webscan.wpscan_api_token == "wp-t"

    def test_env_wins_for_standalone(self, db, monkeypatch):
        monkeypatch.setenv("OSINT_NVD_API_KEY", "env-k")
        save_source_secrets(db, {"nvd": {"api_key": "db-k"}})
        config = Config()  # env already applied by load_config in real use
        apply_source_secrets(config, db)
        # apply_source_secrets must not clobber an env-provided value.
        assert config.nvd.api_key is None  # left for load_config's env handling

    def test_empty_db_is_noop(self, db):
        config = Config()
        apply_source_secrets(config, db)
        assert config.sources == {}


class TestKeyGroups:
    def test_groups_carry_form_name_and_configured_flag(self, db):
        save_source_secrets(db, {"censys": {"api_id": "the-id"}})
        groups = {g["source"]: g for g in source_key_groups(db)}
        censys = {f["field"]: f for f in groups["censys"]["fields"]}
        assert censys["api_id"]["name"] == "source.censys.api_id"
        assert censys["api_id"]["configured"] is True
        assert censys["api_secret"]["configured"] is False

    def test_secret_value_is_not_exposed(self, db):
        save_source_secrets(db, {"shodan": {"api_key": "sk-secret"}})
        # The view model must never carry the raw secret back to the template.
        blob = repr(source_key_groups(db))
        assert "sk-secret" not in blob
