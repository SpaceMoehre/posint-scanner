import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from posint_scanner.config import load_config
from posint_scanner.sources.base import SourceSettings


class KeyedSettings(SourceSettings):
    api_key: str | None = None
    platform_url: str = "https://api.example"


class TestLoadConfig:
    def test_missing_file_returns_defaults(self, tmp_path):
        config = load_config(tmp_path / "does-not-exist.yaml")
        settings = config.source_settings("shodan", KeyedSettings)
        assert settings.api_key is None
        assert settings.enabled is None
        assert config.defaults.passive is True
        assert config.defaults.scrape is False
        assert config.defaults.active is True

    def test_reads_source_section_from_sources_map(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "sources:\n  virustotal:\n    api_key: vt\n    enabled: false\n    ttl_days: 2\n"
        )
        settings = load_config(config_file).source_settings("virustotal", KeyedSettings)
        assert settings.api_key == "vt"
        assert settings.enabled is False
        assert settings.ttl_days == 2

    def test_legacy_top_level_section_is_an_alias(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("shodan:\n  api_key: from-yaml\n")
        settings = load_config(config_file).source_settings("shodan", KeyedSettings)
        assert settings.api_key == "from-yaml"

    def test_sources_map_wins_over_legacy_alias(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "shodan:\n  api_key: legacy\n  platform_url: https://legacy\n"
            "sources:\n  shodan:\n    api_key: new\n"
        )
        settings = load_config(config_file).source_settings("shodan", KeyedSettings)
        assert settings.api_key == "new"
        assert settings.platform_url == "https://legacy"

    def test_env_var_derived_from_source_and_field_name(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("sources:\n  shodan:\n    api_key: from-yaml\n")
        with patch.dict(os.environ, {"OSINT_SHODAN_API_KEY": "from-env"}):
            settings = load_config(config_file).source_settings("shodan", KeyedSettings)
        assert settings.api_key == "from-env"

    def test_env_var_for_multi_word_source_and_generic_field(self, tmp_path):
        env = {"OSINT_QUALYS_VMDR_API_KEY": "u", "OSINT_SHODAN_WEB_ENABLED": "true"}
        with patch.dict(os.environ, env):
            config = load_config(tmp_path / "missing.yaml")
            assert config.source_settings("qualys_vmdr", KeyedSettings).api_key == "u"
            assert config.source_settings("shodan_web", SourceSettings).enabled is True

    def test_unknown_field_in_source_section_is_rejected(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("sources:\n  shodan:\n    api_kee: typo\n")
        config = load_config(config_file)
        with pytest.raises(ValidationError):
            config.source_settings("shodan", KeyedSettings)

    def test_category_defaults_from_yaml(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("defaults:\n  active: false\n  scrape: true\n")
        config = load_config(config_file)
        assert config.defaults.active is False
        assert config.defaults.scrape is True
        assert config.defaults.passive is True

    def test_nvd_defaults_to_none(self, tmp_path):
        config = load_config(tmp_path / "missing.yaml")
        assert config.nvd.api_key is None

    def test_nvd_env_var_override(self, tmp_path):
        with patch.dict(os.environ, {"OSINT_NVD_API_KEY": "nvdkey"}):
            config = load_config(tmp_path / "missing.yaml")
        assert config.nvd.api_key == "nvdkey"
