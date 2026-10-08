from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(source: str, name: str) -> str:
    """A response body captured from the real service (sanitized), stored at
    tests/fixtures/<source>/<name>. See tests/fixtures/README.md."""
    return (FIXTURES / source / name).read_text()


def pytest_collection_modifyitems(config, items):
    # Live canary tests hit real endpoints: only run when selected with -m live.
    if "live" in (config.getoption("-m") or ""):
        return
    skip = pytest.mark.skip(reason="live endpoint test - run with: pytest -m live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)
