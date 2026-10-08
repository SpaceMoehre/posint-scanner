"""Plain-text logging setup. This is a single-operator CLI, not a service
behind a log aggregator, so no structured/JSON logging by default."""

from __future__ import annotations

import logging


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
