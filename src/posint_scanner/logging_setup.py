"""Plain-text logging setup. This is a single-operator CLI, not a service
behind a log aggregator, so no structured/JSON logging by default."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

# --log-file rotates instead of growing without bound.
LOG_FILE_MAX_BYTES = 10 * 1024 * 1024
LOG_FILE_BACKUPS = 3


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.append(
            RotatingFileHandler(log_file, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUPS)
        )

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
