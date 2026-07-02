"""Simple structured audit logger — every check executed gets a log line.

Keeps an append-only record so you have a defensible "here's exactly what
ran, when, against what" trail for the engagement.
"""
from __future__ import annotations
import logging
import time
import sys
from pathlib import Path


def get_logger(log_path: str = "vulnscan_audit.log") -> logging.Logger:
    logger = logging.getLogger("vulnscan")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        fmt="%(asctime)s UTC | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # Force UTC timestamps in the formatter (converter must be set explicitly)
    fmt.converter = time.gmtime

    file_handler = logging.FileHandler(Path(log_path), mode="a", encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(logging.WARNING)
    logger.addHandler(stream_handler)

    return logger
