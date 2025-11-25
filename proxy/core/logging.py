"""Central logging helper configured via environment variables."""

import logging
import os
from pathlib import Path

_LOG_LEVEL_MAP = {
    "1": logging.ERROR,
    "2": logging.WARNING,
    "3": logging.DEBUG,
}

_CONFIGURED = False


def _resolve_log_level() -> int:
    value = os.getenv("LOGGING_LEVEL", "3").strip()
    return _LOG_LEVEL_MAP.get(value, logging.DEBUG)


def _resolve_log_path() -> Path:
    env_path = os.getenv("LOGGING_PATH") or os.getenv("LOG_FILE_PATH")
    if env_path:
        return Path(env_path).expanduser()
    return Path("/home/ppowicz/proxy/proxy/proxy.log")


def _configure_root_logger() -> logging.Logger:
    global _CONFIGURED
    logger = logging.getLogger("proxy")
    if _CONFIGURED or logger.handlers:
        _CONFIGURED = True
        return logger

    log_path = _resolve_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(message)s"))

    logger.setLevel(_resolve_log_level())
    logger.addHandler(handler)

    _CONFIGURED = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger, initializing the stack on first use."""

    _configure_root_logger()
    return logging.getLogger(name)
