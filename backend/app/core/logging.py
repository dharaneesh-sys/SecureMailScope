import logging
from logging.handlers import RotatingFileHandler

from .config import settings

LOG_NAME = "securemailscope"


def setup_logging() -> logging.Logger:
    settings.ensure_dirs()
    logger = logging.getLogger(LOG_NAME)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    fh = RotatingFileHandler(settings.data_dir / "app.log", maxBytes=1_000_000, backupCount=2)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOG_NAME}.{name}" if name else LOG_NAME)
