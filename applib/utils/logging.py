import logging
import sys

from loguru import logger


def init_logging(logging_type="screen", file="lumu.log", verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logger.remove()
    fmt = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    logger.add(
        "errors.log",
        level="ERROR",
        format=fmt,
        rotation="5 MB",
        retention=5,
        enqueue=True,
    )

    if logging_type == "screen":
        logger.add(sys.stdout, level=level, format=fmt, colorize=True)
    else:
        logger.add(
            file, level=level, format=fmt, rotation="5 MB", retention=5, enqueue=True
        )
