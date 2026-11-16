import logging
import sys
import colorlog

def setup_logger(name: str = "Tauria") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    log_format = (
        "%(cyan)s%(asctime)s%(reset)s | "
        "%(log_color)s%(levelname)-8s%(reset)s | "
        "%(yellow)s%(name)s%(reset)s - %(message)s"
    )

    handler = colorlog.StreamHandler(sys.stdout)
    handler.setFormatter(colorlog.ColoredFormatter(
        log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        }
    ))

    logger.addHandler(handler)
    return logger

log = setup_logger()
get_logger = setup_logger

