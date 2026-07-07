import logging
import os

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan.log")


def setup_logger(name="portscanner", level=logging.INFO, log_file=LOG_FILE):
    """Create (or fetch) a logger that writes timestamped entries to scan.log
    and echoes them to the console."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger  # avoid duplicate handlers if called more than once

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger