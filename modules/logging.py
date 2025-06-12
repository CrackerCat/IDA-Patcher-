import logging
import sys
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama
init(autoreset=True)

class ColorFormatter(logging.Formatter):
    def format(self, record):
        time_color = Fore.WHITE
        level_color = Fore.CYAN
        name_color = Fore.MAGENTA
        message_color = Fore.GREEN

        time_str = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        return (
            f"{time_color}[{time_str}] "
            f"{level_color}[{record.levelname:<8}] "
            f"{name_color}{record.name}: "
            f"{message_color}{record.getMessage()}{Style.RESET_ALL}"
        )

# Configure logger
logger = logging.getLogger("IDA-Patcher")
logger.setLevel(logging.DEBUG)

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(ColorFormatter())

logger.handlers.clear()
logger.addHandler(stream_handler)