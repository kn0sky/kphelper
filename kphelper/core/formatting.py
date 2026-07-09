UNKNOWN = "Unknown"
ENABLED = "Enabled"
DISABLED = "Disabled"

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
DIM = "\033[2m"


def colorize(text, color, enabled=True):
    if not enabled:
        return str(text)
    return f"{color}{text}{RESET}"
