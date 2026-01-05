"""
Constants and configuration paths for the Traffic Viewer.
"""

from pathlib import Path
from typing import List, Tuple

# Number of data points to keep in history for sparklines
# Must match graph_width in _update_graphs() for the graph to fill completely
HISTORY_SIZE: int = 70

# Configuration file path (in config/ directory relative to project root)
# We go up from src/traffic_viewer/ to project root
SCRIPT_DIR = Path(__file__).parent.parent.parent  # Goes to project root
CONFIG_DIR = SCRIPT_DIR / "config"
CONFIG_FILE = CONFIG_DIR / "traffic_viewer_selections.json"

# Polling interval options (in seconds)
# Format: (seconds, display_label)
POLLING_INTERVALS: List[Tuple[int, str]] = [
    (5, "5 seconds"),
    (10, "10 seconds"),
    (20, "20 seconds"),
    (30, "30 seconds"),
    (60, "1 minute"),
    (90, "1.5 minutes"),
    (120, "2 minutes"),
]

# Maximum number of rows in the rolling counter table
# Uses HISTORY_SIZE so table shows same number of data points as the graph
COUNTER_TABLE_MAX_ROWS: int = HISTORY_SIZE

