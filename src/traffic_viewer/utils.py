"""
Utility functions for the Traffic Viewer.

Contains:
- natural_sort_key: Natural sorting for interface names
- Configuration file persistence (save/load interface selection)
"""

import re
import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, TYPE_CHECKING

from src.utils.logger import get_logger

from .constants import CONFIG_DIR, CONFIG_FILE

if TYPE_CHECKING:
    from .models import ViewerSelection

logger = get_logger(__name__)


def natural_sort_key(name: str) -> Tuple:
    """Generate sort key for natural sorting of interface names.
    
    Handles names like ethernet1/1, ethernet1/2, ethernet1/10 correctly.
    """
    parts = re.split(r'(\d+)', name)
    return tuple(int(p) if p.isdigit() else p for p in parts)


def ensure_config_dir() -> None:
    """Ensure configuration directory exists."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_interface_selection(selection: "ViewerSelection") -> None:
    """Save interface selection to disk."""
    ensure_config_dir()

    data = {
        'timestamp': datetime.now().isoformat(),
        'polling_interval': selection.polling_interval,
        'interfaces': [
            {
                'id': iface.id,
                'name': iface.name,
                'firewall': iface.firewall,
                'status': iface.status,
                'zone': iface.zone,
                'ip': iface.ip,
                'fwd': iface.fwd
            }
            for iface in selection.interfaces
        ]
    }

    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved interface selection to {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"Failed to save interface selection: {e}")


def load_interface_selection() -> Optional[Dict[str, Any]]:
    """Load saved interface selection from disk."""
    if not CONFIG_FILE.exists():
        return None

    try:
        with open(CONFIG_FILE, 'r') as f:
            data = json.load(f)
        logger.info(f"Loaded interface selection from {CONFIG_FILE}")
        return data
    except Exception as e:
        logger.error(f"Failed to load interface selection: {e}")
        return None

