"""
Traffic Viewer - Real-time interface traffic monitoring for Palo Alto firewalls.

Uses Textual TUI framework with Screen-based navigation for smooth transitions.
"""

from .app import TrafficViewerApp, main, test_data_retrieval
from .models import (
    ColorTheme,
    THEME,
    InterfaceInfo,
    FirewallInfo,
    ViewerSelection,
    InterfaceCache,
    InterfaceTrafficData,
)
from .constants import HISTORY_SIZE, POLLING_INTERVALS

__all__ = [
    # Main app and entry points
    "TrafficViewerApp",
    "main",
    "test_data_retrieval",
    # Models
    "ColorTheme",
    "THEME",
    "InterfaceInfo",
    "FirewallInfo",
    "ViewerSelection",
    "InterfaceCache",
    "InterfaceTrafficData",
    # Constants
    "HISTORY_SIZE",
    "POLLING_INTERVALS",
]

