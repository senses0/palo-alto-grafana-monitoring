"""
Custom widgets for the Traffic Viewer.

Contains:
- InterfaceTree: Custom tree widget for firewall/interface selection
- IndeterminateProgress: Animated indeterminate progress bar
"""

from typing import Dict, List

from rich.progress import Progress, BarColumn
from textual.widgets import Tree, Static
from textual.message import Message

from .models import InterfaceInfo, THEME


class IndeterminateProgress(Static):
    """Animated indeterminate progress bar using Rich Progress.
    
    Creates a smooth animated loading indicator that pulses back and forth,
    ideal for splash screens where loading time is unknown.
    """
    
    def __init__(self, id: str = None, classes: str = None):
        super().__init__("", id=id, classes=classes)
        self._bar = Progress(
            BarColumn(bar_width=40, style=THEME.primary_dark, complete_style=THEME.primary, pulse_style=THEME.primary_light)
        )
        self._task = self._bar.add_task("", total=None)  # Indeterminate progress
    
    def on_mount(self) -> None:
        """Start the animation when mounted."""
        self._update_timer = self.set_interval(1 / 60, self._update_progress)
    
    def _update_progress(self) -> None:
        """Update the progress bar display at 60fps for smooth animation."""
        self.update(self._bar)


class InterfaceTree(Tree):
    """Custom tree widget for firewall/interface selection."""
    
    class SelectionChanged(Message):
        """Message sent when selection changes."""
        def __init__(self, selected: List[str]) -> None:
            self.selected = selected
            super().__init__()
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.selected_interfaces: set = set()
        self.interface_map: Dict[str, InterfaceInfo] = {}
    
    def toggle_selection(self, interface_id: str):
        """Toggle selection for an interface."""
        if interface_id in self.selected_interfaces:
            self.selected_interfaces.remove(interface_id)
        else:
            self.selected_interfaces.add(interface_id)
        self.post_message(self.SelectionChanged(list(self.selected_interfaces)))
        self.refresh()

