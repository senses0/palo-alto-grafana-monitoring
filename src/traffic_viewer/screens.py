"""
Screen classes for the Traffic Viewer.

Contains:
- SplashScreen: Initial splash screen with loading animation
- SelectionScreen: Screen for firewall interface selection
- MonitorScreen: Screen for real-time traffic monitoring
"""

from collections import OrderedDict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import (
    Footer, Static, Button, Label,
    Tree, Select, DataTable
)
from textual.containers import Container, Horizontal, HorizontalScroll, Vertical, VerticalScroll, Center, Middle
from textual.binding import Binding
from textual.reactive import reactive
from textual import on
from textual.timer import Timer

from rich.text import Text

from src.utils.logger import get_logger
from src.palo_alto_client.client import PaloAltoClient
from src.stats.network_interfaces import InterfaceStats

from .constants import HISTORY_SIZE, POLLING_INTERVALS
from .models import (
    THEME, InterfaceInfo, FirewallInfo, ViewerSelection,
    InterfaceCache, InterfaceTrafficData, CounterPollRecord,
    BRAILLE_LEVELS_PER_ROW, get_braille_char
)
from .utils import natural_sort_key, save_interface_selection, load_interface_selection
from .widgets import IndeterminateProgress

logger = get_logger(__name__)


# ============================================================================
# Splash Screen - Initial Loading
# ============================================================================

class SplashScreen(Screen):
    """Initial splash screen with animated loading indicator.
    
    This screen displays while connecting to firewalls and discovering
    available interfaces. No header bar is shown for a clean appearance.
    """
    
    BINDINGS = [
        Binding("q", "quit_app", "Quit", show=False),
        Binding("escape", "quit_app", "Quit", show=False),
    ]
    
    def __init__(self):
        super().__init__()
        self._loading_failed: bool = False
        self._error_message: str = ""
    
    def compose(self) -> ComposeResult:
        """Compose the splash screen UI - no Header for clean look."""
        # Outer container for full centering
        with Center(id="splash-outer"):
            with Middle():
                with Vertical(id="splash-content"):
                    yield Static(
                        "[bold]█▀█ ▄▀█ █   █▀█   ▄▀█ █   ▀█▀ █▀█[/bold]\n"
                        "[bold]█▀▀ █▀█ █▄▄ █▄█   █▀█ █▄▄  █  █▄█[/bold]",
                        classes="splash-title"
                    )
                    yield Static("Traffic Viewer", classes="splash-subtitle")
                    yield IndeterminateProgress(id="splash-progress")
                    yield Static("Connecting to firewalls...", id="splash-status", classes="splash-status")
    
    async def on_mount(self) -> None:
        """Start loading data when mounted."""
        # Small delay to let the UI render, then start loading
        self.set_timer(0.5, self._start_loading)
    
    def _start_loading(self) -> None:
        """Begin the actual data loading process."""
        self.call_later(self._load_data_async)
    
    def _load_data_async(self) -> None:
        """Load firewall and interface data asynchronously."""
        try:
            self._update_status("Initializing API client...")
            
            # Initialize client
            self.app.client = PaloAltoClient()
            self.app.interface_stats = InterfaceStats(self.app.client)
            
            self._update_status("Discovering firewalls...")
            
            # Get firewall summary
            summary = self.app.client.get_firewall_summary()
            
            self._update_status("Querying interface data...")
            
            # Get interface info for all firewalls
            interface_data = self.app.interface_stats.get_interface_info()
            
            # Build firewall list
            firewalls: List[FirewallInfo] = []
            all_interfaces: Dict[str, InterfaceInfo] = {}
            
            for fw_name, config in summary.get('firewalls', {}).items():
                # Skip disabled firewalls
                if not config.get('enabled', True):
                    logger.debug(f"Skipping disabled firewall: {fw_name}")
                    continue
                
                fw = FirewallInfo(
                    name=fw_name,
                    hostname=self.app.client.get_hostname(fw_name),
                    host=config.get('host', 'Unknown'),
                    description=config.get('description', ''),
                    location=config.get('location', ''),
                    interfaces=[]
                )
                
                # Get interfaces for this firewall
                if fw_name in interface_data:
                    fw_data = interface_data[fw_name]
                    if fw_data.get('success'):
                        fw.interfaces = self._parse_interfaces(fw_name, fw_data.get('data', {}))
                
                firewalls.append(fw)
            
            # Sort firewalls by name
            firewalls.sort(key=lambda fw: natural_sort_key(fw.name))
            
            # Build interface map
            for fw in firewalls:
                for iface in fw.interfaces:
                    all_interfaces[iface.id] = iface
            
            # Create and populate cache
            from .models import InterfaceCache
            self.app.cache = InterfaceCache()
            self.app.cache.firewalls = firewalls
            self.app.cache.all_interfaces = all_interfaces.copy()
            self.app.cache.client = self.app.client
            self.app.cache.timestamp = datetime.now()
            
            self._update_status(f"Found {len(firewalls)} firewalls, {len(all_interfaces)} interfaces ✓")
            
            # Pause to let users see the splash screen before transitioning
            self.set_timer(2.5, self._transition_to_selection)
            
        except Exception as e:
            logger.exception("Failed to load firewall data")
            self._loading_failed = True
            self._error_message = self._format_error_message(e)
            self._show_error()
    
    def _parse_interfaces(self, firewall_name: str, data: Dict) -> List[InterfaceInfo]:
        """Parse interface data into InterfaceInfo objects."""
        interfaces = []
        
        interface_info = data.get('interface_info', {})
        
        # Get hardware interfaces for status/speed
        hw_entries = interface_info.get('hw', {}).get('entry', [])
        if isinstance(hw_entries, dict):
            hw_entries = [hw_entries]
        hw_lookup = {e.get('name'): e for e in hw_entries if e.get('name')}
        
        # Get logical interfaces
        ifnet_entries = interface_info.get('ifnet', {}).get('entry', [])
        if isinstance(ifnet_entries, dict):
            ifnet_entries = [ifnet_entries]
        
        for entry in ifnet_entries:
            name = entry.get('name')
            if not name:
                continue
            
            hw_info = hw_lookup.get(name, {})
            
            iface = InterfaceInfo(
                name=name,
                firewall=firewall_name,
                status=hw_info.get('st', 'N/A'),
                speed=hw_info.get('speed', 'N/A'),
                zone=entry.get('zone'),
                ip=entry.get('ip'),
                fwd=entry.get('fwd')
            )
            interfaces.append(iface)
        
        # Natural sort
        interfaces.sort(key=lambda x: natural_sort_key(x.name))
        return interfaces
    
    def _update_status(self, message: str) -> None:
        """Update the status message on the splash screen."""
        try:
            status = self.query_one("#splash-status", Static)
            status.update(f"[{THEME.warning}]{message}[/{THEME.warning}]")
        except Exception:
            pass  # Widget might not be ready
    
    def _show_error(self) -> None:
        """Display error state on splash screen."""
        try:
            status = self.query_one("#splash-status", Static)
            status.update(
                f"[bold {THEME.error}]Connection Failed[/bold {THEME.error}]\n"
                f"[{THEME.text_dim}]{self._error_message}[/{THEME.text_dim}]\n\n"
                f"[{THEME.text_dim}]Press [bold]Q[/bold] to quit or [bold]R[/bold] to retry[/{THEME.text_dim}]"
            )
            status.add_class("splash-error")
            
            # Hide the progress bar on error
            progress = self.query_one("#splash-progress", IndeterminateProgress)
            progress.display = False
            
            # Add retry binding
            self._retry_available = True
        except Exception:
            pass
    
    def _format_error_message(self, error: Exception) -> str:
        """Format error message for user display."""
        error_str = str(error)
        
        if "Connection refused" in error_str or "timeout" in error_str.lower():
            return "Connection failed - check firewall connectivity and API settings"
        elif "Authentication" in error_str or "401" in error_str:
            return "Authentication failed - verify API key and permissions"
        elif "SSL" in error_str or "certificate" in error_str.lower():
            return "SSL/TLS error - check certificate settings"
        else:
            return error_str[:100] + "..." if len(error_str) > 100 else error_str
    
    def _transition_to_selection(self) -> None:
        """Transition to the selection screen."""
        self.app.switch_screen("selection")
    
    def action_quit_app(self) -> None:
        """Quit the application."""
        self.app.exit()
    
    def key_r(self) -> None:
        """Handle R key for retry."""
        if self._loading_failed:
            self._loading_failed = False
            self._error_message = ""
            
            # Reset UI
            try:
                status = self.query_one("#splash-status", Static)
                status.update(f"[{THEME.warning}]Retrying...[/{THEME.warning}]")
                status.remove_class("splash-error")
                
                progress = self.query_one("#splash-progress", IndeterminateProgress)
                progress.display = True
            except Exception:
                pass
            
            # Retry loading
            self.set_timer(0.3, self._start_loading)


class SelectionScreen(Screen):
    """Screen for firewall interface selection.
    
    This screen is shown after SplashScreen has loaded the firewall data.
    Data is expected to be available in app.cache when this screen mounts.
    """

    BINDINGS = [
        Binding("q", "quit_app", "Quit"),
        Binding("space", "toggle_select", "Toggle Selection", show=True, priority=True),
        Binding("a", "select_all", "Select All"),
        Binding("n", "select_none", "Clear All"),
        Binding("u", "select_up", "UP Only"),
        Binding("s", "save_selection", "Save Selection"),
        Binding("f", "force_refresh", "Force Refresh"),
        Binding("enter", "proceed", "Proceed"),
        Binding("escape", "quit_app", "Cancel"),
    ]
    
    selected_count = reactive(0)
    polling_interval = reactive(10)  # Default 10 seconds
    
    def __init__(self):
        super().__init__()
        self.firewalls: List[FirewallInfo] = []
        self.all_interfaces: Dict[str, InterfaceInfo] = {}
        self.selected_interfaces: set = set()
    
    def compose(self) -> ComposeResult:
        """Compose the UI."""
        # No Header widget - using compact header instead

        with Container(id="main-container"):
            yield Static(
                "[bold cyan]Select Interfaces[/bold cyan] [dim]│ ↑↓ Navigate • Space Toggle • Enter Proceed[/dim]",
                id="header-panel"
            )

            yield Tree("Firewalls", id="firewall-tree")

            with Horizontal(id="options-bar"):
                yield Label("⏱️  Polling Interval:", id="polling-label")
                yield Select(
                    [(label, value) for value, label in POLLING_INTERVALS],
                    value=10,  # Default to 10 seconds
                    id="polling-select",
                    allow_blank=False,
                )

            with Horizontal(id="button-bar"):
                yield Button("📋 Select All (A)", id="select-all-btn")
                yield Button("🗑️  Clear (N)", id="clear-btn")
                yield Button("🟢 UP Only (U)", id="up-only-btn")
                yield Button("🔄 Refresh (F)", id="refresh-btn")
                yield Button("▶️  Proceed (Enter)", id="proceed-btn")
                yield Button("❌ Cancel (Esc)", id="cancel-btn")

            yield Static(
                "[dim]Selected: [/dim][bold green]0[/bold green][dim] interfaces • Ready to proceed[/dim]",
                id="status-bar"
            )

        yield Footer()
    
    async def on_mount(self) -> None:
        """Called when screen is mounted - data should be pre-loaded by SplashScreen."""
        # Restore previous selection if returning from monitor
        if self.app.previous_selection:
            self.selected_interfaces = {iface.id for iface in self.app.previous_selection.interfaces}
            self.polling_interval = self.app.previous_selection.polling_interval

        # Load data from cache (populated by SplashScreen)
        self._load_from_cache()
    
    def on_screen_resume(self) -> None:
        """Called when returning to this screen from another screen."""
        # Restore selection from previous_selection if set (coming back from monitor)
        if self.app.previous_selection:
            self.selected_interfaces = {iface.id for iface in self.app.previous_selection.interfaces}
            self.polling_interval = self.app.previous_selection.polling_interval
            
            # Update the polling select widget
            try:
                self.query_one("#polling-select", Select).value = self.polling_interval
            except Exception:
                pass
            
            # Refresh the tree to show restored selection
            if self.all_interfaces:
                self._refresh_tree()

    def _load_from_cache(self) -> None:
        """Load firewall data from app cache (populated by SplashScreen)."""
        if self.app.cache and self.app.cache.is_valid():
            logger.info("Loading interface data from cache")
            self.firewalls = self.app.cache.firewalls
            self.all_interfaces = self.app.cache.all_interfaces.copy()
            
            # Restore previous selection if available
            if self.app.previous_selection:
                self.selected_interfaces = {iface.id for iface in self.app.previous_selection.interfaces}
                self.polling_interval = self.app.previous_selection.polling_interval
        else:
            logger.warning("No cached data available - this shouldn't happen after SplashScreen")
            self.notify("No data available. Try refreshing (F).", severity="error")
            return
        
        # Populate tree
        self._populate_tree()

        # Auto-load saved selection on fresh startup (not when returning from monitor)
        if not self.app.previous_selection and not self.selected_interfaces:
            self._auto_load_saved_selection()
            # Refresh tree to show loaded selection checkboxes
            if self.selected_interfaces:
                self._refresh_tree()

        # Show all controls
        self.query_one("#firewall-tree").display = True
        self.query_one("#options-bar").display = True
        self.query_one("#button-bar").display = True

        # Restore polling interval to the Select widget if we have a previous selection or auto-loaded
        if self.app.previous_selection or self.selected_interfaces:
            self.query_one("#polling-select", Select).value = self.polling_interval

        # Focus tree
        tree = self.query_one("#firewall-tree")
        tree.focus()

        # Auto-expand all firewalls for better UX
        for fw_node in tree.root.children:
            fw_node.expand()
        
        # Update status bar to show restored selection count
        self._update_status()
    
    def _parse_interfaces(self, firewall_name: str, data: Dict) -> List[InterfaceInfo]:
        """Parse interface data into InterfaceInfo objects."""
        interfaces = []
        
        interface_info = data.get('interface_info', {})
        
        # Get hardware interfaces for status/speed
        hw_entries = interface_info.get('hw', {}).get('entry', [])
        if isinstance(hw_entries, dict):
            hw_entries = [hw_entries]
        hw_lookup = {e.get('name'): e for e in hw_entries if e.get('name')}
        
        # Get logical interfaces
        ifnet_entries = interface_info.get('ifnet', {}).get('entry', [])
        if isinstance(ifnet_entries, dict):
            ifnet_entries = [ifnet_entries]
        
        for entry in ifnet_entries:
            name = entry.get('name')
            if not name:
                continue
            
            hw_info = hw_lookup.get(name, {})
            
            iface = InterfaceInfo(
                name=name,
                firewall=firewall_name,
                status=hw_info.get('st', 'N/A'),
                speed=hw_info.get('speed', 'N/A'),
                zone=entry.get('zone'),
                ip=entry.get('ip'),
                fwd=entry.get('fwd')
            )
            interfaces.append(iface)
        
        # Natural sort
        interfaces.sort(key=lambda x: natural_sort_key(x.name))
        return interfaces
    
    def _populate_tree(self) -> None:
        """Populate the tree with firewalls and interfaces."""
        tree = self.query_one("#firewall-tree", Tree)
        tree.clear()
        tree.root.expand()

        for fw in self.firewalls:
            # Create firewall node with better styling
            fw_label = Text()
            fw_label.append(f"{fw.name}", style=f"bold {THEME.text}")
            fw_label.append(f" ({fw.hostname})", style=THEME.text_dim)
            if fw.description:
                fw_label.append(f" • {fw.description}", style=f"italic {THEME.text_dim}")
            if fw.location:
                fw_label.append(f" 📍 {fw.location}", style=f"dim {THEME.warning}")

            fw_node = tree.root.add(fw_label, expand=False, data={"type": "firewall", "name": fw.name})

            # Add column headers with better styling
            header = Text()
            header.append("  Interface         Status   Details          Zone         Forward",
                         style=f"bold {THEME.text_dim}")
            fw_node.add_leaf(header, data={"type": "header"})

            # Add interfaces
            for iface in fw.interfaces:
                self._add_interface_node(fw_node, iface)
    
    def _add_interface_node(self, parent, iface: InterfaceInfo) -> None:
        """Add an interface node to the tree."""
        is_selected = iface.id in self.selected_interfaces
        
        label = Text()
        
        # Selection checkbox
        if is_selected:
            label.append("☑ ", style="bold green")
        else:
            label.append("☐ ", style="dim")
        
        # Interface details
        label.append_text(iface.display_label())
        
        parent.add_leaf(label, data={"type": "interface", "id": iface.id, "interface": iface})
    
    def _refresh_tree(self) -> None:
        """Refresh tree to show current selection state."""
        # Save current expansion state
        tree = self.query_one("#firewall-tree", Tree)
        expanded_nodes = set()

        # Walk through all nodes starting from root
        def walk_tree(node):
            if node.data and node.data.get("type") == "firewall" and node.is_expanded:
                expanded_nodes.add(node.data.get("name"))
            for child in node.children:
                walk_tree(child)

        walk_tree(tree.root)

        # Repopulate tree
        self._populate_tree()

        # Restore expansion state
        def restore_expansion(node):
            if node.data and node.data.get("type") == "firewall":
                fw_name = node.data.get("name")
                if fw_name in expanded_nodes:
                    node.expand()
            for child in node.children:
                restore_expansion(child)

        restore_expansion(tree.root)

        self._update_status()
    
    def _update_status(self) -> None:
        """Update the status bar with better formatting and responsiveness."""
        count = len(self.selected_interfaces)
        status = self.query_one("#status-bar", Static)

        if count == 0:
            status.update(
                f"[{THEME.text_dim}]Selected: [/]"
                f"[bold {THEME.warning}]0[/] "
                f"[{THEME.text_dim}]interfaces • Use Space to select • Enter to proceed[/]"
            )
        else:
            # Show selected count with progress indicator
            total_interfaces = len(self.all_interfaces)
            percentage = (count / total_interfaces) * 100 if total_interfaces > 0 else 0

            # Create a mini progress bar
            bar_width = 20
            filled = int((count / total_interfaces) * bar_width) if total_interfaces > 0 else 0
            progress_bar = "█" * filled + "░" * (bar_width - filled)

            # List selected interfaces (responsive)
            names = [self.all_interfaces[id].name for id in sorted(self.selected_interfaces)]
            if len(names) <= 3:
                names_str = ", ".join(names)
            elif len(names) <= 6:
                names_str = ", ".join(names[:3]) + f", ... (+{len(names)-3})"
            else:
                names_str = f"{len(names)} interfaces selected"

            status.update(
                f"[{THEME.text_dim}]Selected: [/]"
                f"[bold {THEME.success}]{count}[/]"
                f"[{THEME.text_dim}]/[/]{total_interfaces} "
                f"[{THEME.primary}]{progress_bar}[/] "
                f"[{THEME.text_dim}]{names_str}[/]"
            )
    
    def _toggle_interface(self, interface_id: str) -> None:
        """Toggle selection for an interface."""
        if interface_id in self.selected_interfaces:
            self.selected_interfaces.remove(interface_id)
        else:
            self.selected_interfaces.add(interface_id)
        self._refresh_tree()
    
    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Handle tree node selection (click or Enter on a node)."""
        node_data = event.node.data
        if node_data and node_data.get("type") == "interface":
            interface_id = node_data.get("id")
            if interface_id:
                self._toggle_interface(interface_id)
    
    @on(Select.Changed, "#polling-select")
    def on_polling_changed(self, event: Select.Changed) -> None:
        """Handle polling interval selection change."""
        if event.value is not None:
            self.polling_interval = event.value
    
    def action_toggle_select(self) -> None:
        """Toggle selection on currently highlighted node."""
        tree = self.query_one("#firewall-tree", Tree)
        if tree.cursor_node and tree.cursor_node.data:
            node_data = tree.cursor_node.data
            if node_data.get("type") == "interface":
                interface_id = node_data.get("id")
                if interface_id:
                    self._toggle_interface(interface_id)
    
    def action_select_all(self) -> None:
        """Select all interfaces."""
        self.selected_interfaces = set(self.all_interfaces.keys())
        self._refresh_tree()
    
    def action_select_none(self) -> None:
        """Clear all selections."""
        self.selected_interfaces.clear()
        self._refresh_tree()
    
    def action_select_up(self) -> None:
        """Select only UP interfaces."""
        self.selected_interfaces = {
            id for id, iface in self.all_interfaces.items()
            if iface.is_up
        }
        self._refresh_tree()

    def action_save_selection(self) -> None:
        """Save current interface selection."""
        if not self.selected_interfaces:
            self.notify("No interfaces selected to save!", severity="warning")
            return

        # Create selection object
        interfaces = [self.all_interfaces[id] for id in self.selected_interfaces]
        selection = ViewerSelection(interfaces=interfaces, polling_interval=self.polling_interval)

        # Save to disk
        save_interface_selection(selection)
        self.notify(f"Saved selection with {len(interfaces)} interfaces", severity="information")

    def _auto_load_saved_selection(self) -> None:
        """Auto-load saved interface selection on startup."""
        saved_data = load_interface_selection()
        if not saved_data:
            return

        # Restore selection
        loaded_interfaces = []
        for iface_data in saved_data.get('interfaces', []):
            # Find matching interface by id
            iface_id = iface_data.get('id')
            if iface_id in self.all_interfaces:
                loaded_interfaces.append(self.all_interfaces[iface_id])

        if loaded_interfaces:
            self.selected_interfaces = {iface.id for iface in loaded_interfaces}
            self.polling_interval = saved_data.get('polling_interval', 10)
            logger.info(f"Auto-loaded saved selection with {len(loaded_interfaces)} interfaces")

    def action_force_refresh(self) -> None:
        """Force refresh interface data from firewalls (clear cache)."""
        # Clear the cache to force re-query
        if self.app.cache:
            self.app.cache.clear()
        
        # Clear current data
        self.firewalls.clear()
        self.all_interfaces.clear()
        self.selected_interfaces.clear()
        
        # Clear previous selection when forcing refresh
        self.app.previous_selection = None
        
        # Go back to splash screen to reload
        self.notify("Refreshing interface data from firewalls...", severity="information")
        self.app.switch_screen("splash")
    
    def action_proceed(self) -> None:
        """Proceed with selected interfaces."""
        if not self.selected_interfaces:
            self.notify("No interfaces selected!", severity="warning")
            return
        
        # Build selection with interfaces and polling interval
        interfaces = [
            self.all_interfaces[id] for id in self.selected_interfaces
        ]
        selection = ViewerSelection(
            interfaces=interfaces,
            polling_interval=self.polling_interval
        )
        
        # Store selection in app
        self.app.current_selection = selection
        
        # Push a NEW MonitorScreen instance to avoid any caching issues
        # This ensures on_mount is always called with fresh state
        self.app.push_screen(MonitorScreen())
    
    def action_quit_app(self) -> None:
        """Quit the application."""
        self.app.exit()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        button_id = event.button.id
        
        if button_id == "select-all-btn":
            self.action_select_all()
        elif button_id == "clear-btn":
            self.action_select_none()
        elif button_id == "up-only-btn":
            self.action_select_up()
        elif button_id == "refresh-btn":
            self.action_force_refresh()
        elif button_id == "proceed-btn":
            self.action_proceed()
        elif button_id == "cancel-btn":
            self.action_quit_app()


# ============================================================================
# Real-time Traffic Monitoring Screen
# ============================================================================

class MonitorScreen(Screen):
    """Screen for real-time traffic monitoring."""

    BINDINGS = [
        Binding("q", "quit_app", "Quit"),
        Binding("b", "go_back", "Back to Selection"),
        Binding("p", "toggle_pause", "Pause/Resume"),
        Binding("r", "reset_stats", "Reset Stats"),
        Binding("escape", "quit_app", "Exit"),
    ]
    
    is_paused = reactive(False)
    
    def __init__(self):
        super().__init__()
        # Traffic data is stored in app for persistence across screen instances
        # Local reference for convenience (set in on_mount)
        self.poll_timer: Optional[Timer] = None
        self.last_poll_time: Optional[datetime] = None
        self.consecutive_errors: int = 0
        self.max_consecutive_errors: int = 3
    
    @property
    def traffic_data(self) -> OrderedDict:
        """Access traffic data from app (persists across screen instances)."""
        return self.app.traffic_data
    
    @property
    def poll_count(self) -> int:
        """Access poll count from app (persists across screen instances)."""
        return self.app.poll_count
    
    @poll_count.setter
    def poll_count(self, value: int) -> None:
        """Set poll count in app."""
        self.app.poll_count = value

    def _initialize_traffic_data(self) -> None:
        """Initialize or merge traffic data from current selection.
        
        - Preserves existing data for interfaces that are still selected
        - Adds new entries for newly selected interfaces
        - Removes entries for deselected interfaces
        """
        selection = self.app.current_selection
        if not selection:
            logger.warning("_initialize_traffic_data called with no selection!")
            return
        
        # Get current selection interface IDs
        current_ids = {iface.id for iface in selection.interfaces}
        existing_ids = set(self.app.traffic_data.keys())
        
        logger.info(f"_initialize_traffic_data: selection has {len(current_ids)} interfaces, existing data has {len(existing_ids)}")
        
        # Determine what changed
        to_keep = current_ids & existing_ids  # Interfaces still selected
        to_add = current_ids - existing_ids   # New interfaces
        to_remove = existing_ids - current_ids  # Deselected interfaces
        
        # Log changes
        if to_add:
            logger.info(f"Adding {len(to_add)} new interfaces: {to_add}")
        if to_remove:
            logger.info(f"Removing {len(to_remove)} deselected interfaces: {to_remove}")
        if to_keep:
            logger.info(f"Keeping {len(to_keep)} interfaces with existing history")
        
        # Remove deselected interfaces
        for iface_id in to_remove:
            del self.app.traffic_data[iface_id]
        
        # Add new interfaces - build from selection to ensure fresh data
        iface_lookup = {iface.id: iface for iface in selection.interfaces}
        for iface_id in to_add:
            iface = iface_lookup[iface_id]
            self.app.traffic_data[iface_id] = InterfaceTrafficData(
                interface_id=iface.id,
                interface_name=iface.name,
                firewall=iface.firewall,
            )
        
        # Re-sort to maintain consistent display order (firewall name, then interface name)
        sorted_items = sorted(
            self.app.traffic_data.items(),
            key=lambda item: (natural_sort_key(item[1].firewall), natural_sort_key(item[1].interface_name))
        )
        self.app.traffic_data.clear()
        for key, value in sorted_items:
            self.app.traffic_data[key] = value
        
        logger.info(f"Traffic data after merge: {len(self.app.traffic_data)} interfaces")
    
    def compose(self) -> ComposeResult:
        """Compose the monitoring UI."""
        # Get selection from app (will be set before screen is pushed)
        selection = self.app.current_selection
        num_interfaces = len(selection.interfaces) if selection else 0
        polling_interval = selection.polling_interval if selection else 10
        
        # No Header widget - using compact combined header instead
        
        with Container(id="traffic-container"):
            # Combined compact header: legend + interface count in single line
            yield Static(
                f"[#56d364]▲ RX (inbound)[/#56d364]  │  [#58a6ff]▼ TX (outbound)[/#58a6ff]",
                id="legend"
            )
            
            # Stats table (cursor_type="none" disables row selection highlighting)
            yield DataTable(id="stats-table", cursor_type="none")
            
            # Status bar with polling interval selector on the left
            with Horizontal(id="status-footer"):
                yield Static("[dim]Poll[/dim] [bold #56d364]●[/bold #56d364]", id="status-indicator")
                yield Select[int](
                    [(label, value) for value, label in POLLING_INTERVALS],
                    value=polling_interval,
                    id="monitor-polling-select",
                    allow_blank=False,
                )
                yield Static(
                    "[dim]Initializing...[/dim]",
                    id="status-text"
                )
            
            # Graph area - will be populated with per-interface graph+table rows
            with VerticalScroll(id="graph-container"):
                # Per-interface widgets will be mounted here dynamically
                pass
        
        yield Footer()
    
    async def on_mount(self) -> None:
        """Called when screen is mounted."""
        selection = self.app.current_selection
        if not selection:
            self.notify("No selection available!", severity="error")
            return
        
        # Log for debugging
        logger.info(f"MonitorScreen.on_mount: selection has {len(selection.interfaces)} interfaces")
        
        # Determine if this is a resume (we have existing poll history)
        was_polling = self.app.poll_count > 0
        
        # Initialize/merge traffic data from selection
        # This MUST use the latest selection, not cached data
        self._initialize_traffic_data()
        
        if was_polling:
            # Resuming from previous monitoring session
            logger.info(f"Resuming monitoring with {len(self.app.traffic_data)} interfaces, poll_count={self.app.poll_count}")
            self.is_paused = False
            self.consecutive_errors = 0
        else:
            # Fresh start
            logger.info("Starting fresh monitoring session")
            self.is_paused = False
            self.app.poll_count = 0
            self.consecutive_errors = 0
        
        self.last_poll_time = None  # Reset so we don't use stale interval
        
        # Setup data table with columns
        table = self.query_one("#stats-table", DataTable)
        table.add_columns(
            "Interface", "Firewall", "RX Rate", "TX Rate", "RX Peak", "TX Peak"
        )
        
        # Create per-interface widgets
        self._create_interface_widgets()
        
        # Initial table population (shows existing data if resuming)
        self._rebuild_table()
        
        # Update graphs (shows existing history if resuming)
        self._update_graphs()
        
        self._update_status()
        
        # Note: Timer setup moved to on_show for reliability
        logger.info("MonitorScreen.on_mount: complete, waiting for on_show")
    
    def on_show(self) -> None:
        """Called when screen becomes visible - start polling here for reliability."""
        logger.info("MonitorScreen.on_show: starting polling")
        self._start_polling()
    
    def _start_polling(self) -> None:
        """Start the polling timer - called after screen is fully mounted."""
        selection = self.app.current_selection
        if not selection:
            self.notify("No selection - cannot start polling!", severity="error")
            return
        
        # Stop any existing timer first
        if self.poll_timer:
            self.poll_timer.stop()
            self.poll_timer = None
        
        # Update the header with current interface count
        self._update_header()
        
        # Do initial poll immediately
        self._poll_data()
        
        # Start the interval timer
        self.poll_timer = self.set_interval(
            selection.polling_interval,
            self._poll_data
        )
        
        logger.info(f"Polling started: {len(self.app.traffic_data)} interfaces, interval={selection.polling_interval}s")
        
        # Always notify that polling has started
        num_ifaces = len(self.app.traffic_data)
        self.notify(f"Polling started: {num_ifaces} interfaces @ {selection.polling_interval}s", severity="information")
    
    def _update_header(self) -> None:
        """Update the monitor header with current interface count."""
        try:
            header = self.query_one("#monitor-header", Static)
            num_interfaces = len(self.app.traffic_data)
            header.update(
                f"[bold cyan]📊 Real-time Traffic Monitor[/bold cyan]  "
                f"[dim]{num_interfaces} interfaces[/dim]"
            )
        except Exception:
            pass  # Header might not be ready yet
        
        # Also update the polling interval selector to match current selection
        try:
            selection = self.app.current_selection
            if selection:
                poll_select = self.query_one("#monitor-polling-select", Select)
                if poll_select.value != selection.polling_interval:
                    poll_select.value = selection.polling_interval
        except Exception:
            pass
    
    def on_screen_suspend(self) -> None:
        """Called when this screen is suspended (another screen pushed on top)."""
        # Stop polling when screen is not visible
        if self.poll_timer:
            self.poll_timer.stop()
            self.poll_timer = None
    
    def _poll_data(self) -> None:
        """Poll interface counters and update display."""
        if self.is_paused:
            return

        try:
            # Get only interface counters (more efficient than full interface data)
            data = self.app.interface_stats.get_interface_counters()

            now = datetime.now()
            selection = self.app.current_selection
            poll_interval = selection.polling_interval if selection else 10

            # If we have a previous poll time, use actual elapsed time
            if self.last_poll_time:
                poll_interval = (now - self.last_poll_time).total_seconds()

            self.last_poll_time = now

            # Track if any data changed for selective updates
            data_changed = False

            # Update each tracked interface
            for iface_id, traffic in self.traffic_data.items():
                fw_name = traffic.firewall
                iface_name = traffic.interface_name

                if fw_name not in data:
                    continue

                fw_data = data[fw_name]
                if not fw_data.get('success'):
                    continue

                # Get fresh counter data on each poll (don't cache - values change!)
                counters = fw_data.get('data', {}).get('interface_counters', {})

                # Get all counter values
                counter_vals = self._find_interface_counters(counters, iface_name)
                
                ibytes = counter_vals.get('ibytes')
                obytes = counter_vals.get('obytes')

                if ibytes is not None and obytes is not None:
                    old_rx, old_tx = traffic.rx_bps, traffic.tx_bps
                    
                    # Update with all counters including packets, errors, drops
                    traffic.update_counters(
                        ibytes, obytes, poll_interval,
                        ipackets=counter_vals.get('ipackets') or 0,
                        opackets=counter_vals.get('opackets') or 0,
                        ierrors=counter_vals.get('ierrors') or 0,
                        idrops=counter_vals.get('idrops') or 0
                    )
                    
                    # Add counter record to per-interface poll history (only after first poll when we have deltas)
                    if self.poll_count > 0 or traffic.prev_ibytes > 0:
                        record = CounterPollRecord(
                            timestamp=now,
                            firewall=fw_name,
                            interface=iface_name,
                            rx_bps=traffic.rx_bps,
                            tx_bps=traffic.tx_bps,
                            delta_errors=traffic.delta_errors,
                            delta_drops=traffic.delta_drops,
                            tcp_conn=counter_vals.get('tcp_conn') or 0,
                            udp_conn=counter_vals.get('udp_conn') or 0,
                            delta_ibytes=traffic.delta_ibytes,
                            delta_obytes=traffic.delta_obytes
                        )
                        traffic.poll_history.appendleft(record)

                    # Check if rates changed significantly (>1% change)
                    rx_change = abs(traffic.rx_bps - old_rx) / max(old_rx, 1) > 0.01
                    tx_change = abs(traffic.tx_bps - old_tx) / max(old_tx, 1) > 0.01
                    if rx_change or tx_change:
                        data_changed = True

            # Always update both table and graphs for reliable display
            self._rebuild_table()
            self._update_graphs()

            self.poll_count += 1
            self._reset_error_count()  # Reset error counter on success
            self._update_status()

        except Exception as e:
            logger.exception("Error polling data")
            error_msg = self._format_monitor_error(e)
            self._update_status(error=error_msg)

            # Auto-retry logic for temporary failures
            if self.poll_count > 0:  # Don't retry on first failure
                self._handle_polling_error(e)
    
    def _find_interface_counters(self, counters: Dict, iface_name: str) -> Dict[str, Optional[int]]:
        """Find all counters for an interface in counter data.
        
        Returns dict with keys: ibytes, obytes, ipackets, opackets, ierrors, idrops
        """
        result = {
            'ibytes': None, 'obytes': None,
            'ipackets': None, 'opackets': None,
            'ierrors': None, 'idrops': None,
            'tcp_conn': None, 'udp_conn': None
        }
        
        # Check ifnet entries first (as suggested by user)
        ifnet_data = counters.get('ifnet', {})
        # Handle nested ifnet structure
        if 'ifnet' in ifnet_data:
            ifnet_data = ifnet_data['ifnet']

        ifnet_entries = ifnet_data.get('entry', [])
        if isinstance(ifnet_entries, dict):
            ifnet_entries = [ifnet_entries]

        for entry in ifnet_entries:
            if entry.get('name') == iface_name:
                if entry.get('ibytes') is not None:
                    result['ibytes'] = int(entry.get('ibytes'))
                if entry.get('obytes') is not None:
                    result['obytes'] = int(entry.get('obytes'))
                if entry.get('ipackets') is not None:
                    result['ipackets'] = int(entry.get('ipackets'))
                if entry.get('opackets') is not None:
                    result['opackets'] = int(entry.get('opackets'))
                if entry.get('ierrors') is not None:
                    result['ierrors'] = int(entry.get('ierrors'))
                if entry.get('idrops') is not None:
                    result['idrops'] = int(entry.get('idrops'))
                if entry.get('tcp_conn') is not None:
                    result['tcp_conn'] = int(entry.get('tcp_conn'))
                if entry.get('udp_conn') is not None:
                    result['udp_conn'] = int(entry.get('udp_conn'))
                break

        # Fallback/supplement: Check hw entries if ifnet doesn't have all the data
        hw_entries = counters.get('hw', {}).get('entry', [])
        if isinstance(hw_entries, dict):
            hw_entries = [hw_entries]

        for entry in hw_entries:
            if entry.get('name') == iface_name or entry.get('interface') == iface_name:
                # Only fill in missing values
                if result['ibytes'] is None:
                    ibytes = entry.get('ibytes', entry.get('port', {}).get('rx-bytes'))
                    if ibytes is not None:
                        result['ibytes'] = int(ibytes)
                if result['obytes'] is None:
                    obytes = entry.get('obytes', entry.get('port', {}).get('tx-bytes'))
                    if obytes is not None:
                        result['obytes'] = int(obytes)
                if result['ipackets'] is None and entry.get('ipackets') is not None:
                    result['ipackets'] = int(entry.get('ipackets'))
                if result['opackets'] is None and entry.get('opackets') is not None:
                    result['opackets'] = int(entry.get('opackets'))
                if result['ierrors'] is None and entry.get('ierrors') is not None:
                    result['ierrors'] = int(entry.get('ierrors'))
                if result['idrops'] is None and entry.get('idrops') is not None:
                    result['idrops'] = int(entry.get('idrops'))
                break

        return result
    
    def _rebuild_table(self) -> None:
        """Rebuild the stats table with current values."""
        table = self.query_one("#stats-table", DataTable)

        # Clear existing rows
        table.clear()

        # Add rows for each interface with current data
        for iface_id, traffic in self.traffic_data.items():
            # Format rates with color intensity based on value
            rx_rate = InterfaceTrafficData.format_bps(traffic.rx_bps)
            tx_rate = InterfaceTrafficData.format_bps(traffic.tx_bps)
            
            # Color intensity based on rate
            rx_style = self._get_rate_style(traffic.rx_bps, "rx")
            tx_style = self._get_rate_style(traffic.tx_bps, "tx")
            
            # Format total bytes
            rx_total = self._format_bytes(traffic.ibytes)
            tx_total = self._format_bytes(traffic.obytes)
            
            # Calculate peak rates from history
            rx_peak = max(traffic.rx_history) if traffic.rx_history else 0
            tx_peak = max(traffic.tx_history) if traffic.tx_history else 0
            rx_peak_str = InterfaceTrafficData.format_bps(rx_peak)
            tx_peak_str = InterfaceTrafficData.format_bps(tx_peak)
            
            # Add row with formatted values
            table.add_row(
                Text(traffic.interface_name, style="bold white"),
                Text(traffic.firewall, style="dim"),
                Text(f"▲ {rx_rate}", style=rx_style),
                Text(f"▼ {tx_rate}", style=tx_style),
                Text(f"({rx_peak_str})", style="dim #3fb950"),
                Text(f"({tx_peak_str})", style="dim #388bfd"),
            )
    
    def _get_rate_style(self, bps: float, direction: str) -> str:
        """Get style based on rate magnitude and direction."""
        # RX: green shades, TX: blue shades
        if direction == "rx":
            if bps >= 1_000_000_000:  # 1 Gbps+
                return "bold #aff5b4"
            elif bps >= 100_000_000:  # 100 Mbps+
                return "#7ee787"
            elif bps >= 10_000_000:  # 10 Mbps+
                return "#56d364"
            elif bps >= 1_000_000:  # 1 Mbps+
                return "#3fb950"
            else:
                return "#2ea043"
        else:  # tx
            if bps >= 1_000_000_000:
                return "bold #a5d6ff"
            elif bps >= 100_000_000:
                return "#79c0ff"
            elif bps >= 10_000_000:
                return "#58a6ff"
            elif bps >= 1_000_000:
                return "#388bfd"
            else:
                return "#1f6feb"
    
    
    def _create_interface_widgets(self) -> None:
        """Create per-interface graph and table widgets."""
        graph_container = self.query_one("#graph-container", VerticalScroll)
        
        # Remove any existing interface widgets
        for widget in graph_container.query(".interface-row"):
            widget.remove()
        
        # Create widgets for each interface
        for iface_id, traffic in self.traffic_data.items():
            # Sanitize ID for use in widget IDs (replace :: with -)
            safe_id = iface_id.replace("::", "-").replace("/", "-").replace(".", "-")
            
            # Create a horizontal container for this interface
            row = Horizontal(id=f"row-{safe_id}", classes="interface-row")
            
            # Create a scrollable wrapper for the graph (prevents text wrapping)
            graph_scroll = HorizontalScroll(
                id=f"graph-scroll-{safe_id}",
                classes="interface-graph-scroll"
            )
            
            # Create the graph widget (left side, inside scroll container)
            graph_widget = Static(
                "[dim]Loading graph...[/dim]",
                id=f"graph-{safe_id}",
                classes="interface-graph"
            )
            
            # Create the history table widget (right side)
            table_widget = DataTable(
                id=f"table-{safe_id}",
                classes="interface-table",
                cursor_type="none"
            )
            
            # Mount the row first
            graph_container.mount(row)
            
            # Mount scroll container in row, then graph widget inside scroll
            row.mount(graph_scroll)
            graph_scroll.mount(graph_widget)
            row.mount(table_widget)
            
            # Setup table columns
            table_widget.add_columns("Time", "RX Rate", "TX Rate", "RX Vol", "TX Vol", "err", "drp", "tcp", "udp")
    
    def _update_graphs(self) -> None:
        """Update the traffic graphs and per-interface history tables."""
        graph_height = 6  # Number of rows for each direction (RX and TX)
        graph_width = HISTORY_SIZE  # Width matches history size

        for iface_id, traffic in self.traffic_data.items():
            # Sanitize ID
            safe_id = iface_id.replace("::", "-").replace("/", "-").replace(".", "-")
            
            try:
                graph_widget = self.query_one(f"#graph-{safe_id}", Static)
                table_widget = self.query_one(f"#table-{safe_id}", DataTable)
            except Exception:
                # Widget not found, skip (may happen during initialization)
                continue

            # Get max value for scaling with some headroom
            rx_max = max(traffic.rx_history) if traffic.rx_history else max(traffic.rx_bps, 1000)
            tx_max = max(traffic.tx_history) if traffic.tx_history else max(traffic.tx_bps, 1000)
            peak = max(rx_max, tx_max, 1000)
            scale_max = peak * 1.1

            # Format current rates and scale
            rx_rate = InterfaceTrafficData.format_bps(traffic.rx_bps)
            tx_rate = InterfaceTrafficData.format_bps(traffic.tx_bps)
            scale_label = InterfaceTrafficData.format_bps(scale_max)

            # Build graph content
            lines = []
            
            # Header with interface info and scale
            lines.append(
                f"[bold {THEME.text} on {THEME.surface_light}] {traffic.interface_name} [/bold {THEME.text} on {THEME.surface_light}] "
                f"[{THEME.text_dim}]@ {traffic.firewall}[/{THEME.text_dim}]  "
                f"[{THEME.text_dim}]scale: ±{scale_label}[/{THEME.text_dim}]"
            )

            # Activity indicator and peak info
            rx_peak = max(traffic.rx_history) if traffic.rx_history else traffic.rx_bps
            tx_peak = max(traffic.tx_history) if traffic.tx_history else traffic.tx_bps
            activity_indicator = "●" if (traffic.rx_bps > 0 or traffic.tx_bps > 0) else "○"
            activity_color = THEME.success if (traffic.rx_bps > 0 or traffic.tx_bps > 0) else THEME.text_dim
            peak_info = f"↑{InterfaceTrafficData.format_bps(rx_peak)} ↓{InterfaceTrafficData.format_bps(tx_peak)}"
            lines.append(f"[{activity_color}]{activity_indicator}[/{activity_color}] [{THEME.text_dim}]Activity indicator peaks: {peak_info}[/{THEME.text_dim}]")

            # Graph padding
            graph_pad = " " * 11

            # Create RX graph rows (above baseline)
            rx_rows = self._create_area_graph(
                traffic.rx_history, scale_max, graph_height, graph_width,
                direction="up"
            )
            for row in rx_rows:
                lines.append(f"{graph_pad}{row}")

            # Baseline with current rate labels
            baseline = "─" * graph_width
            lines.append(f"[{THEME.rx_green}]▲{rx_rate:>9}[/{THEME.rx_green}] {baseline} [{THEME.tx_blue}]▼{tx_rate:>9}[/{THEME.tx_blue}]")

            # Create TX graph rows (below baseline)
            tx_rows = self._create_area_graph(
                traffic.tx_history, scale_max, graph_height, graph_width,
                direction="down"
            )
            for row in tx_rows:
                lines.append(f"{graph_pad}{row}")

            # Update graph widget and set explicit height so it renders fully
            graph_widget.update("\n".join(lines))
            graph_widget.styles.height = len(lines)
            
            # Update history table
            table_widget.clear()
            for record in traffic.poll_history:
                time_str = record.timestamp.strftime("%H:%M:%S")
                rx_str = InterfaceTrafficData.format_bps(record.rx_bps)
                tx_str = InterfaceTrafficData.format_bps(record.tx_bps)
                
                # Format volume (delta bytes)
                rx_vol_str = InterfaceTrafficData.format_bytes(record.delta_ibytes)
                tx_vol_str = InterfaceTrafficData.format_bytes(record.delta_obytes)
                
                # Style for errors
                if record.delta_errors > 0:
                    err_text = Text(str(record.delta_errors), style=f"bold {THEME.error}")
                else:
                    err_text = Text("0", style=THEME.text_dim)
                
                # Style for drops
                if record.delta_drops > 0:
                    drp_text = Text(str(record.delta_drops), style=f"bold {THEME.warning}")
                else:
                    drp_text = Text("0", style=THEME.text_dim)
                
                # Style for TCP/UDP connections (highlight when > 0)
                if record.tcp_conn > 0:
                    tcp_text = Text(str(record.tcp_conn), style=THEME.primary_light)
                else:
                    tcp_text = Text("0", style=THEME.text_dim)
                
                if record.udp_conn > 0:
                    udp_text = Text(str(record.udp_conn), style=THEME.primary_light)
                else:
                    udp_text = Text("0", style=THEME.text_dim)
                
                table_widget.add_row(
                    Text(time_str, style=THEME.text_dim),
                    Text(rx_str, style=THEME.rx_green),
                    Text(tx_str, style=THEME.tx_blue),
                    Text(rx_vol_str, style=THEME.rx_green_dark),
                    Text(tx_vol_str, style=THEME.tx_blue_dark),
                    err_text,
                    drp_text,
                    tcp_text,
                    udp_text
                )
    
    
    def _create_area_graph(self, history, scale_max: float, height: int, 
                          width: int, direction: str) -> List[str]:
        """
        Create a multi-row FILLED area graph using braille characters.
        
        Braille patterns provide 4x finer vertical resolution than block characters,
        making small traffic variations visible even when dominated by large peaks.
        
        Args:
            history: Deque of values
            scale_max: Maximum value for scaling
            height: Number of rows for the graph
            width: Width of the graph
            direction: "up" for RX (filled from baseline upward)
                      "down" for TX (filled from baseline downward, mirrored)
        
        Returns:
            List of strings, one per row
        """
        empty = '\u2800'  # Braille blank character
        
        # Prepare data - RIGHT-ALIGN so newest data is always at the far right
        data = list(history) if history else []
        
        # Take only the last 'width' items if we have more
        if len(data) > width:
            data = data[-width:]
        
        # Calculate padding (data will appear on the RIGHT)
        padding_count = max(0, width - len(data))
        
        # Pad with None to distinguish "no data yet" from "zero value"
        data = [None] * padding_count + data
        
        # Total levels = rows × braille levels per row (e.g., 6 × 4 = 24)
        total_levels = height * BRAILLE_LEVELS_PER_ROW
        
        # Normalize data to 0-total_levels range for finer resolution
        normalized = []
        for val in data:
            if val is None:
                normalized.append(None)
            else:
                norm = (val / scale_max) * total_levels if scale_max > 0 else 0
                norm = min(total_levels, max(0, norm))
                normalized.append(norm)
        
        # Use theme colors for gradients
        if direction == "up":
            colors = list(THEME.rx_gradient)
        else:
            colors = list(THEME.tx_gradient)
        
        # Ensure we have enough colors for the height
        while len(colors) < height:
            colors.append(colors[-1])
        
        rows = []
        
        if direction == "up":
            # RX: Build from top row (height) down to baseline (1)
            for row_num in range(height, 0, -1):
                row_chars = []
                # This row covers levels from (row_num-1)*4 to row_num*4
                row_base = (row_num - 1) * BRAILLE_LEVELS_PER_ROW
                row_top = row_num * BRAILLE_LEVELS_PER_ROW
                
                for val in normalized:
                    if val is None:
                        row_chars.append(empty)
                    elif val <= row_base:
                        # Value doesn't reach this row
                        row_chars.append(empty)
                    elif val >= row_top:
                        # Value completely fills this row
                        row_chars.append(get_braille_char(1.0, "up"))
                    else:
                        # Value partially fills this row
                        fill_level = (val - row_base) / BRAILLE_LEVELS_PER_ROW
                        row_chars.append(get_braille_char(fill_level, "up"))
                
                row_str = "".join(row_chars)
                # Color: brightest at top (peaks), darker at bottom (baseline)
                color = colors[height - row_num]
                rows.append(f"[{color}]{row_str}[/{color}]")
        else:
            # TX: Build from baseline (1) down to bottom (height)
            for row_num in range(1, height + 1):
                row_chars = []
                # This row covers levels from (row_num-1)*4 to row_num*4
                row_base = (row_num - 1) * BRAILLE_LEVELS_PER_ROW
                row_top = row_num * BRAILLE_LEVELS_PER_ROW
                
                for val in normalized:
                    if val is None:
                        row_chars.append(empty)
                    elif val <= row_base:
                        # Value doesn't reach this row
                        row_chars.append(empty)
                    elif val >= row_top:
                        # Value completely fills this row
                        row_chars.append(get_braille_char(1.0, "down"))
                    else:
                        # Value partially fills this row
                        fill_level = (val - row_base) / BRAILLE_LEVELS_PER_ROW
                        row_chars.append(get_braille_char(fill_level, "down"))
                
                row_str = "".join(row_chars)
                # Color: darker at top (baseline), brighter at bottom (peaks)
                color = colors[row_num - 1]
                rows.append(f"[{color}]{row_str}[/{color}]")
        
        return rows
    
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable string."""
        if bytes_val >= 1_000_000_000_000:
            return f"{bytes_val / 1_000_000_000_000:.2f} TB"
        elif bytes_val >= 1_000_000_000:
            return f"{bytes_val / 1_000_000_000:.2f} GB"
        elif bytes_val >= 1_000_000:
            return f"{bytes_val / 1_000_000:.2f} MB"
        elif bytes_val >= 1_000:
            return f"{bytes_val / 1_000:.2f} KB"
        else:
            return f"{bytes_val} B"
    
    def _update_status(self, error: Optional[str] = None) -> None:
        """Update the status footer."""
        status = self.query_one("#status-text", Static)
        indicator = self.query_one("#status-indicator", Static)
        
        if error:
            indicator.update(f"[dim]Poll[/dim] [bold red]✗[/bold red]")
            status.update(f"[bold red]Error:[/bold red] [red]{error}[/red]")
        elif self.is_paused:
            indicator.update(f"[dim]Poll[/dim] [bold yellow]⏸[/bold yellow]")
            status.update("[bold yellow]PAUSED[/bold yellow] [dim]│ Press [bold]P[/bold] to resume[/dim]")
        else:
            indicator.update(f"[dim]Poll[/dim] [bold #56d364]●[/bold #56d364]")
            last_update = self.last_poll_time.strftime("%H:%M:%S") if self.last_poll_time else "waiting..."
            
            # Calculate aggregate stats
            total_rx = sum(t.rx_bps for t in self.traffic_data.values())
            total_tx = sum(t.tx_bps for t in self.traffic_data.values())
            
            status.update(
                f"[dim]Last:[/dim] {last_update} "
                f"[dim]│ Samples:[/dim] {self.poll_count} "
                f"[dim]│ Total:[/dim] [#56d364]▲{InterfaceTrafficData.format_bps(total_rx)}[/#56d364] "
                f"[#58a6ff]▼{InterfaceTrafficData.format_bps(total_tx)}[/#58a6ff]"
            )
    
    @on(Select.Changed, "#monitor-polling-select")
    def on_monitor_polling_changed(self, event: Select.Changed) -> None:
        """Handle polling interval change in the monitor."""
        selection = self.app.current_selection
        if not selection:
            return
            
        if event.value is not None and event.value != selection.polling_interval:
            old_interval = selection.polling_interval
            selection.polling_interval = event.value
            
            # Cancel existing timer and create new one with the new interval
            if self.poll_timer:
                self.poll_timer.stop()
            
            self.poll_timer = self.set_interval(
                selection.polling_interval, 
                self._poll_data
            )
            
            self.notify(
                f"Polling interval: {old_interval}s → {event.value}s",
                severity="information"
            )
            self._update_status()
    
    def action_toggle_pause(self) -> None:
        """Toggle pause/resume polling."""
        self.is_paused = not self.is_paused
        self._update_status()
        self.notify(
            "Polling paused" if self.is_paused else "Polling resumed",
            severity="warning" if self.is_paused else "information"
        )
    
    def action_reset_stats(self) -> None:
        """Reset all statistics (clears all data including history)."""
        for traffic in self.app.traffic_data.values():
            traffic.rx_history.clear()
            traffic.tx_history.clear()
            traffic.poll_history.clear()
            traffic.rx_bps = 0
            traffic.tx_bps = 0
            traffic.prev_ibytes = traffic.ibytes
            traffic.prev_obytes = traffic.obytes

        self.app.poll_count = 0
        self._rebuild_table()
        self._update_graphs()
        self._update_status()
        self.notify("Statistics reset", severity="information")

    def _format_monitor_error(self, error: Exception) -> str:
        """Format error message for monitor display."""
        error_str = str(error)

        if "Connection refused" in error_str:
            return "Connection lost - checking firewall availability"
        elif "timeout" in error_str.lower():
            return "Request timeout - firewall may be busy"
        elif "Authentication" in error_str:
            return "Auth failed - API key may be invalid"
        else:
            return f"Poll error: {error_str[:50]}..."

    def _handle_polling_error(self, error: Exception) -> None:
        """Handle polling errors with recovery logic."""
        self.consecutive_errors += 1

        if self.consecutive_errors >= self.max_consecutive_errors:
            # Auto-pause on repeated failures
            if not self.is_paused:
                self.is_paused = True
                self.notify(
                    f"Auto-paused after {self.consecutive_errors} consecutive errors. Press P to resume.",
                    severity="error"
                )
        else:
            # Brief pause on temporary failures
            self.notify(f"Temporary error ({self.consecutive_errors}/{self.max_consecutive_errors})",
                       severity="warning")

    def _reset_error_count(self) -> None:
        """Reset consecutive error counter on successful poll."""
        if self.consecutive_errors > 0:
            self.consecutive_errors = 0
            if self.is_paused:
                self.notify("Connection restored - monitoring resumed", severity="information")
    
    def action_go_back(self) -> None:
        """Go back to interface selection screen."""
        # Stop polling timer before leaving
        if self.poll_timer:
            self.poll_timer.stop()
            self.poll_timer = None
        
        # Store current selection for restoration
        self.app.previous_selection = self.app.current_selection
        
        # Pop this screen to return to selection
        self.app.pop_screen()
    
    def action_quit_app(self) -> None:
        """Quit the application."""
        # Stop polling timer
        if self.poll_timer:
            self.poll_timer.stop()
            self.poll_timer = None
        
        self.app.exit()

