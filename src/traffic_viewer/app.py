"""
Main application class and entry points for the Traffic Viewer.

Contains:
- TrafficViewerApp: Main Textual application class
- main: Main entry point function
- test_data_retrieval: Test function for data retrieval
"""

import sys
from collections import OrderedDict
from typing import Optional

from textual.app import App

from src.utils.logger import get_logger, suppress_console_logging
from src.palo_alto_client.client import PaloAltoClient
from src.stats.network_interfaces import InterfaceStats

from .models import ViewerSelection, InterfaceCache
from .styles import get_splash_css, get_css, get_monitor_css
from .screens import SplashScreen, SelectionScreen, MonitorScreen

# Suppress console logging for TUI - logs still go to file
suppress_console_logging()

logger = get_logger(__name__)


class TrafficViewerApp(App):
    """Main application with seamless screen-based navigation."""

    TITLE = "Palo Alto Traffic Viewer"
    ENABLE_COMMAND_PALETTE = False  # Disable command palette dropdown
    
    # Combine CSS from all screens
    CSS = get_splash_css() + get_css() + get_monitor_css()
    
    SCREENS = {
        "splash": SplashScreen,
        "selection": SelectionScreen,
        "monitor": MonitorScreen,
    }
    
    def __init__(self):
        super().__init__()
        # Shared state across screens
        self.client: Optional[PaloAltoClient] = None
        self.interface_stats: Optional[InterfaceStats] = None
        self.cache: Optional[InterfaceCache] = None
        self.current_selection: Optional[ViewerSelection] = None
        self.previous_selection: Optional[ViewerSelection] = None
        # Traffic data persists across screen instances for seamless resume
        self.traffic_data: OrderedDict = OrderedDict()  # OrderedDict[str, InterfaceTrafficData]
        self.poll_count: int = 0  # Persistent poll counter
    
    def on_mount(self) -> None:
        """Called when app is mounted - start with splash screen."""
        self.push_screen("splash")


def main():
    """Main entry point."""
    try:
        app = TrafficViewerApp()
        app.run()
        
    except KeyboardInterrupt:
        # Clean exit on Ctrl+C
        pass
    except Exception as e:
        from rich.console import Console
        console = Console()
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("Fatal error")
        sys.exit(1)


def test_data_retrieval():
    """Test function to check if data retrieval is working."""
    from src.palo_alto_client.client import PaloAltoClient
    from src.stats.network_interfaces import InterfaceStats

    print("Testing data retrieval...")

    try:
        client = PaloAltoClient()
        interface_stats = InterfaceStats(client)

        # Get data
        data = interface_stats.get_interface_data()
        print(f"Retrieved data for {len(data)} firewalls")

        for fw_name, fw_data in data.items():
            print(f"Firewall {fw_name}: success={fw_data.get('success')}")
            if fw_data.get('success'):
                counters = fw_data.get('data', {}).get('interface_counters', {})
                print(f"  Has counters: {bool(counters)}")
                if counters:
                    hw_entries = counters.get('hw', {}).get('entry', [])
                    
                    # Handle nested ifnet structure (ifnet.ifnet.entry)
                    ifnet_data = counters.get('ifnet', {})
                    if 'ifnet' in ifnet_data:
                        ifnet_data = ifnet_data['ifnet']
                    ifnet_entries = ifnet_data.get('entry', [])
                    
                    print(f"  HW entries: {len(hw_entries) if isinstance(hw_entries, list) else 1}")
                    print(f"  Ifnet entries: {len(ifnet_entries) if isinstance(ifnet_entries, list) else 1}")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

