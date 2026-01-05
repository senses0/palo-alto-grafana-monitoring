"""
Data models for the Traffic Viewer.

Contains all dataclasses used across the application:
- ColorTheme: Centralized color theme management
- InterfaceInfo: Network interface properties
- FirewallInfo: Firewall with its interfaces
- ViewerSelection: User's selection of interfaces to monitor
- InterfaceCache: Cache for firewall/interface data
- InterfaceTrafficData: Traffic statistics for a single interface
"""

from dataclasses import dataclass, field
from collections import deque
from datetime import datetime
from typing import Dict, Any, List, Optional, TYPE_CHECKING

from rich.text import Text

from .constants import HISTORY_SIZE, COUNTER_TABLE_MAX_ROWS

# Braille vertical bar patterns for graph rendering (bottom-to-top, left column)
# Each character represents a fill level from 0 (empty) to 4 (full)
# These provide 4x finer vertical resolution than block characters
BRAILLE_BARS_UP = [
    '\u2800',  # Level 0: blank (⠀)
    '\u2840',  # Level 1: dot 7 - bottom (⡀)
    '\u2844',  # Level 2: dots 3,7 (⡄)
    '\u2846',  # Level 3: dots 2,3,7 (⡆)
    '\u2847',  # Level 4: dots 1,2,3,7 - full left column (⡇)
]

# Braille bars for downward graphs (TX - below baseline)
# These fill from top to bottom
BRAILLE_BARS_DOWN = [
    '\u2800',  # Level 0: blank (⠀)
    '\u2801',  # Level 1: dot 1 - top (⠁)
    '\u2803',  # Level 2: dots 1,2 (⠃)
    '\u2807',  # Level 3: dots 1,2,3 (⠇)
    '\u2847',  # Level 4: dots 1,2,3,7 - full left column (⡇)
]

# Number of braille levels per row (excluding the empty level)
BRAILLE_LEVELS_PER_ROW = 4


def get_braille_char(fill_level: float, direction: str = "up") -> str:
    """
    Get the braille character for a given fill level within a row.
    
    Args:
        fill_level: Value from 0.0 to 1.0 representing how full this row should be
        direction: "up" for RX (fills bottom-to-top), "down" for TX (fills top-to-bottom)
    
    Returns:
        The appropriate braille character for the fill level
    """
    bars = BRAILLE_BARS_UP if direction == "up" else BRAILLE_BARS_DOWN
    
    if fill_level <= 0:
        return bars[0]  # Empty
    
    # Map 0.0-1.0 to 1-4 index (minimum 1 for any non-zero value)
    # This ensures even tiny values show at least a single dot
    index = int(fill_level * BRAILLE_LEVELS_PER_ROW)
    index = max(1, min(index, BRAILLE_LEVELS_PER_ROW))  # Clamp to 1-4 range
    
    return bars[index]


# Avoid circular import - PaloAltoClient only needed for type hints
if TYPE_CHECKING:
    from src.palo_alto_client.client import PaloAltoClient


@dataclass
class ColorTheme:
    """Centralized color theme management."""

    # Primary colors
    primary: str = "#58a6ff"
    primary_dark: str = "#388bfd"
    primary_light: str = "#79c0ff"

    # Status colors
    success: str = "#56d364"
    success_dark: str = "#238636"
    success_light: str = "#7ee787"

    warning: str = "#d29922"
    warning_dark: str = "#bb8009"
    warning_light: str = "#e3b341"

    error: str = "#f85149"
    error_dark: str = "#da3633"
    error_light: str = "#ff7b72"

    # Data colors
    rx_green: str = "#56d364"
    rx_green_dark: str = "#238636"
    rx_green_light: str = "#7ee787"

    tx_blue: str = "#58a6ff"
    tx_blue_dark: str = "#1f6feb"
    tx_blue_light: str = "#79c0ff"

    # UI colors
    background: str = "#0d1117"
    surface: str = "#161b22"
    surface_dark: str = "#0d1117"
    surface_light: str = "#21262d"

    text: str = "#c9d1d9"
    text_dim: str = "#8b949e"
    text_muted: str = "#656d76"

    border: str = "#30363d"
    border_light: str = "#454c54"

    # Graph gradients
    rx_gradient: List[str] = field(default_factory=lambda: [
        "#2ea043", "#3fb950", "#56d364", "#7ee787", "#aff5b4", "#d3f9d8"
    ])

    tx_gradient: List[str] = field(default_factory=lambda: [
        "#1f6feb", "#388bfd", "#58a6ff", "#79c0ff", "#a5d6ff", "#cae8ff"
    ])

    def get_rx_color(self, intensity: float) -> str:
        """Get RX color based on intensity (0.0 to 1.0)."""
        index = int(intensity * (len(self.rx_gradient) - 1))
        return self.rx_gradient[min(index, len(self.rx_gradient) - 1)]

    def get_tx_color(self, intensity: float) -> str:
        """Get TX color based on intensity (0.0 to 1.0)."""
        index = int(intensity * (len(self.tx_gradient) - 1))
        return self.tx_gradient[min(index, len(self.tx_gradient) - 1)]


# Global theme instance
THEME = ColorTheme()


@dataclass
class InterfaceInfo:
    """Represents a network interface with its properties."""
    name: str
    firewall: str
    status: str = "unknown"
    speed: str = "N/A"
    zone: Optional[str] = None
    ip: Optional[str] = None
    fwd: Optional[str] = None
    
    @property
    def id(self) -> str:
        """Unique identifier for this interface."""
        return f"{self.firewall}::{self.name}"
    
    @property
    def is_up(self) -> bool:
        """Check if interface is up."""
        return self.status and "up" in self.status.lower()
    
    def display_label(self) -> Text:
        """Create rich text label for display."""
        text = Text()

        # Interface name with better styling
        text.append(f"{self.name:<18}", style=f"bold {THEME.text}")

        # Status with theme colors
        if self.is_up:
            text.append("🟢 UP   ", style=f"bold {THEME.success}")
        elif "down" in (self.status or "").lower():
            text.append("🔴 DOWN ", style=f"bold {THEME.error}")
        else:
            text.append("⚪ N/A  ", style=THEME.text_dim)

        # Speed/status details
        status_text = self.status if self.status and self.status != "N/A" else "-"
        text.append(f" {status_text:<16}", style=THEME.text_dim)

        # Zone 
        zone_text = self.zone or "-"
        text.append(f"{zone_text:<10}", style=THEME.warning)

        # Forward type
        fwd_text = self.fwd or "-"
        text.append(f" {fwd_text}", style=f"italic {THEME.text_dim}")

        return text


@dataclass 
class FirewallInfo:
    """Represents a firewall with its interfaces."""
    name: str
    hostname: str
    host: str
    description: str = ""
    location: str = ""
    interfaces: List[InterfaceInfo] = field(default_factory=list)


@dataclass
class ViewerSelection:
    """Result of the traffic viewer selection process."""
    interfaces: List[InterfaceInfo]
    polling_interval: int  # in seconds
    
    def __bool__(self) -> bool:
        """Return True if interfaces were selected."""
        return len(self.interfaces) > 0


@dataclass
class InterfaceCache:
    """Cache for firewall and interface data to avoid re-querying."""
    firewalls: List[FirewallInfo] = field(default_factory=list)
    all_interfaces: Dict[str, InterfaceInfo] = field(default_factory=dict)
    client: Optional["PaloAltoClient"] = None  # Cached client to avoid re-auth
    timestamp: Optional[datetime] = None
    
    def is_valid(self) -> bool:
        """Check if cache has data and client."""
        return len(self.firewalls) > 0 and self.client is not None
    
    def clear(self) -> None:
        """Clear the cache."""
        self.firewalls.clear()
        self.all_interfaces.clear()
        self.client = None
        self.timestamp = None


@dataclass
class CounterPollRecord:
    """Record of a single poll's counter data for the rolling table."""
    timestamp: datetime
    firewall: str
    interface: str
    rx_bps: float
    tx_bps: float
    delta_errors: int
    delta_drops: int
    tcp_conn: int = 0
    udp_conn: int = 0
    delta_ibytes: int = 0
    delta_obytes: int = 0


@dataclass
class InterfaceTrafficData:
    """Traffic data for a single interface."""
    interface_id: str
    interface_name: str
    firewall: str
    
    # Current counter values (cumulative bytes)
    ibytes: int = 0
    obytes: int = 0
    
    # Previous counter values for delta calculation
    prev_ibytes: int = 0
    prev_obytes: int = 0
    
    # Calculated rates in bits per second
    rx_bps: float = 0.0
    tx_bps: float = 0.0
    
    # Packet counters (cumulative)
    ipackets: int = 0
    opackets: int = 0
    prev_ipackets: int = 0
    prev_opackets: int = 0
    
    # Calculated packets per second
    rx_pps: float = 0.0
    tx_pps: float = 0.0
    
    # Error and drop counters (cumulative)
    ierrors: int = 0
    idrops: int = 0
    prev_ierrors: int = 0
    prev_idrops: int = 0
    
    # Delta values for errors/drops (calculated per poll)
    delta_errors: int = 0
    delta_drops: int = 0
    
    # Delta bytes transferred (calculated per poll)
    delta_ibytes: int = 0
    delta_obytes: int = 0
    
    # History for sparklines (deques of bps values)
    rx_history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_SIZE))
    tx_history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_SIZE))
    
    # Per-interface poll history for the history table (stores CounterPollRecord entries)
    poll_history: deque = field(default_factory=lambda: deque(maxlen=COUNTER_TABLE_MAX_ROWS))
    
    # Timestamp of last update
    last_update: Optional[datetime] = None
    
    def update_counters(self, ibytes: int, obytes: int, poll_interval: float,
                        ipackets: int = 0, opackets: int = 0,
                        ierrors: int = 0, idrops: int = 0) -> None:
        """Update counters and calculate rates."""
        # Store previous values for bytes
        self.prev_ibytes = self.ibytes
        self.prev_obytes = self.obytes
        
        # Store previous values for packets
        self.prev_ipackets = self.ipackets
        self.prev_opackets = self.opackets
        
        # Store previous values for errors/drops
        self.prev_ierrors = self.ierrors
        self.prev_idrops = self.idrops
        
        # Update current values
        self.ibytes = ibytes
        self.obytes = obytes
        self.ipackets = ipackets
        self.opackets = opackets
        self.ierrors = ierrors
        self.idrops = idrops
        
        # Calculate byte deltas (handle counter wrap-around)
        delta_rx = ibytes - self.prev_ibytes
        delta_tx = obytes - self.prev_obytes
        
        # Handle first update or counter reset for bytes
        if self.prev_ibytes == 0 or delta_rx < 0:
            delta_rx = 0
        if self.prev_obytes == 0 or delta_tx < 0:
            delta_tx = 0
        
        # Store raw delta bytes for volume display
        self.delta_ibytes = delta_rx
        self.delta_obytes = delta_tx
        
        # Convert to bits per second: (bytes * 8) / seconds
        self.rx_bps = (delta_rx * 8) / poll_interval if poll_interval > 0 else 0
        self.tx_bps = (delta_tx * 8) / poll_interval if poll_interval > 0 else 0
        
        # Calculate packet deltas
        delta_rx_packets = ipackets - self.prev_ipackets
        delta_tx_packets = opackets - self.prev_opackets
        
        # Handle first update or counter reset for packets
        if self.prev_ipackets == 0 or delta_rx_packets < 0:
            delta_rx_packets = 0
        if self.prev_opackets == 0 or delta_tx_packets < 0:
            delta_tx_packets = 0
        
        # Calculate packets per second
        self.rx_pps = delta_rx_packets / poll_interval if poll_interval > 0 else 0
        self.tx_pps = delta_tx_packets / poll_interval if poll_interval > 0 else 0
        
        # Calculate error/drop deltas (just the difference, not per second)
        # For errors/drops, we use the last_update check to determine first poll
        # since prev_ierrors == 0 is a valid "no errors" state
        self.delta_errors = ierrors - self.prev_ierrors
        self.delta_drops = idrops - self.prev_idrops
        
        # Handle first update (no previous data) or counter reset (negative delta)
        if self.last_update is None:
            # First poll - can't calculate delta yet
            self.delta_errors = 0
            self.delta_drops = 0
        elif self.delta_errors < 0:
            # Counter reset for errors
            self.delta_errors = 0
        elif self.delta_drops < 0:
            # Counter reset for drops
            self.delta_drops = 0
        
        # Add to history
        self.rx_history.append(self.rx_bps)
        self.tx_history.append(self.tx_bps)
        
        self.last_update = datetime.now()
    
    @staticmethod
    def format_bps(bps: float) -> str:
        """Format bits per second to human readable string."""
        if bps >= 1_000_000_000:
            return f"{bps / 1_000_000_000:.2f} Gb/s"
        elif bps >= 1_000_000:
            return f"{bps / 1_000_000:.2f} Mb/s"
        elif bps >= 1_000:
            return f"{bps / 1_000:.2f} Kb/s"
        else:
            return f"{bps:.0f} b/s"
    
    @staticmethod
    def format_bytes(bytes_val: int) -> str:
        """Format bytes to human readable string."""
        if bytes_val >= 1_073_741_824:  # 1 GB
            return f"{bytes_val / 1_073_741_824:.2f} GB"
        elif bytes_val >= 1_048_576:  # 1 MB
            return f"{bytes_val / 1_048_576:.2f} MB"
        elif bytes_val >= 1_024:  # 1 KB
            return f"{bytes_val / 1_024:.2f} KB"
        else:
            return f"{bytes_val} B"
    
    @staticmethod
    def format_pps(pps: float) -> str:
        """Format packets per second to human readable string."""
        if pps >= 1_000_000:
            return f"{pps / 1_000_000:.2f}M"
        elif pps >= 1_000:
            return f"{pps / 1_000:.2f}k"
        else:
            return f"{pps:.1f}"

