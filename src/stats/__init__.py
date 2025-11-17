"""Palo Alto Network statistics collection modules."""

from .system import SystemStats
from .network_interfaces import InterfaceStats
from .global_counters import GlobalCounters
from .global_protect import GlobalProtectStats
from .routing import RoutingStats
from .vpn_tunnels import VpnTunnelStats

__all__ = [
    'SystemStats',
    'InterfaceStats', 
    'GlobalCounters',
    'GlobalProtectStats',
    'AdvancedRoutingStats',
    'VpnTunnelStats'
] 