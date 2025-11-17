"""Unified routing statistics and BGP monitoring (read-only)."""

from typing import Dict, Any, List, Optional, Literal, Tuple
from datetime import datetime
from enum import Enum

from ..palo_alto_client.client import PaloAltoClient
from ..utils.logger import get_logger, update_logger_firewall_context
from ..utils.parsers import parse_json_fields, parse_data_types
from ..utils.stats_config import StatsCollectionConfig
from config.settings import settings

logger = get_logger(__name__)

class RoutingMode(Enum):
    """Routing mode enumeration."""
    AUTO = "auto"
    ADVANCED = "advanced"
    LEGACY = "legacy"

class RoutingStats:
    """Unified routing statistics collector (read-only)."""
    
    def __init__(self, client: PaloAltoClient):
        self.client = client
        self.stats_config = StatsCollectionConfig(settings)
        # Update logger with firewall context from client
        if not client.multi_firewall_mode:
            update_logger_firewall_context(logger, client.firewall_name, client.host)
        else:
            # In multi-firewall mode, we'll update the logger context dynamically
            pass
    
    def _detect_routing_mode(self, client: PaloAltoClient) -> RoutingMode:
        """Detect the routing mode for a firewall."""
        # Get routing mode from configuration
        firewall_config = settings.get_firewall(client.firewall_name)
        configured_mode = firewall_config.get('routing_mode', 'auto')
        
        if configured_mode != 'auto':
            return RoutingMode(configured_mode)
        
        # Auto-detect by trying advanced routing first
        try:
            # Try a simple advanced routing command
            response = client.execute_operational_command('<show><advanced-routing><static-route-path-monitor></static-route-path-monitor></advanced-routing></show>')
            if response and 'result' in response:
                logger.info(f"Auto-detected advanced routing mode for firewall {client.firewall_name}")
                return RoutingMode.ADVANCED
        except Exception as e:
            logger.debug(f"Advanced routing not available for firewall {client.firewall_name}: {e}")
        
        # Fall back to legacy routing
        logger.info(f"Auto-detected legacy routing mode for firewall {client.firewall_name}")
        return RoutingMode.LEGACY
    
    def _get_command_config(self, routing_mode: RoutingMode) -> Dict[str, Tuple[str, str]]:
        """Get command configuration with (command, parser) tuples.
        
        Returns:
            Dict mapping collection_name to (command, parser_name) tuple
        """
        if routing_mode == RoutingMode.ADVANCED:
            return {
                'bgp_summary': (
                    '<show><advanced-routing><bgp><summary></summary></bgp></advanced-routing></show>',
                    'parse_json_fields'
                ),
                'bgp_peer_status': (
                    '<show><advanced-routing><bgp><peer><status/></peer></bgp></advanced-routing></show>',
                    'parse_json_fields'
                ),
                'bgp_path_monitor': (
                    '<show><advanced-routing><static-route-path-monitor/></advanced-routing></show>',
                    'parse_data_types'  # ⚠️ Different parser for this command!
                ),
                'routing_table': (
                    '<show><advanced-routing><route></route></advanced-routing></show>',
                    'parse_json_fields'
                ),
                'bgp_routes': (
                    '<show><advanced-routing><route><type>bgp</type></route></advanced-routing></show>',
                    'parse_json_fields'
                ),
                'static_routes': (
                    '<show><advanced-routing><route><type>static</type></route></advanced-routing></show>',
                    'parse_json_fields'
                ),
            }
        else:  # Legacy routing
            return {
                'bgp_summary': (
                    '<show><routing><protocol><bgp><summary></summary></bgp></protocol></routing></show>',
                    'parse_data_types'
                ),
                'bgp_peer_status': (
                    '<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>',
                    'parse_data_types'
                ),
                'bgp_path_monitor': (
                    '<show><routing><path-monitor></path-monitor></routing></show>',
                    'parse_data_types'
                ),
                'routing_table': (
                    '<show><routing><route></route></routing></show>',
                    'parse_data_types'
                ),
                'bgp_routes': (
                    '<show><routing><route><type>bgp</type></route></routing></show>',
                    'parse_data_types'
                ),
                'static_routes': (
                    '<show><routing><route><type>static</type></route></routing></show>',
                    'parse_data_types'
                ),
            }
    
    def _parse_response(self, response: Dict[str, Any], parser_name: str) -> Dict[str, Any]:
        """Parse response using the specified parser."""
        result = response.get('result', {})
        
        if parser_name == 'parse_json_fields':
            return parse_json_fields(result)
        elif parser_name == 'parse_data_types':
            return parse_data_types(result)
        else:
            logger.warning(f"Unknown parser '{parser_name}', using parse_data_types as fallback")
            return parse_data_types(result)
    
    def _normalize_legacy_to_advanced_format(self, data: Dict[str, Any], collection_name: str) -> Dict[str, Any]:
        """
        Normalize legacy routing format to advanced routing format.
        
        This ensures that downstream consumers (data_analyzer.py, influxdb_converter.py, etc.)
        can work uniformly with data from both routing modes.
        
        Args:
            data: The parsed data from legacy routing commands
            collection_name: The name of the collection (bgp_summary, bgp_peer_status, etc.)
        
        Returns:
            Normalized data in advanced routing format
        """
        if not data:
            return data
        
        try:
            if collection_name == 'bgp_summary':
                # Legacy: {"entry": {"@virtual-router": "Azure-VR", "router-id": "...", ...}}
                # Advanced: {"VRF-NAME": {"router-id": "...", ...}}
                if 'entry' in data and isinstance(data['entry'], dict):
                    entry = data['entry']
                    vrf_name = entry.get('@virtual-router', 'default')
                    # Remove the @virtual-router attribute and use it as the key
                    normalized_entry = {k: v for k, v in entry.items() if not k.startswith('@')}
                    return {vrf_name: normalized_entry}
                return data
            
            elif collection_name == 'bgp_peer_status':
                # Legacy: {"entry": [{"@peer": "PeerName", "@vr": "VRF", ...}, ...]}
                # Advanced: {"PeerName": {...}, ...}
                if 'entry' in data:
                    entries = data['entry']
                    # Ensure it's a list
                    if not isinstance(entries, list):
                        entries = [entries]
                    
                    normalized = {}
                    for entry in entries:
                        if isinstance(entry, dict):
                            peer_name = entry.get('@peer', entry.get('peer-name', 'unknown'))
                            # Remove @ attributes and normalize field names
                            normalized_entry = {}
                            for k, v in entry.items():
                                if k.startswith('@'):
                                    continue
                                # Map legacy field names to advanced format
                                if k == 'status':
                                    normalized_entry['state'] = v
                                elif k == 'status-duration':
                                    normalized_entry['status-time'] = v
                                elif k == 'peer-group':
                                    normalized_entry['peer-group-name'] = v
                                elif k == 'peer-address':
                                    normalized_entry['peer-ip'] = v
                                elif k == 'local-address':
                                    normalized_entry['local-ip'] = v
                                else:
                                    normalized_entry[k] = v
                            
                            normalized[peer_name] = normalized_entry
                    
                    return normalized
                return data
            
            elif collection_name == 'bgp_path_monitor':
                # bgp_path_monitor already has similar structure in both modes
                # Legacy: {"entry": [...]}
                # Just return as-is, both formats are compatible
                return data
            
            elif collection_name in ['routing_table', 'bgp_routes', 'static_routes']:
                # Legacy: {"entry": [{"virtual-router": "VRF", "destination": "...", ...}, ...]}
                # Advanced: Already in VRF-keyed format with nested routes
                # For legacy, we need to group by VRF and then by destination
                if 'entry' in data:
                    entries = data['entry']
                    if not isinstance(entries, list):
                        entries = [entries]
                    
                    # Group by VRF
                    vrf_routes = {}
                    for entry in entries:
                        if isinstance(entry, dict):
                            vrf_name = entry.get('virtual-router', 'default')
                            destination = entry.get('destination', 'unknown')
                            
                            if vrf_name not in vrf_routes:
                                vrf_routes[vrf_name] = {}
                            
                            # Create route entry without virtual-router field
                            route_entry = {k: v for k, v in entry.items() if k != 'virtual-router'}
                            
                            # Store as list to handle multiple routes per destination
                            if destination not in vrf_routes[vrf_name]:
                                vrf_routes[vrf_name][destination] = []
                            vrf_routes[vrf_name][destination].append(route_entry)
                    
                    return vrf_routes
                return data
            
            else:
                # Unknown collection, return as-is
                return data
        
        except Exception as e:
            logger.warning(f"Failed to normalize {collection_name} data: {e}")
            return data
    
    def get_routing_data(self) -> Dict[str, Any]:
        """Get comprehensive routing data from all firewalls."""
        def _get_routing_data_single(client: PaloAltoClient) -> Dict[str, Any]:
            """Get routing data from a single firewall."""
            # Update logger context for this specific firewall
            update_logger_firewall_context(logger, client.firewall_name, client.host)
            
            # Detect routing mode
            routing_mode = self._detect_routing_mode(client)
            logger.info(f"Using {routing_mode.value} routing mode for firewall {client.firewall_name}")
            
            # Get command configuration for this routing mode
            command_config = self._get_command_config(routing_mode)
            
            result = {
                'routing_mode': routing_mode.value,
                'timestamp': datetime.now().isoformat()
            }
            firewall_name = client.firewall_name
            
            # Use the unified routing module name for stats collection config
            module_name = 'routing'
            
            # Collect data for each enabled collection
            for collection_name, (command, parser_name) in command_config.items():
                if self.stats_config.is_collection_enabled(module_name, collection_name, firewall_name):
                    try:
                        response = client.execute_operational_command(command)
                        parsed_data = self._parse_response(response, parser_name)
                        
                        # Normalize legacy format to advanced format for uniform downstream processing
                        if routing_mode == RoutingMode.LEGACY:
                            parsed_data = self._normalize_legacy_to_advanced_format(parsed_data, collection_name)
                            logger.debug(f"Normalized legacy {collection_name} data to advanced format")
                        
                        result[collection_name] = parsed_data
                        logger.debug(f"Successfully collected {collection_name} using {parser_name} parser")
                    except Exception as e:
                        logger.warning(f"Failed to get {collection_name}: {e}")
                        result[collection_name] = {}
                else:
                    logger.debug(f"{collection_name} collection disabled for firewall {firewall_name}")
            
            return result
        
        return self.client.execute_on_all_firewalls(_get_routing_data_single)
    
    def get_bgp_peer_status(self) -> Dict[str, Any]:
        """Get BGP peer status information from all firewalls."""
        def _get_bgp_peer_status_single(client: PaloAltoClient) -> Dict[str, Any]:
            """Get BGP peer status from a single firewall."""
            routing_mode = self._detect_routing_mode(client)
            command_config = self._get_command_config(routing_mode)
            
            command, parser_name = command_config['bgp_peer_status']
            
            try:
                response = client.execute_operational_command(command)
                parsed_data = self._parse_response(response, parser_name)
                
                # Normalize legacy format to advanced format for uniform downstream processing
                if routing_mode == RoutingMode.LEGACY:
                    parsed_data = self._normalize_legacy_to_advanced_format(parsed_data, 'bgp_peer_status')
                    logger.debug("Normalized legacy BGP peer status data to advanced format")
                
                return parsed_data
            except Exception as e:
                logger.warning(f"Failed to get BGP peer status: {e}")
                return {}
        
        return self.client.execute_on_all_firewalls(_get_bgp_peer_status_single)
    
    def format_bgp_peer_status_for_display(self, bgp_data: Dict[str, Any]) -> str:
        """Format BGP peer status data for console display."""
        try:
            output = []
            output.append("BGP Peer Status Summary:")
            
            # Count peers by state
            total_peers = 0
            established_peers = 0
            active_peers = 0
            inactive_peers = 0
            
            for peer_name, peer_info in bgp_data.items():
                if isinstance(peer_info, dict):
                    total_peers += 1
                    state = peer_info.get('state', 'Unknown').lower()
                    if 'established' in state:
                        established_peers += 1
                    elif 'active' in state:
                        active_peers += 1
                    else:
                        inactive_peers += 1
            
            output.append(f"  Total Peers: {total_peers}")
            output.append(f"  Established: {established_peers}")
            output.append(f"  Active: {active_peers}")
            output.append(f"  Inactive: {inactive_peers}")
            output.append("")
            
            for peer_name, peer_info in bgp_data.items():
                if isinstance(peer_info, dict):
                    output.append(f"Peer: {peer_name}")
                    output.append(f"  State: {peer_info.get('state', 'N/A')}")
                    output.append(f"  Local IP: {peer_info.get('local-ip', 'N/A')}")
                    output.append(f"  Peer IP: {peer_info.get('peer-ip', 'N/A')}")
                    output.append(f"  Local AS: {peer_info.get('local-as', 'N/A')}")
                    output.append(f"  Remote AS: {peer_info.get('remote-as', 'N/A')}")
                    output.append(f"  Peer Group: {peer_info.get('peer-group-name', 'N/A')}")
                    
                    # Show uptime information
                    uptime_string = peer_info.get('status-time', 'N/A')
                    if uptime_string and uptime_string != 'N/A':
                        output.append(f"  Uptime: {uptime_string} seconds")
                    
                    # Show detailed information if available
                    detail = peer_info.get('detail', {})
                    if detail:
                        if 'bgpTimerUpString' in detail:
                            output.append(f"  Uptime: {detail['bgpTimerUpString']}")
                        if 'bgpVersion' in detail:
                            output.append(f"  BGP Version: {detail['bgpVersion']}")
                        if 'bgpTimerUpMsec' in detail:
                            output.append(f"  Uptime (ms): {detail['bgpTimerUpMsec']}")
                        if 'bgpTimerUpEstablishedEpoch' in detail:
                            output.append(f"  Established Epoch: {detail['bgpTimerUpEstablishedEpoch']}")
                        
                        # Message statistics
                        msg_stats = detail.get('messageStats', {})
                        if msg_stats:
                            output.append(f"  Messages Sent: {msg_stats.get('totalSent', 0)}")
                            output.append(f"  Messages Received: {msg_stats.get('totalRecv', 0)}")
                            output.append(f"  Updates Sent: {msg_stats.get('updatesSent', 0)}")
                            output.append(f"  Updates Received: {msg_stats.get('updatesRecv', 0)}")
                            output.append(f"  Keepalives Sent: {msg_stats.get('keepalivesSent', 0)}")
                            output.append(f"  Keepalives Received: {msg_stats.get('keepalivesRecv', 0)}")
                        
                        # Address family information
                        af_info = detail.get('addressFamilyInfo', {})
                        ipv4_info = af_info.get('ipv4Unicast', {})
                        if ipv4_info:
                            output.append(f"  IPv4 Prefixes Accepted: {ipv4_info.get('acceptedPrefixCounter', 0)}")
                            output.append(f"  IPv4 Prefixes Sent: {ipv4_info.get('sentPrefixCounter', 0)}")
                            output.append(f"  IPv4 Prefix Limit: {ipv4_info.get('prefixAllowedMax', 0)}")
                        
                        if 'connectionsEstablished' in detail:
                            output.append(f"  Connections Established: {detail['connectionsEstablished']}")
                            output.append(f"  Connections Dropped: {detail.get('connectionsDropped', 0)}")
                        
                        if 'estimatedRttInMsecs' in detail:
                            output.append(f"  Estimated RTT: {detail['estimatedRttInMsecs']} ms")
                    
                    output.append("")
            
            return "\n".join(output)
            
        except Exception as e:
            logger.error(f"Failed to format BGP peer status: {e}")
            return f"Error formatting BGP peer status: {e}"
