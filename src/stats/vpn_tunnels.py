"""VPN tunnel statistics and monitoring (read-only)."""

from typing import Dict, Any, List, Optional
from datetime import datetime

from ..palo_alto_client.client import PaloAltoClient
from ..utils.logger import get_logger, update_logger_firewall_context
from ..utils.parsers import parse_data_types
from ..utils.stats_config import StatsCollectionConfig
from config.settings import settings

logger = get_logger(__name__)

class VpnTunnelStats:
    """VPN tunnel statistics collector (read-only)."""
    
    def __init__(self, client: PaloAltoClient):
        self.client = client
        self.stats_config = StatsCollectionConfig(settings)
        # Update logger with firewall context from client
        if not client.multi_firewall_mode:
            update_logger_firewall_context(logger, client.firewall_name, client.host)
        else:
            # In multi-firewall mode, we'll update the logger context dynamically
            # when processing each firewall in the _get_vpn_data_single function
            pass

    def get_vpn_data(self) -> Dict[str, Any]:
        """Get comprehensive VPN data from all firewalls."""
        def _get_vpn_data_single(client: PaloAltoClient) -> Dict[str, Any]:
            """Get VPN data from a single firewall."""
            # Update logger context for this specific firewall
            update_logger_firewall_context(logger, client.firewall_name, client.host)
            
            result = {}
            firewall_name = client.firewall_name
            
            # Get VPN flows (if enabled)
            if self.stats_config.is_collection_enabled('vpn_tunnels', 'vpn_flows', firewall_name):
                try:
                    vpn_flows_response = client.execute_operational_command('<show><vpn><flow><all></all></flow></vpn></show>')
                    result['vpn_flows'] = vpn_flows_response.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get VPN flows: {e}")
                    result['vpn_flows'] = {}
            else:
                logger.debug(f"VPN flows collection disabled for firewall {firewall_name}")
            
            # Get VPN gateways (if enabled)
            if self.stats_config.is_collection_enabled('vpn_tunnels', 'vpn_gateways', firewall_name):
                try:
                    vpn_gateways_response = client.execute_operational_command('<show><vpn><gateway></gateway></vpn></show>')
                    result['vpn_gateways'] = vpn_gateways_response.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get VPN gateways: {e}")
                    result['vpn_gateways'] = {}
            else:
                logger.debug(f"VPN gateways collection disabled for firewall {firewall_name}")
            
            # Get VPN tunnels (if enabled)
            if self.stats_config.is_collection_enabled('vpn_tunnels', 'vpn_tunnels', firewall_name):
                try:
                    vpn_tunnels_response = client.execute_operational_command('<show><vpn><tunnel></tunnel></vpn></show>')
                    result['vpn_tunnels'] = vpn_tunnels_response.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get VPN tunnels: {e}")
                    result['vpn_tunnels'] = {}
            else:
                logger.debug(f"VPN tunnels collection disabled for firewall {firewall_name}")
            
            # Get IPsec SA (if enabled)
            if self.stats_config.is_collection_enabled('vpn_tunnels', 'ipsec_sa', firewall_name):
                try:
                    ipsec_sa_response = client.execute_operational_command('<show><vpn><ipsec-sa></ipsec-sa></vpn></show>')
                    result['ipsec_sa'] = ipsec_sa_response.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get IPsec SA: {e}")
                    result['ipsec_sa'] = {}
            else:
                logger.debug(f"IPsec SA collection disabled for firewall {firewall_name}")

            # Get active tunnels (if enabled)
            if self.stats_config.is_collection_enabled('vpn_tunnels', 'active_tunnels', firewall_name):
                try:
                    active_tunnels_response = client.execute_operational_command('<show><vpn><tunnel></tunnel></vpn></show>')
                    result['active_tunnels'] = active_tunnels_response.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get active tunnels: {e}")
                    result['active_tunnels'] = {}
            else:
                logger.debug(f"Active tunnels collection disabled for firewall {firewall_name}")
            
            # Add timestamp
            result['timestamp'] = datetime.now().isoformat()
            
            return parse_data_types(result)
        
        return self.client.execute_on_all_firewalls(_get_vpn_data_single)
    
