"""Network interface statistics and monitoring (read-only)."""

from typing import Dict, Any, List
from datetime import datetime

from ..palo_alto_client.client import PaloAltoClient
from ..utils.logger import get_logger, update_logger_firewall_context
from ..utils.parsers import parse_data_types
from ..utils.stats_config import StatsCollectionConfig
from config.settings import settings

logger = get_logger(__name__)

class InterfaceStats:
    """Network interface statistics collector (read-only)."""
    
    def __init__(self, client: PaloAltoClient):
        self.client = client
        self.stats_config = StatsCollectionConfig(settings)
        # Update logger with firewall context from client
        if not client.multi_firewall_mode:
            update_logger_firewall_context(logger, client.firewall_name, client.host)
        else:
            # In multi-firewall mode, we'll update the logger context dynamically
            # when processing each firewall in the _get_interface_data_single function
            pass

    def get_interface_data(self) -> Dict[str, Any]:
        """Get comprehensive interface data from all firewalls."""
        def _get_interface_data_single(client: PaloAltoClient) -> Dict[str, Any]:
            """Get interface data from a single firewall."""
            # Update logger context for this specific firewall
            update_logger_firewall_context(logger, client.firewall_name, client.host)
            
            result = {}
            firewall_name = client.firewall_name
            
            # Get interface info (if enabled)
            if self.stats_config.is_collection_enabled('network_interfaces', 'interface_info', firewall_name):
                try:
                    interface_info_response = client.execute_operational_command('<show><interface>all</interface></show>')
                    result['interface_info'] = interface_info_response.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get interface info: {e}")
                    result['interface_info'] = {}
            else:
                logger.debug(f"Interface info collection disabled for firewall {firewall_name}")
            
            # Get interface counters (if enabled)
            if self.stats_config.is_collection_enabled('network_interfaces', 'interface_counters', firewall_name):
                try:
                    interface_counters_response = client.execute_operational_command('<show><counter><interface>all</interface></counter></show>')
                    result['interface_counters'] = interface_counters_response.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get interface counters: {e}")
                    result['interface_counters'] = {}
            else:
                logger.debug(f"Interface counters collection disabled for firewall {firewall_name}")
            
            # Add timestamp
            result['timestamp'] = datetime.now().isoformat()
            
            return parse_data_types(result)
        
        # Execute on all firewalls using the unified client
        return self.client.execute_on_all_firewalls(_get_interface_data_single)
