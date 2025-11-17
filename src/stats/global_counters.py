"""Global counter statistics and monitoring (read-only)."""

from typing import Dict, Any, Optional
from datetime import datetime
import re

from ..palo_alto_client.client import PaloAltoClient
from ..utils.logger import get_logger, update_logger_firewall_context
from ..utils.parsers import parse_data_types
from ..utils.stats_config import StatsCollectionConfig
from config.settings import settings

logger = get_logger(__name__)

class GlobalCounters:
    """Global counter statistics collector (read-only)."""
    
    def __init__(self, client: PaloAltoClient):
        self.client = client
        self.stats_config = StatsCollectionConfig(settings)
        # Update logger with firewall context from client
        if not client.multi_firewall_mode:
            update_logger_firewall_context(logger, client.firewall_name, client.host)
        else:
            # In multi-firewall mode, we'll update the logger context dynamically
            # when processing each firewall in the _get_counter_data_single function
            pass

    def _parse_management_server_counters(self, response_text: str) -> Dict[str, int]:
        """
        Parse management server counters from response text.
        
        Args:
            response_text: Raw response string containing counter data
            
        Returns:
            Dictionary with counter names as keys and integer values
        """
        counters = {}
        
        if not response_text:
            logger.warning("Empty management server counters response")
            return counters
        
        # Handle case where response_text is a dictionary instead of string
        if isinstance(response_text, dict):
            # If it's a dictionary, try to extract the text content
            if 'text' in response_text:
                response_text = response_text['text']
            elif 'result' in response_text:
                response_text = str(response_text['result'])
            else:
                return counters
        
        # Ensure we have a string to work with
        if not isinstance(response_text, str):
            return counters
            
        # Pattern to match counter lines: "Counter name   :          value"
        # This handles various spacing and formatting
        pattern = r'^(.+?)\s*:\s*(\d+)$'
        
        for line in response_text.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
                
            match = re.match(pattern, line)
            if match:
                counter_name = match.group(1).strip()
                counter_value = int(match.group(2))
                counters[counter_name] = counter_value
            else:
                logger.debug(f"Could not parse management server counter line: {line}")
        
        return counters

    def get_counter_data(self) -> Dict[str, Any]:
        """Get comprehensive counter statistics data from all firewalls."""
        def _get_counter_data_single(client: PaloAltoClient) -> Dict[str, Any]:
            """Get counter data from a single firewall."""
            # Update logger context for this specific firewall
            update_logger_firewall_context(logger, client.firewall_name, client.host)
            
            result = {}
            firewall_name = client.firewall_name
            
            # Get global counters (if enabled)
            if self.stats_config.is_collection_enabled('global_counters', 'global_counters', firewall_name):
                try:
                    global_counters_response = client.execute_operational_command('<show><counter><global></global></counter></show>')
                    result['global_counters'] = global_counters_response.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get global counters: {e}")
                    result['global_counters'] = {}
            else:
                logger.debug(f"Global counters collection disabled for firewall {firewall_name}")
            
            # Get session info (if enabled)
            if self.stats_config.is_collection_enabled('global_counters', 'session_info', firewall_name):
                try:
                    session_info_response = client.execute_operational_command('<show><session><info></info></session></show>')
                    result['session_info'] = session_info_response.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get session info: {e}")
                    result['session_info'] = {}
            else:
                logger.debug(f"Session info collection disabled for firewall {firewall_name}")
            
            # Get management server counters (if enabled)
            if self.stats_config.is_collection_enabled('global_counters', 'management_server_counters', firewall_name):
                try:
                    management_server_counters_response = client.execute_operational_command('<show><counter><management-server/></counter></show>')
                    raw_response = management_server_counters_response.get('result', '')
                    
                    # Parse the raw response string
                    parsed_counters = self._parse_management_server_counters(raw_response)
                    result['management_server_counters'] = parsed_counters
                    
                    logger.debug(f"Parsed {len(parsed_counters)} management server counters")
                    
                except Exception as e:
                    logger.warning(f"Failed to get management server counters: {e}")
                    result['management_server_counters'] = {}
            else:
                logger.debug(f"Management server counters collection disabled for firewall {firewall_name}")
            
            # Add timestamp
            result['timestamp'] = datetime.now().isoformat()
            
            return parse_data_types(result)
        
        # Execute on all firewalls using the unified client
        return self.client.execute_on_all_firewalls(_get_counter_data_single)
    
