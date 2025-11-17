"""Global Protect statistics and counters (read-only)."""

from typing import Dict, Any
from datetime import datetime

from ..palo_alto_client.client import PaloAltoClient
from ..utils.logger import get_logger, update_logger_firewall_context
from ..utils.parsers import parse_data_types
from ..utils.stats_config import StatsCollectionConfig
from config.settings import settings

logger = get_logger(__name__)

class GlobalProtectStats:
    """Global Protect statistics collector (read-only)."""
    
    def __init__(self, client: PaloAltoClient):
        self.client = client
        self.stats_config = StatsCollectionConfig(settings)
        # Update logger with firewall context from client
        if not client.multi_firewall_mode:
            update_logger_firewall_context(logger, client.firewall_name, client.host)
        else:
            # In multi-firewall mode, we'll update the logger context dynamically
            # when processing each firewall in the _get_global_protect_data_single function
            pass
    
    def get_global_protect_data(self) -> Dict[str, Any]:
        """Get comprehensive Global Protect data from all firewalls."""
        def _get_global_protect_data_single(client: PaloAltoClient) -> Dict[str, Any]:
            """Get Global Protect data from a single firewall."""
            # Update logger context for this specific firewall
            update_logger_firewall_context(logger, client.firewall_name, client.host)
            
            result = {}
            firewall_name = client.firewall_name
            
            # Get gateway summary (if enabled)
            if self.stats_config.is_collection_enabled('global_protect', 'gateway_summary', firewall_name):
                try:
                    gateway_summary_response = client.execute_operational_command('<show><global-protect-gateway><summary><detail/></summary></global-protect-gateway></show>')
                    gateway_summary_result = gateway_summary_response.get('result', '')
                    result['gateway_summary'] = self._parse_gateway_summary(gateway_summary_result)
                except Exception as e:
                    logger.warning(f"Failed to get gateway summary: {e}")
                    result['gateway_summary'] = {}
            else:
                logger.debug(f"Gateway summary collection disabled for firewall {firewall_name}")
            
            # Get gateway statistics (if enabled)
            if self.stats_config.is_collection_enabled('global_protect', 'gateway_statistics', firewall_name):
                try:
                    gateway_statistics_response = client.execute_operational_command('<show><global-protect-gateway><statistics/></global-protect-gateway></show>')
                    gateway_statistics_result = gateway_statistics_response.get('result', '')
                    result['gateway_statistics'] = self._parse_gateway_statistics(gateway_statistics_result)
                except Exception as e:
                    logger.warning(f"Failed to get gateway statistics: {e}")
                    result['gateway_statistics'] = {}
            else:
                logger.debug(f"Gateway statistics collection disabled for firewall {firewall_name}")
            
            # Get portal statistics (if enabled)
            if self.stats_config.is_collection_enabled('global_protect', 'portal_statistics', firewall_name):
                try:
                    portal_statistics_response = client.execute_operational_command('<show><global-protect-portal><statistics/></global-protect-portal></show>')
                    portal_statistics_result = portal_statistics_response.get('result', '')
                    result['portal_statistics'] = self._parse_portal_statistics(portal_statistics_result)
                except Exception as e:
                    logger.warning(f"Failed to get portal statistics: {e}")
                    result['portal_statistics'] = {}
            else:
                logger.debug(f"Portal statistics collection disabled for firewall {firewall_name}")
            
            # Get portal summary (if enabled)
            if self.stats_config.is_collection_enabled('global_protect', 'portal_summary', firewall_name):
                try:
                    portal_summary_response = client.execute_operational_command('<show><global-protect-portal><summary><all/></summary></global-protect-portal></show>')
                    portal_summary_result = portal_summary_response.get('result', '')
                    result['portal_summary'] = self._parse_portal_summary_string(portal_summary_result)
                except Exception as e:
                    logger.warning(f"Failed to get portal summary: {e}")
                    result['portal_summary'] = {}
            else:
                logger.debug(f"Portal summary collection disabled for firewall {firewall_name}")
            
            # Add timestamp
            result['timestamp'] = datetime.now().isoformat()
            
            return parse_data_types(result)
        
        return self.client.execute_on_all_firewalls(_get_global_protect_data_single)
    

    
    def _parse_gateway_summary(self, result: Any) -> Dict[str, Any]:
        """Parse gateway summary result."""
        # Handle string/CDATA response
        if isinstance(result, str):
            return self._parse_gateway_summary_string(result)
        
        # Handle structured XML response with #text field
        if isinstance(result, dict) and '#text' in result:
            return self._parse_gateway_summary_structured(result)
        
        return result
    
    def _parse_gateway_statistics(self, result: Any) -> Dict[str, Any]:
        """Parse gateway statistics result."""
        # Handle string/CDATA response
        if isinstance(result, str):
            return self._parse_gateway_statistics_string(result)
        
        # For structured responses, ensure Gateway is always a list and convert values
        if isinstance(result, dict) and 'Gateway' in result:
            if not isinstance(result['Gateway'], list):
                result['Gateway'] = [result['Gateway']]
            
            # Convert values in gateway entries
            for gateway in result['Gateway']:
                if 'CurrentUsers' in gateway:
                    gateway['CurrentUsers'] = self._convert_value(gateway['CurrentUsers'])
                if 'PreviousUsers' in gateway:
                    gateway['PreviousUsers'] = self._convert_value(gateway['PreviousUsers'])
            
            # Convert total values
            if 'TotalCurrentUsers' in result:
                result['TotalCurrentUsers'] = self._convert_value(result['TotalCurrentUsers'])
            if 'TotalPreviousUsers' in result:
                result['TotalPreviousUsers'] = self._convert_value(result['TotalPreviousUsers'])
        
        return result
    
    def _parse_portal_statistics(self, result: Any) -> Dict[str, Any]:
        """Parse portal statistics result."""
        # Handle CDATA response (common for portal statistics)
        if isinstance(result, str):
            return self._parse_portal_statistics_cdata(result)
        
        return result
    
    def _parse_portal_statistics_cdata(self, cdata_string: str) -> Dict[str, Any]:
        """Parse portal statistics CDATA response into structured format."""
        parsed_data = {
            'total_messages_dp_to_mp': 0,
            'total_invalid_messages_dp_to_mp': 0,
            'failed_to_read_messages_dp_to_mp': 0
        }
        
        # Clean up the CDATA string
        lines = cdata_string.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Parse each statistic line
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    stat_name = parts[0].strip()
                    stat_value = parts[1].strip()
                    
                    # Map the statistic names to our structure
                    if 'Total messages DP => MP' in stat_name:
                        parsed_data['total_messages_dp_to_mp'] = self._convert_value(stat_value)
                    elif 'Total Invalid messages DP => MP' in stat_name:
                        parsed_data['total_invalid_messages_dp_to_mp'] = self._convert_value(stat_value)
                    elif 'Failed to read messages DP => MP' in stat_name:
                        parsed_data['failed_to_read_messages_dp_to_mp'] = self._convert_value(stat_value)
        
        return parsed_data
    
    def _parse_portal_summary_string(self, summary_string: str) -> Dict[str, Any]:
        """Parse portal summary string response into structured format."""
        parsed_data = {
            'entry': []
        }
        
        lines = summary_string.strip().split('\n')
        
        # Skip the header line (first line)
        if len(lines) > 0:
            lines = lines[1:]  # Remove header line
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Check if this is a portal data line (contains ':')
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    portal_name = parts[0].strip()
                    successful_connections = parts[1].strip()
                    
                    # Create portal entry
                    portal_entry = {
                        'name': portal_name,
                        'successful_connections': self._convert_value(successful_connections)
                    }
                    
                    parsed_data['entry'].append(portal_entry)
        
        return parsed_data
    
    def _parse_gateway_summary_string(self, summary_string: str) -> Dict[str, Any]:
        """Parse gateway summary string response into structured format."""
        parsed_data = {
            'entry': []
        }
        
        # Split the response into gateway sections
        # Each gateway section starts with <Gateway> and ends with </Gateway>
        gateway_sections = summary_string.split('<Gateway>')
        
        for section in gateway_sections[1:]:  # Skip the first empty section
            if '</Gateway>' not in section:
                continue
                
            # Split at </Gateway> to separate the XML from the text stats
            parts = section.split('</Gateway>')
            if len(parts) != 2:
                continue
                
            xml_part = parts[0].strip()
            text_stats = parts[1].strip()
            
            # Parse the XML part to get gateway name and user info
            gateway_entry = {
                'name': '',
                'CurrentUsers': '0',
                'PreviousUsers': '0'
            }
            
            # Extract name from XML
            if '<name>' in xml_part and '</name>' in xml_part:
                name_start = xml_part.find('<name>') + 6
                name_end = xml_part.find('</name>')
                gateway_entry['name'] = xml_part[name_start:name_end]
            
            # Extract CurrentUsers from XML
            if '<CurrentUsers>' in xml_part and '</CurrentUsers>' in xml_part:
                current_start = xml_part.find('<CurrentUsers>') + 14
                current_end = xml_part.find('</CurrentUsers>')
                gateway_entry['CurrentUsers'] = xml_part[current_start:current_end]
            
            # Extract PreviousUsers from XML
            if '<PreviousUsers>' in xml_part and '</PreviousUsers>' in xml_part:
                prev_start = xml_part.find('<PreviousUsers>') + 15
                prev_end = xml_part.find('</PreviousUsers>')
                gateway_entry['PreviousUsers'] = xml_part[prev_start:prev_end]
            
            # Parse the text statistics
            lines = text_stats.split('\n')
            for line in lines:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                    
                parts = line.split(':', 1)
                if len(parts) == 2:
                    stat_name = parts[0].strip()
                    stat_value = parts[1].strip()
                    
                    # Map the statistic names to our structure
                    if 'current-user' in stat_name:
                        gateway_entry['current_user'] = stat_value
                    elif 'gateway-max-concurrent-tunnel' in stat_name:
                        gateway_entry['gateway_max_concurrent_tunnel'] = stat_value
                    elif 'gateway-successful-ip-sec-connections' in stat_name:
                        gateway_entry['gateway_successful_ip_sec_connections'] = stat_value
                    elif 'successful-gateway-connections' in stat_name:
                        gateway_entry['successful_gateway_connections'] = stat_value
                    elif 'gateway-max-tunnel-setup-rate' in stat_name:
                        gateway_entry['gateway_max_tunnel_setup_rate'] = stat_value
                    elif 'record-gateway-tunnel-count' in stat_name:
                        gateway_entry['record_gateway_tunnel_count'] = stat_value
                    elif 'record-gateway-tunnel-count-last-check-time' in stat_name:
                        gateway_entry['record_gateway_tunnel_count_last_check_time'] = stat_value
            
            parsed_data['entry'].append(gateway_entry)
        
        return parsed_data
    
    def _parse_gateway_statistics_string(self, statistics_string: str) -> Dict[str, Any]:
        """Parse gateway statistics string response into structured format."""
        parsed_data = {
            'gateway': {
                'entry': []
            }
        }
        
        # For now, return empty structure if it's a string response
        # This can be enhanced based on actual gateway statistics response format
        logger.warning("Gateway statistics returned string response - format unknown")
        
        return parsed_data
    
    def _convert_value(self, value: str) -> Any:
        """Convert string value to appropriate data type."""
        if not value or value == 'N/A':
            return value
        
        # Try to convert to integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try to convert to float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Return as string if no conversion possible
        return value
    
    def _parse_gateway_summary_structured(self, structured_result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse gateway summary structured response with #text field."""
        parsed_data = {
            'entry': []
        }
        
        # Get gateway entries from the structured response
        gateways = structured_result.get('Gateway', [])
        if not isinstance(gateways, list):
            gateways = [gateways]
        
        # Get the text statistics
        text_stats = structured_result.get('#text', '')
        
        # Split the text into sections for each gateway
        # The text format has blank lines and tabs separating gateway sections
        sections = []
        current_section = []
        
        lines = text_stats.strip().split('\n')
        for line in lines:
            line = line.strip()
            
            # If we encounter a blank line, it might separate gateway sections
            if not line:
                if current_section:
                    sections.append(current_section)
                    current_section = []
                continue
            
            # If line starts with tab, it's a new gateway section
            if line.startswith('\t'):
                if current_section:
                    sections.append(current_section)
                    current_section = []
                # Remove the tab and add to new section
                current_section.append(line.lstrip())
            else:
                current_section.append(line)
        
        # Add the last section
        if current_section:
            sections.append(current_section)
        
        # Combine gateway entries with their statistics
        for i, gateway in enumerate(gateways):
            gateway_entry = {
                'name': gateway.get('name', ''),
                'CurrentUsers': self._convert_value(gateway.get('CurrentUsers', '0')),
                'PreviousUsers': self._convert_value(gateway.get('PreviousUsers', '0'))
            }
            
            # Add statistics for this gateway if available
            if i < len(sections):
                stats_lines = sections[i]
                for line in stats_lines:
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            stat_name = parts[0].strip()
                            stat_value = parts[1].strip()
                            
                            # Map the statistic names to our structure
                            if 'current-user' in stat_name:
                                gateway_entry['current_user'] = self._convert_value(stat_value)
                            elif 'gateway-max-concurrent-tunnel' in stat_name:
                                gateway_entry['gateway_max_concurrent_tunnel'] = self._convert_value(stat_value)
                            elif 'gateway-successful-ip-sec-connections' in stat_name:
                                gateway_entry['gateway_successful_ip_sec_connections'] = self._convert_value(stat_value)
                            elif 'successful-gateway-connections' in stat_name:
                                gateway_entry['successful_gateway_connections'] = self._convert_value(stat_value)
                            elif 'gateway-max-tunnel-setup-rate' in stat_name:
                                gateway_entry['gateway_max_tunnel_setup_rate'] = stat_value  # Keep as string (contains '/s')
                            elif 'record-gateway-tunnel-count' in stat_name:
                                gateway_entry['record_gateway_tunnel_count'] = self._convert_value(stat_value)
                            elif 'record-gateway-tunnel-count-last-check-time' in stat_name:
                                gateway_entry['record_gateway_tunnel_count_last_check_time'] = self._convert_value(stat_value)
            
            parsed_data['entry'].append(gateway_entry)
        
        return parsed_data 