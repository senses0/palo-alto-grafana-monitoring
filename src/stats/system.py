"""System statistics and monitoring (read-only)."""

from typing import Dict, Any
from datetime import datetime
import re

from ..palo_alto_client.client import PaloAltoClient
from ..utils.logger import get_logger, update_logger_firewall_context
from ..utils.parsers import parse_data_types
from ..utils.stats_config import StatsCollectionConfig
from config.settings import settings

logger = get_logger(__name__)

class SystemStats:
    """System statistics collector (read-only)."""
    
    def __init__(self, client: PaloAltoClient):
        self.client = client
        self.stats_config = StatsCollectionConfig(settings)
        # Update logger with firewall context from client
        if not client.multi_firewall_mode:
            update_logger_firewall_context(logger, client.firewall_name, client.host)
        else:
            # In multi-firewall mode, we'll update the logger context dynamically
            # when processing each firewall in the _get_system_data_single function
            pass
    
    def get_system_data(self) -> Dict[str, Any]:
        """Get comprehensive system data from all firewalls."""
        def _get_system_data_single(client: PaloAltoClient) -> Dict[str, Any]:
            """Get system data from a single firewall."""
            # Update logger context for this specific firewall
            update_logger_firewall_context(logger, client.firewall_name, client.host)
            
            result = {}
            firewall_name = client.firewall_name
            
            # Get system info (if enabled)
            if self.stats_config.is_collection_enabled('system', 'system_info', firewall_name):
                try:
                    system_info = client.execute_operational_command('<show><system><info></info></system></show>')
                    system_data = system_info.get('result', {})
                    
                    # Convert uptime to seconds if available
                    if 'system' in system_data and 'uptime' in system_data['system']:
                        uptime_str = system_data['system']['uptime']
                        uptime_seconds = self._convert_uptime_to_seconds(uptime_str)
                        system_data['system']['_uptime_seconds'] = uptime_seconds
                    
                    result['system_info'] = system_data
                except Exception as e:
                    logger.warning(f"Failed to get system info: {e}")
                    result['system_info'] = {}
            else:
                logger.debug(f"System info collection disabled for firewall {firewall_name}")
            
            # Get resource usage (if enabled)
            if self.stats_config.is_collection_enabled('system', 'resource_usage', firewall_name):
                try:
                    resource_usage = client.execute_operational_command('<show><system><resources></resources></system></show>')
                    result['resource_usage'] = self.parse_top_output(resource_usage.get('result', {}))
                except Exception as e:
                    logger.warning(f"Failed to get resource usage: {e}")
                    result['resource_usage'] = {}
            else:
                logger.debug(f"Resource usage collection disabled for firewall {firewall_name}")
            
            # Get disk usage (if enabled)
            if self.stats_config.is_collection_enabled('system', 'disk_usage', firewall_name):
                try:
                    disk_usage = client.execute_operational_command('<show><system><disk-space></disk-space></system></show>')
                    result['disk_usage'] = self.parse_disk_space_string(disk_usage.get('result', {}))
                except Exception as e:
                    logger.warning(f"Failed to get disk usage: {e}")
                    result['disk_usage'] = {}
            else:
                logger.debug(f"Disk usage collection disabled for firewall {firewall_name}")
            
            # Get HA status (if enabled)
            if self.stats_config.is_collection_enabled('system', 'ha_status', firewall_name):
                try:
                    ha_status = client.execute_operational_command('<show><high-availability><state></state></high-availability></show>')
                    result['ha_status'] = ha_status.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get HA status: {e}")
                    result['ha_status'] = {}
            else:
                logger.debug(f"HA status collection disabled for firewall {firewall_name}")
            
            # Get environmental data (if enabled)
            if self.stats_config.is_collection_enabled('system', 'environmental', firewall_name):
                try:
                    environmental_data = client.execute_operational_command('<show><system><environmentals></environmentals></system></show>')
                    result['environmental'] = environmental_data.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get environmental data: {e}")
                    result['environmental'] = {}
            else:
                logger.debug(f"Environmental data collection disabled for firewall {firewall_name}")
            
            # Get hardware info (if enabled)
            if self.stats_config.is_collection_enabled('system', 'hardware_info', firewall_name):
                try:
                    hardware_info = client.execute_operational_command('<show><system><hardware></hardware></system></show>')
                    result['hardware_info'] = hardware_info.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get hardware info: {e}")
                    result['hardware_info'] = {}
            else:
                logger.debug(f"Hardware info collection disabled for firewall {firewall_name}")
            
            # Get extended CPU data (if enabled)
            if self.stats_config.is_collection_enabled('system', 'extended_cpu', firewall_name):
                try:
                    extended_cpu_data = client.execute_operational_command('<show><running><resource-monitor></resource-monitor></running></show>')
                    result['extended_cpu'] = extended_cpu_data.get('result', {})
                except Exception as e:
                    logger.warning(f"Failed to get extended CPU data: {e}")
                    result['extended_cpu'] = {}
            else:
                logger.debug(f"Extended CPU data collection disabled for firewall {firewall_name}")
            
            # Add timestamp
            result['timestamp'] = datetime.now().isoformat()
            
            return parse_data_types(result)
        
        # Execute on all firewalls using the unified client
        return self.client.execute_on_all_firewalls(_get_system_data_single)
    

    def parse_top_output(self, top_output: str) -> Dict[str, Any]:
        """Parse top command output and extract key metrics."""
        if not top_output:
            return {}
        
        # Handle case where top_output is a dictionary instead of string
        if isinstance(top_output, dict):
            # If it's a dictionary, try to extract the text content
            if 'text' in top_output:
                top_output = top_output['text']
            elif 'result' in top_output:
                top_output = str(top_output['result'])
            else:
                return {}
        
        # Ensure we have a string to work with
        if not isinstance(top_output, str):
            return {}
        
        lines = top_output.strip().split('\n')
        if len(lines) < 5:
            return {}
        
        metrics = {}
        
        # Parse first line: uptime and load average
        # Example: "top - 12:26:55 up 6 days,  1:15,  0 users,  load average: 0.81, 0.91, 0.79"
        first_line = lines[0]
        uptime_match = re.search(r'up\s+(\d+)\s+days?,\s*(\d+):(\d+)', first_line)
        if uptime_match:
            metrics['uptime_days'] = int(uptime_match.group(1))
            metrics['uptime_hours'] = int(uptime_match.group(2))
            metrics['uptime_minutes'] = int(uptime_match.group(3))
        
        load_match = re.search(r'load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)', first_line)
        if load_match:
            metrics['load_average_1min'] = float(load_match.group(1))
            metrics['load_average_5min'] = float(load_match.group(2))
            metrics['load_average_15min'] = float(load_match.group(3))
        
        # Parse second line: task summary
        # Example: "Tasks: 247 total,   2 running, 244 sleeping,   0 stopped,   1 zombie"
        if len(lines) > 1:
            tasks_line = lines[1]
            tasks_match = re.search(r'Tasks:\s*(\d+)\s+total,\s*(\d+)\s+running,\s*(\d+)\s+sleeping,\s*(\d+)\s+stopped,\s*(\d+)\s+zombie', tasks_line)
            if tasks_match:
                metrics['tasks_total'] = int(tasks_match.group(1))
                metrics['tasks_running'] = int(tasks_match.group(2))
                metrics['tasks_sleeping'] = int(tasks_match.group(3))
                metrics['tasks_stopped'] = int(tasks_match.group(4))
                metrics['tasks_zombie'] = int(tasks_match.group(5))
        
        # Parse third line: CPU usage
        # Example: "%Cpu(s):  9.0 us, 16.4 sy,  9.0 ni, 62.7 id,  0.0 wa,  1.5 hi,  1.5 si,  0.0 st"
        if len(lines) > 2:
            cpu_line = lines[2]
            cpu_match = re.search(r'%Cpu\(s\):\s*([\d.]+)\s+us,\s*([\d.]+)\s+sy,\s*([\d.]+)\s+ni,\s*([\d.]+)\s+id,\s*([\d.]+)\s+wa,\s*([\d.]+)\s+hi,\s*([\d.]+)\s+si,\s*([\d.]+)\s+st', cpu_line)
            if cpu_match:
                metrics['cpu_user'] = float(cpu_match.group(1))
                metrics['cpu_system'] = float(cpu_match.group(2))
                metrics['cpu_nice'] = float(cpu_match.group(3))
                metrics['cpu_idle'] = float(cpu_match.group(4))
                metrics['cpu_iowait'] = float(cpu_match.group(5))
                metrics['cpu_hardware_interrupt'] = float(cpu_match.group(6))
                metrics['cpu_software_interrupt'] = float(cpu_match.group(7))
                metrics['cpu_steal'] = float(cpu_match.group(8))
        
        # Parse fourth line: memory usage
        # Example: "MiB Mem :  16030.8 total,    919.4 free,   5004.1 used,  10107.3 buff/cache"
        if len(lines) > 3:
            mem_line = lines[3]
            mem_match = re.search(r'MiB Mem\s*:\s*([\d.]+)\s+total,\s*([\d.]+)\s+free,\s*([\d.]+)\s+used,\s*([\d.]+)\s+buff/cache', mem_line)
            if mem_match:
                metrics['memory_total_mib'] = float(mem_match.group(1))
                metrics['memory_free_mib'] = float(mem_match.group(2))
                metrics['memory_used_mib'] = float(mem_match.group(3))
                metrics['memory_buff_cache_mib'] = float(mem_match.group(4))
                
                # Calculate memory usage percentage
                total = metrics['memory_total_mib']
                used = metrics['memory_used_mib']
                if total > 0:
                    metrics['memory_usage_percent'] = (used / total) * 100
        
        # Parse fifth line: swap usage
        # Example: "MiB Swap:   4000.0 total,   3999.7 free,      0.2 used.   5575.6 avail Mem"
        if len(lines) > 4:
            swap_line = lines[4]
            swap_match = re.search(r'MiB Swap:\s*([\d.]+)\s+total,\s*([\d.]+)\s+free,\s*([\d.]+)\s+used\.\s*([\d.]+)\s+avail Mem', swap_line)
            if swap_match:
                metrics['swap_total_mib'] = float(swap_match.group(1))
                metrics['swap_free_mib'] = float(swap_match.group(2))
                metrics['swap_used_mib'] = float(swap_match.group(3))
                metrics['memory_available_mib'] = float(swap_match.group(4))
                
                # Calculate swap usage percentage
                swap_total = metrics['swap_total_mib']
                swap_used = metrics['swap_used_mib']
                if swap_total > 0:
                    metrics['swap_usage_percent'] = (swap_used / swap_total) * 100
                else:
                    # No swap configured or available
                    metrics['swap_usage_percent'] = 0.0
        
        return metrics

    def parse_disk_usage(self, disk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse disk usage data."""
        disk_usage = {}
        
        if 'disk-space' in disk_data and 'entry' in disk_data['disk-space']:
            entries = disk_data['disk-space']['entry']
            if not isinstance(entries, list):
                entries = [entries]
            
            for entry in entries:
                mount_point = entry.get('mount-point', 'unknown')
                disk_usage[mount_point] = {
                    'device': entry.get('device', 'N/A'),
                    'size': entry.get('size', 'N/A'),
                    'used': entry.get('used', 'N/A'),
                    'available': entry.get('available', 'N/A'),
                    'use_percent': entry.get('use-percent', 'N/A')
                }
        
        return disk_usage

    def parse_disk_space_string(self, disk_output: str) -> Dict[str, Any]:
        """Parse disk space output from df command string."""
        disk_usage = {}
        
        # Handle case where disk_output is a dictionary instead of string
        if isinstance(disk_output, dict):
            # If it's a dictionary, try to extract the text content
            if 'text' in disk_output:
                disk_output = disk_output['text']
            elif 'result' in disk_output:
                disk_output = str(disk_output['result'])
            else:
                return {}
        
        # Ensure we have a string to work with
        if not isinstance(disk_output, str):
            return {}
        
        lines = disk_output.strip().split('\n')
        
        # Skip header line
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                filesystem = parts[0]
                size = parts[1]
                used = parts[2]
                available = parts[3]
                use_percent = parts[4].rstrip('%')
                mount_point = parts[5]
                
                disk_usage[mount_point] = {
                    'device': filesystem,
                    'size': size,
                    'used': used,
                    'available': available,
                    'use_percent': use_percent
                }
        
        return disk_usage

    def _convert_uptime_to_seconds(self, uptime_str: str) -> int:
        """
        Convert uptime string to seconds.
        
        Args:
            uptime_str: Uptime string in format "18 days, 22:03:09"
            
        Returns:
            Total uptime in seconds
            
        Example:
            "18 days, 22:03:09" -> 1638189 seconds
        """
        if not uptime_str:
            return 0
            
        try:
            # Parse the uptime string format: "18 days, 22:03:09"
            # Handle variations: "1 day, 22:03:09" or "22:03:09" (no days)
            parts = uptime_str.split(', ')
            
            days = 0
            time_part = uptime_str
            
            if len(parts) == 2:
                # Has days: "18 days, 22:03:09"
                days_match = re.match(r'(\d+)\s+days?', parts[0])
                if days_match:
                    days = int(days_match.group(1))
                    time_part = parts[1]
            elif len(parts) == 1:
                # No days: "22:03:09"
                time_part = parts[0]
            
            # Parse time part: "22:03:09"
            time_match = re.match(r'(\d+):(\d+):(\d+)', time_part)
            if time_match:
                hours = int(time_match.group(1))
                minutes = int(time_match.group(2))
                seconds = int(time_match.group(3))
                
                total_seconds = (days * 24 * 3600) + (hours * 3600) + (minutes * 60) + seconds
                return total_seconds
            else:
                logger.warning(f"Could not parse time part of uptime string: {uptime_str}")
                return 0
                
        except Exception as e:
            logger.warning(f"Error converting uptime string '{uptime_str}' to seconds: {e}")
            return 0