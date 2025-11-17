#!/usr/bin/env python3
"""
Palo Alto Networks Firewall to InfluxDB Line Protocol Converter v2

A clean, modular, schema-driven converter that transforms Palo Alto firewall 
statistics into InfluxDB line protocol format for time-series monitoring.

Features:
- Schema-driven design based on comprehensive data analysis
- Support for all 42 measurements across 7 categories
- Smart fallback logic for routing table counts (2 additional fallback measurements)
- Proper type handling and data conversions
- Multi-firewall support with consistent tagging
- Handles missing data gracefully

Usage:
    # From JSON file
    python influxdb_converter.py --input complete_stats.json
    
    # From live query with output
    python pa_query.py -o json all-stats | python influxdb_converter.py --output metrics.txt
    
    # Verbose mode
    python influxdb_converter.py --input complete_stats.json --verbose
"""

import json
import sys
import argparse
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
from collections import defaultdict


class InfluxDBLineProtocol:
    """Utilities for generating InfluxDB line protocol format."""
    
    @staticmethod
    def escape_tag_value(value: str) -> str:
        """Escape special characters in tag values."""
        if value is None:
            return ""
        value = str(value)
        # Escape commas, equals, and spaces in tag values
        value = value.replace(',', r'\,')
        value = value.replace('=', r'\=')
        value = value.replace(' ', r'\ ')
        return value
    
    @staticmethod
    def escape_field_key(key: str) -> str:
        """Escape special characters in field keys."""
        # Field keys need to escape commas, equals, and spaces
        key = key.replace(',', r'\,')
        key = key.replace('=', r'\=')
        key = key.replace(' ', r'\ ')
        return key
    
    @staticmethod
    def format_field_value(value: Any) -> str:
        """Format field value according to InfluxDB requirements."""
        if value is None:
            return None
        
        if isinstance(value, bool):
            return 'true' if value else 'false'
        elif isinstance(value, int):
            return f'{value}i'
        elif isinstance(value, float):
            return str(value)
        elif isinstance(value, str):
            # String values must be quoted and escaped
            escaped = value.replace('"', r'\"')
            return f'"{escaped}"'
        else:
            # Default to string
            escaped = str(value).replace('"', r'\"')
            return f'"{escaped}"'
    
    @staticmethod
    def build_line(measurement: str, tags: Dict[str, Any], 
                   fields: Dict[str, Any], timestamp: int) -> Optional[str]:
        """
        Build an InfluxDB line protocol string.
        
        Format: measurement,tag1=value1,tag2=value2 field1=value1,field2=value2 timestamp
        
        Args:
            measurement: Measurement name
            tags: Dictionary of tag key-value pairs
            fields: Dictionary of field key-value pairs
            timestamp: Unix timestamp in nanoseconds
            
        Returns:
            InfluxDB line protocol string or None if no valid fields
        """
        # Escape measurement name
        measurement = InfluxDBLineProtocol.escape_tag_value(measurement)
        
        # Build tag set (sorted for consistency)
        tag_parts = []
        for key in sorted(tags.keys()):
            value = tags[key]
            if value is not None and value != "":
                escaped_key = InfluxDBLineProtocol.escape_tag_value(key)
                escaped_value = InfluxDBLineProtocol.escape_tag_value(value)
                tag_parts.append(f'{escaped_key}={escaped_value}')
        
        tag_set = ',' + ','.join(tag_parts) if tag_parts else ''
        
        # Build field set
        field_parts = []
        for key in sorted(fields.keys()):
            value = fields[key]
            formatted_value = InfluxDBLineProtocol.format_field_value(value)
            if formatted_value is not None:
                escaped_key = InfluxDBLineProtocol.escape_field_key(key)
                field_parts.append(f'{escaped_key}={formatted_value}')
        
        if not field_parts:
            return None
        
        field_set = ','.join(field_parts)
        
        # Build complete line
        return f'{measurement}{tag_set} {field_set} {timestamp}'


class DataConverter:
    """Base converter with common utility functions."""
    
    def __init__(self, timestamp: Optional[int] = None, verbose: bool = False):
        """
        Initialize converter.
        
        Args:
            timestamp: Unix timestamp in nanoseconds. If None, uses current time.
            verbose: Enable verbose logging
        """
        self.timestamp = timestamp or int(datetime.now(timezone.utc).timestamp() * 1e9)
        self.verbose = verbose
        self.stats = {
            'lines_generated': 0,
            'errors': 0,
            'skipped': 0
        }
    
    def log(self, message: str, level: str = 'INFO'):
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[{level}] {message}", file=sys.stderr)
    
    def safe_int(self, value: Any) -> Optional[int]:
        """
        Safely convert a value to integer, handling strings and None.
        
        This is critical for InfluxDB compatibility - once InfluxDB sees a field
        as a certain type, it must remain that type. This method ensures numeric
        fields are consistently integers, whether the source data provides them
        as strings or integers.
        
        Args:
            value: Value to convert (can be int, str, or None)
            
        Returns:
            Integer value or None if conversion fails
        """
        if value is None or value == '':
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    
    def safe_float(self, value: Any, precision: int = 2) -> Optional[float]:
        """
        Safely convert a value to float with specified precision.
        
        This is critical for InfluxDB compatibility - ensures percentage and 
        decimal fields are always floats, never integers. Without this, round(0, 2)
        returns int(0) instead of float(0.0), causing schema conflicts.
        
        Args:
            value: Value to convert (can be int, float, str, or None)
            precision: Number of decimal places (default: 2)
            
        Returns:
            Float value rounded to precision, or None if conversion fails
        """
        if value is None or value == '':
            return None
        try:
            # Convert to float first, then round
            # This ensures round() always returns a float
            return round(float(value), precision)
        except (ValueError, TypeError):
            return None
    
    def parse_size_string(self, size_str: str) -> Optional[float]:
        """
        Parse size strings like '12G', '6.9G', '2.7G' to numeric values in GB.
        
        Args:
            size_str: Size string (e.g., '12G', '6.9M', '108K')
            
        Returns:
            Size in GB as float, or None if parsing fails
        """
        if not size_str or size_str == 0:
            return 0.0
        
        size_str = str(size_str).strip()
        
        # Match number and unit
        match = re.match(r'^([\d.]+)([KMGT]?)$', size_str, re.IGNORECASE)
        if not match:
            return None
        
        value = float(match.group(1))
        unit = match.group(2).upper() if match.group(2) else ''
        
        # Convert to GB
        conversions = {
            '': 1.0,  # Assume bytes if no unit
            'K': 1.0 / (1024 ** 3),
            'M': 1.0 / (1024 ** 2),
            'G': 1.0,
            'T': 1024.0
        }
        
        return value * conversions.get(unit, 1.0)


class SystemConverter(DataConverter):
    """Converter for system module (13 measurements)."""
    
    def convert(self, hostname: str, data: Dict[str, Any]) -> List[str]:
        """Convert system module data to InfluxDB line protocol."""
        lines = []
        
        # 1. System Identity
        if 'system_info' in data and 'system' in data['system_info']:
            line = self._convert_system_identity(hostname, data['system_info']['system'])
            if line:
                lines.append(line)
        
        # 2. System Uptime
        if 'system_info' in data and 'system' in data['system_info']:
            line = self._convert_system_uptime(hostname, data['system_info']['system'])
            if line:
                lines.append(line)
        
        # 3. Content Versions
        if 'system_info' in data and 'system' in data['system_info']:
            line = self._convert_content_versions(hostname, data['system_info']['system'])
            if line:
                lines.append(line)
        
        # 4. MAC Count
        if 'system_info' in data and 'system' in data['system_info']:
            line = self._convert_mac_count(hostname, data['system_info']['system'])
            if line:
                lines.append(line)
        
        # 5. CPU Usage
        if 'resource_usage' in data:
            line = self._convert_cpu_usage(hostname, data['resource_usage'])
            if line:
                lines.append(line)
        
        # 6. Memory Usage
        if 'resource_usage' in data:
            line = self._convert_memory_usage(hostname, data['resource_usage'])
            if line:
                lines.append(line)
        
        # 7. Swap Usage
        if 'resource_usage' in data:
            line = self._convert_swap_usage(hostname, data['resource_usage'])
            if line:
                lines.append(line)
        
        # 8. Load Average
        if 'resource_usage' in data:
            line = self._convert_load_average(hostname, data['resource_usage'])
            if line:
                lines.append(line)
        
        # 9. Task Statistics
        if 'resource_usage' in data:
            line = self._convert_task_stats(hostname, data['resource_usage'])
            if line:
                lines.append(line)
        
        # 10. Disk Usage (multiple lines - one per mount point)
        if 'disk_usage' in data:
            disk_lines = self._convert_disk_usage(hostname, data['disk_usage'])
            lines.extend(disk_lines)
        
        # 11. HA Status
        if 'ha_status' in data:
            line = self._convert_ha_status(hostname, data['ha_status'])
            if line:
                lines.append(line)
        
        # 12. CPU Dataplane Tasks (extended CPU metrics)
        if 'extended_cpu' in data:
            line = self._convert_cpu_dataplane_tasks(hostname, data['extended_cpu'])
            if line:
                lines.append(line)
        
        # 13. CPU Dataplane Cores (per-core extended CPU metrics)
        if 'extended_cpu' in data:
            core_lines = self._convert_cpu_dataplane_cores(hostname, data['extended_cpu'])
            lines.extend(core_lines)
        
        self.stats['lines_generated'] += len(lines)
        return lines
    
    def _convert_system_identity(self, hostname: str, system: Dict) -> Optional[str]:
        """Convert system identity information."""
        tags = {
            'hostname': hostname,
            'model': system.get('model'),
            'family': system.get('family'),
            'serial': system.get('serial')
        }
        
        # Convert yes/no to boolean for DHCP fields
        is_dhcp = system.get('is-dhcp')
        is_dhcp_bool = True if is_dhcp == 'yes' else False if is_dhcp == 'no' else None
        
        is_dhcp6 = system.get('is-dhcp6')
        is_dhcp6_bool = True if is_dhcp6 == 'yes' else False if is_dhcp6 == 'no' else None
        
        fields = {
            'sw_version': system.get('sw-version'),
            'vm_cores': self.safe_int(system.get('vm-cores')),
            'vm_mem_mb': round(system.get('vm-mem', 0) / 1024, 2) if system.get('vm-mem') else None,
            'operational_mode': system.get('operational-mode'),
            'advanced_routing': system.get('advanced-routing'),
            'multi_vsys': system.get('multi-vsys'),
            'ip_address': system.get('ip-address'),
            'mac_address': system.get('mac-address'),
            'ipv6_address': system.get('ipv6-address'),
            'is_dhcp': is_dhcp_bool,
            'is_dhcp6': is_dhcp6_bool
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_system_identity', tags, fields, self.timestamp)
    
    def _convert_system_uptime(self, hostname: str, system: Dict) -> Optional[str]:
        """Convert system uptime metrics."""
        tags = {
            'hostname': hostname
        }
        
        uptime_seconds = system.get('_uptime_seconds')
        fields = {
            'uptime_seconds': uptime_seconds,
            'uptime_days': round(uptime_seconds / 86400, 2) if uptime_seconds else None
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_system_uptime', tags, fields, self.timestamp)
    
    def _convert_content_versions(self, hostname: str, system: Dict) -> Optional[str]:
        """Convert content version information."""
        tags = {
            'hostname': hostname
        }
        
        fields = {
            'app_version': system.get('app-version'),
            'av_version': self.safe_int(system.get('av-version')),
            'threat_version': self.safe_int(system.get('threat-version')),
            'wf_private_version': self.safe_int(system.get('wf-private-version')),
            'wildfire_version': self.safe_int(system.get('wildfire-version')),
            'wildfire_rt': system.get('wildfire-rt'),
            'url_filtering_version': self.safe_int(system.get('url-filtering-version')),
            'url_db': system.get('url-db'),
            'logdb_version': system.get('logdb-version'),
            'device_dictionary_version': system.get('device-dictionary-version'),
            'global_protect_client_package_version': system.get('global-protect-client-package-version')
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_content_versions', tags, fields, self.timestamp)
    
    def _convert_mac_count(self, hostname: str, system: Dict) -> Optional[str]:
        """Convert MAC address count (handles both hardware and VM firewalls)."""
        tags = {
            'hostname': hostname,
            'model': system.get('model'),
            'family': system.get('family')
        }
        
        # VM firewalls use 'vm-mac-count', hardware firewalls use 'mac_count'
        mac_count = system.get('vm-mac-count') or system.get('mac_count')
        
        fields = {
            'mac_count': self.safe_int(mac_count)
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_mac_count', tags, fields, self.timestamp)
    
    def _convert_cpu_usage(self, hostname: str, resources: Dict) -> Optional[str]:
        """Convert CPU usage metrics."""
        tags = {'hostname': hostname}
        
        # All CPU percentages must be floats to avoid InfluxDB schema conflicts
        # The firewall can return these as either int or float
        cpu_idle = self.safe_float(resources.get('cpu_idle', 0), 2)
        
        # Calculate cpu_total_used as float
        cpu_total = (100.0 - cpu_idle) if cpu_idle is not None else None
        
        fields = {
            'cpu_user': self.safe_float(resources.get('cpu_user'), 2),
            'cpu_system': self.safe_float(resources.get('cpu_system'), 2),
            'cpu_nice': self.safe_float(resources.get('cpu_nice'), 2),
            'cpu_idle': cpu_idle,
            'cpu_iowait': self.safe_float(resources.get('cpu_iowait'), 2),
            'cpu_hardware_interrupt': self.safe_float(resources.get('cpu_hardware_interrupt'), 2),
            'cpu_software_interrupt': self.safe_float(resources.get('cpu_software_interrupt'), 2),
            'cpu_steal': self.safe_float(resources.get('cpu_steal'), 2),
            'cpu_total_used': self.safe_float(cpu_total, 2)
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_cpu_usage', tags, fields, self.timestamp)
    
    def _convert_memory_usage(self, hostname: str, resources: Dict) -> Optional[str]:
        """Convert memory usage metrics."""
        tags = {'hostname': hostname}
        
        fields = {
            'memory_total_mib': resources.get('memory_total_mib'),
            'memory_free_mib': resources.get('memory_free_mib'),
            'memory_used_mib': resources.get('memory_used_mib'),
            'memory_buff_cache_mib': resources.get('memory_buff_cache_mib'),
            'memory_available_mib': resources.get('memory_available_mib'),
            'memory_usage_percent': self.safe_float(resources.get('memory_usage_percent', 0), 2)
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_memory_usage', tags, fields, self.timestamp)
    
    def _convert_swap_usage(self, hostname: str, resources: Dict) -> Optional[str]:
        """Convert swap usage metrics."""
        tags = {'hostname': hostname}
        
        fields = {
            'swap_total_mib': resources.get('swap_total_mib'),
            'swap_free_mib': resources.get('swap_free_mib'),
            'swap_used_mib': resources.get('swap_used_mib'),
            'swap_usage_percent': self.safe_float(resources.get('swap_usage_percent', 0), 2)
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_swap_usage', tags, fields, self.timestamp)
    
    def _convert_load_average(self, hostname: str, resources: Dict) -> Optional[str]:
        """Convert load average metrics."""
        tags = {'hostname': hostname}
        
        # Load averages are always floats to avoid InfluxDB schema conflicts
        fields = {
            'load_1min': self.safe_float(resources.get('load_average_1min'), 2),
            'load_5min': self.safe_float(resources.get('load_average_5min'), 2),
            'load_15min': self.safe_float(resources.get('load_average_15min'), 2)
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_load_average', tags, fields, self.timestamp)
    
    def _convert_task_stats(self, hostname: str, resources: Dict) -> Optional[str]:
        """Convert task/process statistics."""
        tags = {'hostname': hostname}
        
        fields = {
            'tasks_total': resources.get('tasks_total'),
            'tasks_running': resources.get('tasks_running'),
            'tasks_sleeping': resources.get('tasks_sleeping'),
            'tasks_stopped': resources.get('tasks_stopped'),
            'tasks_zombie': resources.get('tasks_zombie')
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_task_stats', tags, fields, self.timestamp)
    
    def _convert_disk_usage(self, hostname: str, disk_data: Dict) -> List[str]:
        """Convert disk usage metrics (one line per mount point)."""
        lines = []
        
        for mount_point, mount_data in disk_data.items():
            tags = {
                'hostname': hostname,
                'mount_point': mount_point,
                'device': mount_data.get('device')
            }
            
            # Parse size strings to GB
            size_gb = self.parse_size_string(mount_data.get('size'))
            used_gb = self.parse_size_string(mount_data.get('used'))
            available_gb = self.parse_size_string(mount_data.get('available'))
            
            fields = {
                'use_percent': self.safe_float(mount_data.get('use_percent'), 2),
                'size_gb': round(size_gb, 2) if size_gb is not None else None,
                'used_gb': round(used_gb, 2) if used_gb is not None else None,
                'available_gb': round(available_gb, 2) if available_gb is not None else None
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_disk_usage', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_ha_status(self, hostname: str, ha_data: Dict) -> Optional[str]:
        """Convert HA status with comprehensive HA metrics."""
        tags = {'hostname': hostname}
        
        fields = {
            'enabled': ha_data.get('enabled')
        }
        
        # Only extract additional fields if HA is enabled and group data exists
        if ha_data.get('enabled') == 'yes' and 'group' in ha_data:
            group = ha_data['group']
            
            # Core HA State Information
            fields['ha_mode'] = group.get('mode')
            
            if 'local-info' in group:
                local_info = group['local-info']
                fields['local_state'] = local_info.get('state')
                fields['local_state_duration'] = self.safe_int(local_info.get('state-duration'))
                fields['local_priority'] = self.safe_int(local_info.get('priority'))
                fields['preempt_flap_cnt'] = self.safe_int(local_info.get('preempt-flap-cnt'))
                fields['nonfunc_flap_cnt'] = self.safe_int(local_info.get('nonfunc-flap-cnt'))
                fields['max_flaps'] = self.safe_int(local_info.get('max-flaps'))
                
                # Synchronization Status
                fields['state_sync'] = local_info.get('state-sync')
                fields['state_sync_type'] = local_info.get('state-sync-type')
                
                # Version Compatibility (11 fields from local-info)
                # DLP, ND, OC don't have -compat suffix in source, so we add it
                fields['dlp_compat'] = local_info.get('DLP')
                fields['nd_compat'] = local_info.get('ND')
                fields['oc_compat'] = local_info.get('OC')
                # These already have -compat suffix in source
                fields['build_compat'] = local_info.get('build-compat')
                fields['url_compat'] = local_info.get('url-compat')
                fields['app_compat'] = local_info.get('app-compat')
                fields['iot_compat'] = local_info.get('iot-compat')
                fields['av_compat'] = local_info.get('av-compat')
                fields['threat_compat'] = local_info.get('threat-compat')
                fields['vpnclient_compat'] = local_info.get('vpnclient-compat')
                fields['gpclient_compat'] = local_info.get('gpclient-compat')
            
            if 'peer-info' in group:
                peer_info = group['peer-info']
                fields['peer_state'] = peer_info.get('state')
                fields['peer_state_duration'] = self.safe_int(peer_info.get('state-duration'))
                fields['peer_priority'] = self.safe_int(peer_info.get('priority'))
                
                # Connection Health
                fields['peer_conn_status'] = peer_info.get('conn-status')
                
                # HA1 connection status
                if 'conn-ha1' in peer_info:
                    fields['peer_conn_ha1_status'] = peer_info['conn-ha1'].get('conn-status')
                
                # HA2 connection status
                if 'conn-ha2' in peer_info:
                    fields['peer_conn_ha2_status'] = peer_info['conn-ha2'].get('conn-status')
            
            # Running sync status (at group level)
            fields['running_sync'] = group.get('running-sync')
            fields['running_sync_enabled'] = group.get('running-sync-enabled')
        
        return InfluxDBLineProtocol.build_line('palo_alto_ha_status', tags, fields, self.timestamp)
    
    def _parse_task_cpu(self, value: str) -> Optional[float]:
        """
        Parse task CPU percentage string to float.
        
        Args:
            value: CPU percentage string (e.g., "0%", "12.5%")
            
        Returns:
            Float value or None if parsing fails
        """
        if not value:
            return None
        # Remove '%' and convert to float
        value_str = str(value).rstrip('%')
        return self.safe_float(value_str, 2)
    
    def _calculate_average_from_csv(self, value_string: str) -> Optional[float]:
        """
        Calculate average from comma-separated value string.
        
        Args:
            value_string: Comma-separated values (e.g., "0,0,1,0,...")
            
        Returns:
            Average as float or None if parsing fails
        """
        if not value_string:
            return None
        
        try:
            values = [int(v.strip()) for v in str(value_string).split(',') if v.strip()]
            if not values:
                return None
            return self.safe_float(sum(values) / len(values), 2)
        except (ValueError, TypeError):
            return None
    
    def _convert_cpu_dataplane_tasks(self, hostname: str, extended_cpu: Dict) -> Optional[str]:
        """
        Convert dataplane task CPU utilization and resource utilization.
        
        This captures instantaneous task CPU percentages and averaged resource
        utilization over 60 seconds from the dataplane processor.
        """
        # Navigate to resource-monitor data
        if 'resource-monitor' not in extended_cpu:
            return None
        
        resource_monitor = extended_cpu['resource-monitor']
        
        # Handle both nested structures
        if 'data-processors' in resource_monitor:
            data_processors = resource_monitor['data-processors']
        else:
            # Some versions may have it directly
            data_processors = resource_monitor
        
        # Get dp0 data (primary dataplane processor)
        if 'dp0' not in data_processors:
            return None
        
        dp0 = data_processors['dp0']
        
        # Get second-level data
        if 'second' not in dp0:
            return None
        
        second_data = dp0['second']
        
        tags = {
            'hostname': hostname,
            'dp_id': 'dp0'
        }
        
        fields = {}
        
        # 1. Task CPU percentages (instantaneous)
        if 'task' in second_data and second_data['task']:
            task_data = second_data['task']
            task_mapping = {
                'flow_lookup': 'task_flow_lookup',
                'flow_fastpath': 'task_flow_fastpath',
                'flow_slowpath': 'task_flow_slowpath',
                'flow_forwarding': 'task_flow_forwarding',
                'flow_mgmt': 'task_flow_mgmt',
                'flow_ctrl': 'task_flow_ctrl',
                'nac_result': 'task_nac_result',
                'flow_np': 'task_flow_np',
                'dfa_result': 'task_dfa_result',
                'module_internal': 'task_module_internal',
                'aho_result': 'task_aho_result',
                'zip_result': 'task_zip_result',
                'pktlog_forwarding': 'task_pktlog_forwarding',
                'send_out': 'task_send_out',
                'flow_host': 'task_flow_host',
                'send_host': 'task_send_host',
                'fpga_result': 'task_fpga_result'
            }
            
            for source_key, field_name in task_mapping.items():
                value = task_data.get(source_key)
                if value is not None:
                    fields[field_name] = self._parse_task_cpu(value)
        
        # 2. Resource utilization (60-second average)
        if 'resource-utilization' in second_data:
            resource_util = second_data['resource-utilization']
            if 'entry' in resource_util:
                entries = resource_util['entry']
                if not isinstance(entries, list):
                    entries = [entries]
                
                for entry in entries:
                    name = entry.get('name', '').lower()
                    value = entry.get('value')
                    
                    if value is not None:
                        avg_value = self._calculate_average_from_csv(value)
                        if avg_value is not None:
                            # Map resource names to field names
                            if name == 'session':
                                fields['resource_session_avg'] = avg_value
                            elif name == 'packet buffer':
                                fields['resource_packet_buffer_avg'] = avg_value
                            elif name == 'packet descriptor':
                                fields['resource_packet_descriptor_avg'] = avg_value
                            elif name == 'sw tags descriptor':
                                fields['resource_sw_tags_descriptor_avg'] = avg_value
        
        # 3. CPU core count
        if 'cpu-load-average' in second_data:
            cpu_load = second_data['cpu-load-average']
            if 'entry' in cpu_load:
                entries = cpu_load['entry']
                if not isinstance(entries, list):
                    entries = [entries]
                fields['cpu_cores'] = len(entries)
        
        return InfluxDBLineProtocol.build_line('palo_alto_cpu_dataplane_tasks', tags, fields, self.timestamp)
    
    def _convert_cpu_dataplane_cores(self, hostname: str, extended_cpu: Dict) -> List[str]:
        """
        Convert per-core dataplane CPU utilization.
        
        This creates one data point per dataplane core with 60-second average utilization.
        """
        lines = []
        
        # Navigate to resource-monitor data
        if 'resource-monitor' not in extended_cpu:
            return lines
        
        resource_monitor = extended_cpu['resource-monitor']
        
        # Handle both nested structures
        if 'data-processors' in resource_monitor:
            data_processors = resource_monitor['data-processors']
        else:
            data_processors = resource_monitor
        
        # Get dp0 data (primary dataplane processor)
        if 'dp0' not in data_processors:
            return lines
        
        dp0 = data_processors['dp0']
        
        # Get second-level data
        if 'second' not in dp0:
            return lines
        
        second_data = dp0['second']
        
        # Get per-core CPU load averages
        if 'cpu-load-average' not in second_data:
            return lines
        
        cpu_load = second_data['cpu-load-average']
        if 'entry' not in cpu_load:
            return lines
        
        entries = cpu_load['entry']
        if not isinstance(entries, list):
            entries = [entries]
        
        # Create one data point per core
        for entry in entries:
            core_id = entry.get('coreid')
            value = entry.get('value')
            
            if core_id is not None and value is not None:
                tags = {
                    'hostname': hostname,
                    'dp_id': 'dp0',
                    'core_id': str(core_id)
                }
                
                # Calculate 60-second average for this core
                avg_utilization = self._calculate_average_from_csv(value)
                
                fields = {
                    'cpu_utilization_avg': avg_utilization
                }
                
                line = InfluxDBLineProtocol.build_line('palo_alto_cpu_dataplane_cores', tags, fields, self.timestamp)
                if line:
                    lines.append(line)
        
        return lines


class EnvironmentalConverter(DataConverter):
    """Converter for environmental module (4 measurements - hardware firewalls only)."""
    
    def convert(self, hostname: str, data: Dict[str, Any]) -> List[str]:
        """Convert environmental data to InfluxDB line protocol."""
        lines = []
        
        # Environmental data is only available on hardware firewalls
        if 'environmental' not in data:
            self.log(f"No environmental data found for {hostname} (VM firewall?)", "DEBUG")
            return lines
        
        env_data = data['environmental']
        
        # 1. Thermal Sensors
        if 'thermal' in env_data:
            thermal_lines = self._convert_thermal(hostname, env_data['thermal'])
            lines.extend(thermal_lines)
        
        # 2. Fan Sensors
        if 'fan' in env_data:
            fan_lines = self._convert_fan(hostname, env_data['fan'])
            lines.extend(fan_lines)
        
        # 3. Power/Voltage Sensors
        if 'power' in env_data:
            power_lines = self._convert_power(hostname, env_data['power'])
            lines.extend(power_lines)
        
        # 4. Power Supply Status
        if 'power-supply' in env_data:
            ps_lines = self._convert_power_supply(hostname, env_data['power-supply'])
            lines.extend(ps_lines)
        
        self.stats['lines_generated'] += len(lines)
        return lines
    
    def _convert_thermal(self, hostname: str, thermal_data: Dict) -> List[str]:
        """Convert thermal sensor data."""
        lines = []
        
        # Iterate through all slots
        for slot_name, slot_data in thermal_data.items():
            if not isinstance(slot_data, dict) or 'entry' not in slot_data:
                continue
            
            entries = slot_data.get('entry', [])
            if not isinstance(entries, list):
                entries = [entries]
            
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                
                tags = {
                    'hostname': hostname,
                    'slot': entry.get('slot'),
                    'description': entry.get('description')
                }
                
                fields = {}
                
                # Temperature reading
                temp_c = self.safe_float(entry.get('DegreesC'))
                if temp_c is not None:
                    fields['temperature_c'] = temp_c
                
                # Thresholds
                min_temp = self.safe_float(entry.get('min'))
                if min_temp is not None:
                    fields['min_temp_c'] = min_temp
                
                max_temp = self.safe_float(entry.get('max'))
                if max_temp is not None:
                    fields['max_temp_c'] = max_temp
                
                # Alarm status
                alarm = entry.get('alarm')
                if alarm is not None:
                    fields['alarm'] = 1 if alarm else 0
                
                if fields:
                    line = InfluxDBLineProtocol.build_line('palo_alto_env_thermal', tags, fields, self.timestamp)
                    if line:
                        lines.append(line)
        
        return lines
    
    def _convert_fan(self, hostname: str, fan_data: Dict) -> List[str]:
        """Convert fan sensor data."""
        lines = []
        
        # Iterate through all slots
        for slot_name, slot_data in fan_data.items():
            if not isinstance(slot_data, dict) or 'entry' not in slot_data:
                continue
            
            entries = slot_data.get('entry', [])
            if not isinstance(entries, list):
                entries = [entries]
            
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                
                tags = {
                    'hostname': hostname,
                    'slot': entry.get('slot'),
                    'description': entry.get('description')
                }
                
                fields = {}
                
                # Fan RPM
                rpm = self.safe_int(entry.get('RPMs'))
                if rpm is not None:
                    fields['rpm'] = rpm
                
                # Minimum threshold
                min_rpm = self.safe_int(entry.get('min'))
                if min_rpm is not None:
                    fields['min_rpm'] = min_rpm
                
                # Alarm status
                alarm = entry.get('alarm')
                if alarm is not None:
                    fields['alarm'] = 1 if alarm else 0
                
                if fields:
                    line = InfluxDBLineProtocol.build_line('palo_alto_env_fan', tags, fields, self.timestamp)
                    if line:
                        lines.append(line)
        
        return lines
    
    def _convert_power(self, hostname: str, power_data: Dict) -> List[str]:
        """Convert voltage sensor data."""
        lines = []
        
        # Iterate through all slots
        for slot_name, slot_data in power_data.items():
            if not isinstance(slot_data, dict) or 'entry' not in slot_data:
                continue
            
            entries = slot_data.get('entry', [])
            if not isinstance(entries, list):
                entries = [entries]
            
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                
                tags = {
                    'hostname': hostname,
                    'slot': entry.get('slot'),
                    'description': entry.get('description')
                }
                
                fields = {}
                
                # Voltage reading
                volts = self.safe_float(entry.get('Volts'), precision=4)
                if volts is not None:
                    fields['volts'] = volts
                
                # Thresholds
                min_volts = self.safe_float(entry.get('min'), precision=4)
                if min_volts is not None:
                    fields['min_volts'] = min_volts
                
                max_volts = self.safe_float(entry.get('max'), precision=4)
                if max_volts is not None:
                    fields['max_volts'] = max_volts
                
                # Alarm status
                alarm = entry.get('alarm')
                if alarm is not None:
                    fields['alarm'] = 1 if alarm else 0
                
                if fields:
                    line = InfluxDBLineProtocol.build_line('palo_alto_env_power', tags, fields, self.timestamp)
                    if line:
                        lines.append(line)
        
        return lines
    
    def _convert_power_supply(self, hostname: str, ps_data: Dict) -> List[str]:
        """Convert power supply status data."""
        lines = []
        
        # Iterate through all slots
        for slot_name, slot_data in ps_data.items():
            if not isinstance(slot_data, dict) or 'entry' not in slot_data:
                continue
            
            entries = slot_data.get('entry', [])
            if not isinstance(entries, list):
                entries = [entries]
            
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                
                tags = {
                    'hostname': hostname,
                    'slot': entry.get('slot'),
                    'description': entry.get('description')
                }
                
                fields = {}
                
                # Inserted status
                inserted = entry.get('Inserted')
                if inserted is not None:
                    fields['inserted'] = 1 if inserted else 0
                
                # Minimum required status
                min_req = entry.get('min')
                if min_req is not None:
                    fields['min_required'] = 1 if min_req else 0
                
                # Alarm status
                alarm = entry.get('alarm')
                if alarm is not None:
                    fields['alarm'] = 1 if alarm else 0
                
                if fields:
                    line = InfluxDBLineProtocol.build_line('palo_alto_env_power_supply', tags, fields, self.timestamp)
                    if line:
                        lines.append(line)
        
        return lines


class InterfaceConverter(DataConverter):
    """Converter for interface module (4 measurements)."""
    
    def convert(self, hostname: str, data: Dict[str, Any]) -> List[str]:
        """Convert interface module data to InfluxDB line protocol."""
        lines = []
        
        # 1. Interface Hardware Info
        if 'interface_info' in data and 'hw' in data['interface_info']:
            hw_lines = self._convert_interface_info(hostname, data['interface_info']['hw'])
            lines.extend(hw_lines)
        
        # 2. Interface Logical Config
        if 'interface_info' in data and 'ifnet' in data['interface_info']:
            logical_lines = self._convert_interface_logical(hostname, data['interface_info']['ifnet'])
            lines.extend(logical_lines)
        
        # 3. Interface Hardware Counters (physical port statistics)
        if 'interface_counters' in data and 'hw' in data['interface_counters']:
            counter_lines = self._convert_interface_counters_hw(hostname, data['interface_counters']['hw'])
            lines.extend(counter_lines)
        
        # 4. Interface Logical Counters (firewall/security processing statistics)
        if 'interface_counters' in data and 'ifnet' in data['interface_counters']:
            logical_counter_lines = self._convert_interface_counters_logical(hostname, data['interface_counters']['ifnet'])
            lines.extend(logical_counter_lines)
        
        self.stats['lines_generated'] += len(lines)
        return lines
    
    def _convert_interface_info(self, hostname: str, hw_data: Dict) -> List[str]:
        """Convert interface hardware information."""
        lines = []
        
        if 'entry' not in hw_data:
            return lines
        
        for interface in hw_data['entry']:
            tags = {
                'hostname': hostname,
                'interface': interface.get('name'),
                'type': str(interface.get('type'))
            }
            
            fields = {
                'state': interface.get('state'),
                'speed': self.safe_int(interface.get('speed')),
                'duplex': interface.get('duplex'),
                'mac': interface.get('mac'),
                'mode': interface.get('mode'),
                'fec': interface.get('fec')
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_interface_info', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_interface_logical(self, hostname: str, ifnet_data: Dict) -> List[str]:
        """Convert interface logical configuration."""
        lines = []
        
        if 'entry' not in ifnet_data:
            return lines
        
        for interface in ifnet_data['entry']:
            tags = {
                'hostname': hostname,
                'interface': interface.get('name'),
                'zone': interface.get('zone'),
                'vsys': str(interface.get('vsys'))
            }
            
            fields = {
                'ip': interface.get('ip'),
                'fwd': interface.get('fwd'),
                'tag': interface.get('tag')
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_interface_logical', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_interface_counters_hw(self, hostname: str, hw_data: Dict) -> List[str]:
        """Convert interface hardware/port traffic counters."""
        lines = []
        
        if 'entry' not in hw_data:
            return lines
        
        for interface in hw_data['entry']:
            port = interface.get('port', {})
            
            tags = {
                'hostname': hostname,
                'interface': interface.get('name')
            }
            
            fields = {
                # Port-level counters from hardware
                'rx_bytes': port.get('rx-bytes'),
                'rx_unicast': port.get('rx-unicast'),
                'rx_multicast': port.get('rx-multicast'),
                'rx_broadcast': port.get('rx-broadcast'),
                'rx_error': port.get('rx-error'),
                'rx_discards': port.get('rx-discards'),
                'tx_bytes': port.get('tx-bytes'),
                'tx_unicast': port.get('tx-unicast'),
                'tx_multicast': port.get('tx-multicast'),
                'tx_broadcast': port.get('tx-broadcast'),
                'tx_error': port.get('tx-error'),
                'tx_discards': port.get('tx-discards'),
                'link_down_count': port.get('link-down'),
                # Interface-level counters
                'ibytes': interface.get('ibytes'),
                'obytes': interface.get('obytes'),
                'ipackets': interface.get('ipackets'),
                'opackets': interface.get('opackets'),
                'ierrors': interface.get('ierrors'),
                'idrops': interface.get('idrops')
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_interface_counters_hw', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_interface_counters_logical(self, hostname: str, ifnet_data: Dict) -> List[str]:
        """Convert interface logical/firewall-level counters."""
        lines = []
        
        # Navigate nested structure: ifnet.ifnet.entry
        if 'ifnet' not in ifnet_data:
            return lines
        
        inner_ifnet = ifnet_data['ifnet']
        if 'entry' not in inner_ifnet:
            return lines
        
        for interface in inner_ifnet['entry']:
            tags = {
                'hostname': hostname,
                'interface': interface.get('name')
            }
            
            fields = {
                # Basic traffic counters
                'ibytes': interface.get('ibytes'),
                'obytes': interface.get('obytes'),
                'ipackets': interface.get('ipackets'),
                'opackets': interface.get('opackets'),
                'ierrors': interface.get('ierrors'),
                'idrops': interface.get('idrops'),
                # Firewall processing counters
                'flowstate': interface.get('flowstate'),
                'ifwderrors': interface.get('ifwderrors'),
                # Routing/forwarding drops
                'noroute': interface.get('noroute'),
                'noarp': interface.get('noarp'),
                'noneigh': interface.get('noneigh'),
                'neighpend': interface.get('neighpend'),
                'nomac': interface.get('nomac'),
                # Security drops
                'zonechange': interface.get('zonechange'),
                'land': interface.get('land'),
                'pod': interface.get('pod'),
                'teardrop': interface.get('teardrop'),
                'ipspoof': interface.get('ipspoof'),
                'macspoof': interface.get('macspoof'),
                'icmp_frag': interface.get('icmp_frag'),
                # Encapsulation
                'l2_encap': interface.get('l2_encap'),
                'l2_decap': interface.get('l2_decap'),
                # Connection counters
                'tcp_conn': interface.get('tcp_conn'),
                'udp_conn': interface.get('udp_conn'),
                'sctp_conn': interface.get('sctp_conn'),
                'other_conn': interface.get('other_conn')
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_interface_counters_logical', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines


class RoutingConverter(DataConverter):
    """Converter for routing module (4 primary measurements + 2 fallback measurements)."""
    
    def convert(self, hostname: str, data: Dict[str, Any]) -> List[str]:
        """Convert routing module data to InfluxDB line protocol."""
        lines = []
        
        # 1. BGP Summary
        if 'bgp_summary' in data and data['bgp_summary']:
            line = self._convert_bgp_summary(hostname, data['bgp_summary'])
            if line:
                lines.append(line)
        
        # 2. BGP Peer Status
        if 'bgp_peer_status' in data and data['bgp_peer_status']:
            peer_lines = self._convert_bgp_peers(hostname, data['bgp_peer_status'])
            lines.extend(peer_lines)
        
        # 3. BGP Path Monitor
        if 'bgp_path_monitor' in data and 'entry' in data['bgp_path_monitor']:
            path_lines = self._convert_bgp_path_monitor(hostname, data['bgp_path_monitor']['entry'])
            lines.extend(path_lines)
        
        # 4. Route Counts - Primary: from routing_table
        if 'routing_table' in data and data['routing_table']:
            route_lines = self._convert_routing_table_counts(hostname, data['routing_table'])
            lines.extend(route_lines)
        # Fallback: from individual protocol modules
        else:
            # Static routes fallback
            if 'static_routes' in data and data['static_routes']:
                line = self._convert_static_routes_count(hostname, data['static_routes'])
                if line:
                    lines.append(line)
            
            # BGP routes fallback
            if 'bgp_routes' in data and data['bgp_routes']:
                line = self._convert_bgp_routes_count(hostname, data['bgp_routes'])
                if line:
                    lines.append(line)
        
        self.stats['lines_generated'] += len(lines)
        return lines
    
    def _convert_bgp_summary(self, hostname: str, summary: Dict) -> Optional[str]:
        """Convert BGP summary."""
        tags = {
            'hostname': hostname,
            'router_id': summary.get('router_id'),
            'local_as': str(summary.get('local_as')) if summary.get('local_as') else None
        }
        
        fields = {
            'total_peers': summary.get('total_peers'),
            'peers_established': summary.get('peers_established'),
            'peers_down': summary.get('peers_down'),
            'total_prefixes': summary.get('total_prefixes')
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_bgp_summary', tags, fields, self.timestamp)
    
    def _convert_bgp_peers(self, hostname: str, peers: Dict) -> List[str]:
        """Convert BGP peer status (one line per peer)."""
        lines = []
        
        for peer_name, peer in peers.items():
            state = peer.get('state', 'Unknown')
            
            tags = {
                'hostname': hostname,
                'peer_name': peer_name,
                'peer_ip': peer.get('peer-ip'),
                'peer_group': peer.get('peer-group-name'),
                'state': state
            }
            
            fields = {
                'remote_as': peer.get('remote-as'),
                'local_as': peer.get('local-as'),
                'status_time': self.safe_float(peer.get('status-time'), 1),
                'state_up': 1 if state == 'Established' else 0
            }
            
            # Add message statistics if available
            # Try advanced routing format first
            if 'detail' in peer and 'messageStats' in peer['detail']:
                stats = peer['detail']['messageStats']
                fields.update({
                    'messages_sent': stats.get('totalSent'),
                    'messages_received': stats.get('totalRecv'),
                    'updates_sent': stats.get('updatesSent'),
                    'updates_received': stats.get('updatesRecv'),
                    'keepalives_sent': stats.get('keepalivesSent'),
                    'keepalives_received': stats.get('keepalivesRecv'),
                    'notifications_sent': stats.get('notificationsSent'),
                    'notifications_received': stats.get('notificationsRecv')
                })
            # Fallback to legacy routing format (normalized data retains these fields)
            elif 'msg-update-in' in peer or 'msg-total-in' in peer:
                fields.update({
                    'messages_sent': peer.get('msg-total-out'),
                    'messages_received': peer.get('msg-total-in'),
                    'updates_sent': peer.get('msg-update-out'),
                    'updates_received': peer.get('msg-update-in')
                    # Note: legacy format doesn't separate keepalives/notifications
                })
            
            line = InfluxDBLineProtocol.build_line('palo_alto_bgp_peer', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_bgp_path_monitor(self, hostname: str, entries: List[Dict]) -> List[str]:
        """Convert BGP path monitor status (one line per monitored path)."""
        lines = []
        
        for entry in entries:
            pm_status = entry.get('pathmonitor-status', 'Unknown')
            
            tags = {
                'hostname': hostname,
                'destination': entry.get('destination'),
                'nexthop': entry.get('nexthop'),
                'interface': entry.get('interface'),
                'pathmonitor_status': pm_status
            }
            
            fields = {
                'metric': entry.get('metric'),
                'pathmonitor_condition': entry.get('pathmonitor-cond'),
                'path_up': 1 if pm_status == 'Up' else 0
            }
            
            # Add monitor destinations and statuses
            for i in range(10):  # Support up to 10 monitors
                if f'monitordst-{i}' in entry:
                    fields[f'monitor_{i}_destination'] = entry.get(f'monitordst-{i}')
                    fields[f'monitor_{i}_status'] = entry.get(f'monitorstatus-{i}')
                    fields[f'monitor_{i}_interval_count'] = entry.get(f'interval-count-{i}')
                else:
                    break
            
            line = InfluxDBLineProtocol.build_line('palo_alto_bgp_path_monitor', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_routing_table_counts(self, hostname: str, routing_table: Dict) -> List[str]:
        """Convert route counts from routing table (per VRF)."""
        lines = []
        
        for vrf_name, vrf_routes in routing_table.items():
            protocol_counts = defaultdict(int)
            
            # Count routes per protocol
            for prefix, route_list in vrf_routes.items():
                if isinstance(route_list, list):
                    for route in route_list:
                        # Try to get protocol field first (advanced mode)
                        protocol = route.get('protocol')
                        
                        # If no protocol field, derive from flags (legacy mode)
                        if not protocol:
                            flags = route.get('flags', '')
                            if 'B' in flags:
                                protocol = 'bgp'
                            elif 'S' in flags:
                                protocol = 'static'
                            elif 'C' in flags:
                                protocol = 'connected'
                            elif 'O' in flags:
                                protocol = 'ospf'
                            elif 'R' in flags:
                                protocol = 'rip'
                            else:
                                protocol = 'other'
                        
                        # Normalize protocol name: lowercase, strip whitespace, replace spaces with underscores
                        protocol_normalized = str(protocol).lower().strip().replace(' ', '_')
                        protocol_counts[protocol_normalized] += 1
            
            tags = {
                'hostname': hostname,
                'vrf': vrf_name
            }
            
            # Create fields for each protocol
            fields = {}
            for protocol, count in protocol_counts.items():
                fields[f'routes_{protocol}'] = count
            
            fields['routes_total'] = sum(protocol_counts.values())
            
            # Log protocol breakdown in verbose mode
            if self.verbose:
                protocol_summary = ', '.join([f'{p}={c}' for p, c in sorted(protocol_counts.items())])
                self.log(f"Route counts for VRF '{vrf_name}': {protocol_summary}", 'DEBUG')
            
            line = InfluxDBLineProtocol.build_line('palo_alto_routing_table_counts', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_static_routes_count(self, hostname: str, static_routes: Dict) -> Optional[str]:
        """Convert static route count (fallback when routing_table disabled)."""
        total_count = 0
        
        for vrf_name, vrf_routes in static_routes.items():
            for prefix, route_list in vrf_routes.items():
                if isinstance(route_list, list):
                    total_count += len(route_list)
        
        tags = {'hostname': hostname}
        fields = {'static_routes': total_count}
        
        return InfluxDBLineProtocol.build_line('palo_alto_static_routes_count', tags, fields, self.timestamp)
    
    def _convert_bgp_routes_count(self, hostname: str, bgp_routes: Dict) -> Optional[str]:
        """Convert BGP route count (fallback when routing_table disabled)."""
        total_count = 0
        
        for vrf_name, vrf_routes in bgp_routes.items():
            for prefix, route_list in vrf_routes.items():
                if isinstance(route_list, list):
                    total_count += len(route_list)
        
        tags = {'hostname': hostname}
        fields = {'bgp_routes': total_count}
        
        return InfluxDBLineProtocol.build_line('palo_alto_bgp_routes_count', tags, fields, self.timestamp)


class CountersConverter(DataConverter):
    """Converter for global counters module (10 measurements by category)."""
    
    def convert(self, hostname: str, data: Dict[str, Any]) -> List[str]:
        """Convert counters module data to InfluxDB line protocol."""
        lines = []
        
        if 'global_counters' not in data or 'global' not in data['global_counters']:
            return lines
        
        global_data = data['global_counters']['global']
        if 'counters' not in global_data or 'entry' not in global_data['counters']:
            return lines
        
        # Group counters by category
        categories = defaultdict(list)
        for entry in global_data['counters']['entry']:
            category = entry.get('category', 'other')
            categories[category].append(entry)
        
        # Convert each major category
        for category, entries in categories.items():
            # Only create measurements for significant categories
            if len(entries) >= 5:
                line = self._convert_category_counters(hostname, category, entries)
                if line:
                    lines.append(line)
        
        self.stats['lines_generated'] += len(lines)
        return lines
    
    def _convert_category_counters(self, hostname: str, category: str, entries: List[Dict]) -> Optional[str]:
        """Convert counters for a specific category."""
        tags = {'hostname': hostname}
        
        fields = {}
        for entry in entries:
            counter_name = entry.get('name', '')
            if counter_name:
                # Add counter value
                fields[counter_name] = entry.get('value')
                # Add rate if available
                if 'rate' in entry:
                    fields[f'{counter_name}_rate'] = entry.get('rate')
        
        measurement = f'palo_alto_counters_{category}'
        return InfluxDBLineProtocol.build_line(measurement, tags, fields, self.timestamp)


class GlobalProtectConverter(DataConverter):
    """Converter for GlobalProtect module (2 measurements)."""
    
    def convert(self, hostname: str, data: Dict[str, Any]) -> List[str]:
        """Convert GlobalProtect module data to InfluxDB line protocol."""
        lines = []
        
        # 1. Gateway Summary
        if 'gateway_summary' in data and 'entry' in data['gateway_summary']:
            gw_lines = self._convert_gateway_summary(hostname, data['gateway_summary']['entry'])
            lines.extend(gw_lines)
        
        # 2. Portal Summary
        if 'portal_summary' in data and 'entry' in data['portal_summary']:
            portal_lines = self._convert_portal_summary(hostname, data['portal_summary']['entry'])
            lines.extend(portal_lines)
        
        self.stats['lines_generated'] += len(lines)
        return lines
    
    def _convert_gateway_summary(self, hostname: str, entries: List[Dict]) -> List[str]:
        """Convert GlobalProtect gateway statistics."""
        lines = []
        
        for gateway in entries:
            tags = {
                'hostname': hostname,
                'gateway_name': gateway.get('name')
            }
            
            fields = {
                'current_users': gateway.get('CurrentUsers', 0),
                'previous_users': gateway.get('PreviousUsers', 0),
                'max_concurrent_tunnels': gateway.get('gateway_max_concurrent_tunnel'),
                'successful_ipsec_connections': gateway.get('gateway_successful_ip_sec_connections'),
                'total_tunnel_count': gateway.get('record_gateway_tunnel_count')
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_gp_gateway', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_portal_summary(self, hostname: str, entries: List[Dict]) -> List[str]:
        """Convert GlobalProtect portal statistics."""
        lines = []
        
        for portal in entries:
            tags = {
                'hostname': hostname,
                'portal_name': portal.get('name')
            }
            
            fields = {
                'successful_connections': portal.get('successful_connections', 0)
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_gp_portal', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines


class VPNConverter(DataConverter):
    """Converter for VPN tunnels module (5 measurements)."""
    
    def convert(self, hostname: str, data: Dict[str, Any]) -> List[str]:
        """Convert VPN module data to InfluxDB line protocol."""
        lines = []
        
        # 1. VPN Flows Summary
        if 'vpn_flows' in data:
            line = self._convert_vpn_flows(hostname, data['vpn_flows'])
            if line:
                lines.append(line)
        
        # 2. IPsec Flow Operational State (from vpn_flows.IPSec.entry)
        if 'vpn_flows' in data and data['vpn_flows'].get('IPSec'):
            flow_lines = self._convert_ipsec_flows(hostname, data['vpn_flows']['IPSec'])
            lines.extend(flow_lines)
        
        # 3. VPN Tunnels (per tunnel configuration from active_tunnels or vpn_tunnels)
        if 'active_tunnels' in data and data['active_tunnels']:
            tunnel_lines = self._convert_vpn_tunnels(hostname, data['active_tunnels'])
            lines.extend(tunnel_lines)
        elif 'vpn_tunnels' in data and data['vpn_tunnels']:
            tunnel_lines = self._convert_vpn_tunnels(hostname, data['vpn_tunnels'])
            lines.extend(tunnel_lines)
        
        # 4. VPN Gateways (per gateway)
        if 'vpn_gateways' in data and data['vpn_gateways']:
            gateway_lines = self._convert_vpn_gateways(hostname, data['vpn_gateways'])
            lines.extend(gateway_lines)
        
        # 5. IPsec Security Associations (per SA with lifetime tracking)
        if 'ipsec_sa' in data and data['ipsec_sa']:
            sa_lines = self._convert_ipsec_sa(hostname, data['ipsec_sa'])
            lines.extend(sa_lines)
        
        self.stats['lines_generated'] += len(lines)
        return lines
    
    def _convert_vpn_flows(self, hostname: str, flows: Dict) -> Optional[str]:
        """Convert VPN flow summary."""
        tags = {'hostname': hostname}
        
        fields = {
            'num_ipsec': flows.get('num_ipsec', 0),
            'num_sslvpn': flows.get('num_sslvpn', 0),
            'total_flows': flows.get('total', 0)
        }
        
        return InfluxDBLineProtocol.build_line('palo_alto_vpn_flows', tags, fields, self.timestamp)
    
    def _convert_ipsec_flows(self, hostname: str, ipsec_data: Dict) -> List[str]:
        """Convert IPsec flow operational state (one line per active flow)."""
        lines = []
        
        # Extract flow entries from nested structure
        flow_entries = []
        if isinstance(ipsec_data, dict) and 'entry' in ipsec_data:
            flow_entries = ipsec_data['entry']
            # Ensure it's a list
            if not isinstance(flow_entries, list):
                flow_entries = [flow_entries]
        
        for flow in flow_entries:
            if not isinstance(flow, dict):
                continue
            
            tags = {
                'hostname': hostname,
                'flow_name': flow.get('name')
            }
            
            fields = {
                'flow_id': self.safe_int(flow.get('id')),
                'gateway_id': self.safe_int(flow.get('gwid')),
                'inner_interface': flow.get('inner-if'),
                'outer_interface': flow.get('outer-if'),
                'state': flow.get('state'),
                'ipsec_mode': flow.get('ipsec-mode'),
                'local_ip': flow.get('localip'),
                'peer_ip': flow.get('peerip'),
                'monitoring': flow.get('mon'),
                'owner': self.safe_int(flow.get('owner')),
                'state_up': 1 if flow.get('state') == 'active' else 0
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_ipsec_flow', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_vpn_tunnels(self, hostname: str, tunnels_data: Dict) -> List[str]:
        """Convert VPN tunnel status (one line per tunnel)."""
        lines = []
        
        # Extract tunnel entries from nested structure
        tunnel_entries = []
        if isinstance(tunnels_data, dict):
            if 'entries' in tunnels_data and tunnels_data['entries']:
                entries = tunnels_data['entries']
                if isinstance(entries, dict) and 'entry' in entries:
                    tunnel_entries = entries['entry']
                    # Ensure it's a list
                    if not isinstance(tunnel_entries, list):
                        tunnel_entries = [tunnel_entries]
        
        for tunnel in tunnel_entries:
            if not isinstance(tunnel, dict):
                continue
            
            tags = {
                'hostname': hostname,
                'tunnel_name': tunnel.get('name'),
                'gateway': tunnel.get('gw')
            }
            
            fields = {
                'tunnel_id': self.safe_int(tunnel.get('id')),
                'protocol': tunnel.get('proto'),
                'mode': tunnel.get('mode'),
                'dh_group': tunnel.get('dh'),
                'encryption': tunnel.get('enc'),
                'hash': tunnel.get('hash'),
                'lifetime': self.safe_int(tunnel.get('life')),
                'kb_limit': self.safe_int(tunnel.get('kb'))
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_vpn_tunnel', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_vpn_gateways(self, hostname: str, gateways_data: Dict) -> List[str]:
        """Convert VPN gateway information (one line per gateway)."""
        lines = []
        
        # Extract gateway entries from nested structure
        gateway_entries = []
        if isinstance(gateways_data, dict):
            if 'entries' in gateways_data and gateways_data['entries']:
                entries = gateways_data['entries']
                if isinstance(entries, dict) and 'entry' in entries:
                    gateway_entries = entries['entry']
                    # Ensure it's a list
                    if not isinstance(gateway_entries, list):
                        gateway_entries = [gateway_entries]
        
        for gateway in gateway_entries:
            if not isinstance(gateway, dict):
                continue
            
            # Prefer v2 (IKEv2) over v1
            ike_version = gateway.get('v2') if gateway.get('v2') else gateway.get('v1')
            
            # Extract peer and local IPs from ID strings
            peer_id = ike_version.get('peer-id', '') if ike_version else ''
            local_id = ike_version.get('local-id', '') if ike_version else ''
            
            # Parse peer IP from format "ip(ipaddr:x.x.x.x)"
            peer_ip = peer_id.split('ipaddr:')[-1].rstrip(')') if 'ipaddr:' in peer_id else peer_id
            local_ip = local_id.split('ipaddr:')[-1].rstrip(')') if 'ipaddr:' in local_id else local_id
            
            tags = {
                'hostname': hostname,
                'gateway_name': gateway.get('name')
            }
            
            fields = {
                'gateway_id': self.safe_int(gateway.get('id')),
                'socket': self.safe_int(gateway.get('sock')),
                'nat_t': self.safe_int(gateway.get('natt')),
                'peer_ip': peer_ip,
                'local_ip': local_ip,
                'ike_version': 2 if gateway.get('v2') else 1,
                'authentication': ike_version.get('auth') if ike_version else None,
                'dh_group': ike_version.get('dh') if ike_version else None,
                'encryption': ike_version.get('enc') if ike_version else None,
                'hash': ike_version.get('hash') if ike_version else None,
                'prf': ike_version.get('prf') if ike_version and 'prf' in ike_version else None,
                'lifetime': self.safe_int(ike_version.get('life')) if ike_version else None
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_vpn_gateway', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines
    
    def _convert_ipsec_sa(self, hostname: str, sa_data: Dict) -> List[str]:
        """Convert IPsec Security Associations (one line per SA with lifetime tracking)."""
        lines = []
        
        # Extract SA entries from nested structure
        sa_entries = []
        if isinstance(sa_data, dict):
            if 'entries' in sa_data and sa_data['entries']:
                entries = sa_data['entries']
                if isinstance(entries, dict) and 'entry' in entries:
                    sa_entries = entries['entry']
                    # Ensure it's a list
                    if not isinstance(sa_entries, list):
                        sa_entries = [sa_entries]
        
        for sa in sa_entries:
            if not isinstance(sa, dict):
                continue
            
            tags = {
                'hostname': hostname,
                'tunnel_name': sa.get('name'),
                'gateway': sa.get('gateway')
            }
            
            # Calculate percentage of lifetime remaining
            lifetime = self.safe_int(sa.get('life'))
            remain = self.safe_int(sa.get('remain'))
            remain_percent = None
            if lifetime and remain and lifetime > 0:
                remain_percent = self.safe_float((remain / lifetime) * 100, 2)
            
            fields = {
                'gateway_id': self.safe_int(sa.get('gwid')),
                'tunnel_id': self.safe_int(sa.get('tid')),
                'remote_ip': sa.get('remote'),
                'protocol': sa.get('proto'),
                'encryption': sa.get('enc'),
                'hash': sa.get('hash'),
                'inbound_spi': self.safe_int(sa.get('i_spi')),
                'outbound_spi': self.safe_int(sa.get('o_spi')),
                'lifetime_seconds': lifetime,
                'remaining_seconds': remain,
                'remaining_percent': remain_percent
            }
            
            line = InfluxDBLineProtocol.build_line('palo_alto_ipsec_sa', tags, fields, self.timestamp)
            if line:
                lines.append(line)
        
        return lines


class PaloAltoInfluxDBConverter:
    """
    Main converter orchestrating all module converters.
    
    Converts pa_query.py all-stats output to InfluxDB line protocol.
    """
    
    def __init__(self, timestamp: Optional[int] = None, verbose: bool = False):
        """
        Initialize the main converter.
        
        Args:
            timestamp: Unix timestamp in nanoseconds. If None, uses current time.
            verbose: Enable verbose logging
        """
        self.timestamp = timestamp or int(datetime.now(timezone.utc).timestamp() * 1e9)
        self.verbose = verbose
        
        # Initialize module converters
        self.system_converter = SystemConverter(self.timestamp, verbose)
        self.environmental_converter = EnvironmentalConverter(self.timestamp, verbose)
        self.interface_converter = InterfaceConverter(self.timestamp, verbose)
        self.routing_converter = RoutingConverter(self.timestamp, verbose)
        self.counters_converter = CountersConverter(self.timestamp, verbose)
        self.gp_converter = GlobalProtectConverter(self.timestamp, verbose)
        self.vpn_converter = VPNConverter(self.timestamp, verbose)
        
        self.total_lines = 0
        self.total_errors = 0
    
    def _normalize_routing_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize legacy routing format to advanced routing format.
        
        This handles both live data collection (already normalized by routing.py)
        and pre-collected JSON data piped from files.
        
        Args:
            data: Complete stats data with routing module
        
        Returns:
            Data with normalized routing structures
        """
        if 'routing' not in data:
            return data
        
        # Process each firewall's routing data
        for firewall_name, fw_data in data['routing'].items():
            if not fw_data.get('success') or 'data' not in fw_data:
                continue
            
            routing_data = fw_data['data']
            routing_mode = routing_data.get('routing_mode', 'unknown')
            
            # Only normalize if in legacy mode
            if routing_mode != 'legacy':
                continue
            
            if self.verbose:
                print(f"[INFO] Normalizing legacy routing data for {firewall_name}", file=sys.stderr)
            
            # Normalize bgp_summary
            if 'bgp_summary' in routing_data:
                bgp_summary = routing_data['bgp_summary']
                if 'entry' in bgp_summary and isinstance(bgp_summary['entry'], dict):
                    entry = bgp_summary['entry']
                    vrf_name = entry.get('@virtual-router', 'default')
                    normalized_entry = {k: v for k, v in entry.items() if not k.startswith('@')}
                    routing_data['bgp_summary'] = {vrf_name: normalized_entry}
                    if self.verbose:
                        print(f"[DEBUG] Normalized bgp_summary: {vrf_name}", file=sys.stderr)
            
            # Normalize bgp_peer_status
            if 'bgp_peer_status' in routing_data:
                bgp_peers = routing_data['bgp_peer_status']
                if 'entry' in bgp_peers:
                    entries = bgp_peers['entry']
                    if not isinstance(entries, list):
                        entries = [entries]
                    
                    normalized = {}
                    for entry in entries:
                        if isinstance(entry, dict):
                            peer_name = entry.get('@peer', entry.get('peer-name', 'unknown'))
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
                    
                    routing_data['bgp_peer_status'] = normalized
                    if self.verbose:
                        print(f"[DEBUG] Normalized bgp_peer_status: {len(normalized)} peers", file=sys.stderr)
            
            # Normalize routing_table, bgp_routes, static_routes
            for collection_name in ['routing_table', 'bgp_routes', 'static_routes']:
                if collection_name in routing_data:
                    routes = routing_data[collection_name]
                    if 'entry' in routes:
                        entries = routes['entry']
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
                        
                        routing_data[collection_name] = vrf_routes
                        if self.verbose:
                            print(f"[DEBUG] Normalized {collection_name}: {len(vrf_routes)} VRFs", file=sys.stderr)
        
        return data
    
    def convert(self, stats_data: Dict[str, Any]) -> List[str]:
        """
        Convert complete stats data to InfluxDB line protocol.
        
        Args:
            stats_data: Complete stats from pa_query.py all-stats
            
        Returns:
            List of InfluxDB line protocol strings
        """
        all_lines = []
        
        # Normalize routing data if needed (handles both live and piped data)
        stats_data = self._normalize_routing_data(stats_data)
        
        # First pass: Build firewall_name -> hostname mapping from system module
        hostname_map = self._build_hostname_map(stats_data)
        
        # Process each module
        modules = [
            ('system', self.system_converter),
            ('interfaces', self.interface_converter),
            ('routing', self.routing_converter),
            ('counters', self.counters_converter),
            ('global_protect', self.gp_converter),
            ('vpn', self.vpn_converter)
        ]
        
        for module_name, converter in modules:
            if module_name not in stats_data:
                if self.verbose:
                    print(f"[WARN] Module '{module_name}' not found in data", file=sys.stderr)
                continue
            
            module_data = stats_data[module_name]
            
            # Process each firewall in the module
            for firewall_name, fw_data in module_data.items():
                if not fw_data.get('success'):
                    if self.verbose:
                        error = fw_data.get('error', 'Unknown error')
                        print(f"[ERROR] {module_name}/{firewall_name}: {error}", file=sys.stderr)
                    self.total_errors += 1
                    continue
                
                try:
                    data = fw_data.get('data', {})
                    
                    # Priority order for hostname:
                    # 1. From result metadata (hostname cache)
                    # 2. From system_info in data (existing _build_hostname_map)
                    # 3. From module data (_hostname field)
                    # 4. Fallback to firewall config name
                    hostname = (
                        fw_data.get('hostname') or  # From cache via result metadata
                        hostname_map.get(firewall_name) or  # From system_info
                        data.get('_hostname') or  # From module-level cache
                        firewall_name  # Fallback
                    )
                    
                    lines = converter.convert(hostname, data)
                    all_lines.extend(lines)
                    
                    # Special case: Environmental data is also in system module
                    if module_name == 'system':
                        env_lines = self.environmental_converter.convert(hostname, data)
                        all_lines.extend(env_lines)
                        if self.verbose and env_lines:
                            print(f"[INFO] {module_name}/{firewall_name} environmental: {len(env_lines)} lines", file=sys.stderr)
                    
                    if self.verbose:
                        source = "cache" if fw_data.get('hostname') else "system_info" if hostname_map.get(firewall_name) else "fallback"
                        print(f"[INFO] {module_name}/{firewall_name} (hostname={hostname} from {source}): {len(lines)} lines", file=sys.stderr)
                
                except Exception as e:
                    if self.verbose:
                        print(f"[ERROR] {module_name}/{firewall_name}: {str(e)}", file=sys.stderr)
                    self.total_errors += 1
        
        self.total_lines = len(all_lines)
        return all_lines
    
    def _build_hostname_map(self, stats_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Build a mapping of firewall_name -> hostname from system module data.
        
        Args:
            stats_data: Complete stats from pa_query.py all-stats
            
        Returns:
            Dictionary mapping firewall config names to actual hostnames
        """
        hostname_map = {}
        
        if 'system' not in stats_data:
            return hostname_map
        
        system_data = stats_data['system']
        
        for firewall_name, fw_data in system_data.items():
            if fw_data.get('success') and 'data' in fw_data:
                data = fw_data['data']
                if 'system_info' in data and 'system' in data['system_info']:
                    hostname = data['system_info']['system'].get('hostname')
                    if hostname:
                        hostname_map[firewall_name] = hostname
                        if self.verbose:
                            print(f"[INFO] Mapped firewall '{firewall_name}' to hostname '{hostname}'", file=sys.stderr)
        
        return hostname_map
    
    def get_stats(self) -> Dict[str, Any]:
        """Get conversion statistics."""
        return {
            'total_lines': self.total_lines,
            'total_errors': self.total_errors,
            'system': self.system_converter.stats,
            'interfaces': self.interface_converter.stats,
            'routing': self.routing_converter.stats,
            'counters': self.counters_converter.stats,
            'globalprotect': self.gp_converter.stats,
            'vpn': self.vpn_converter.stats
        }


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='''Convert Palo Alto firewall statistics to InfluxDB line protocol format.

This converter is specifically designed to process JSON output from:
    pa_query.py -o json all-stats

The expected JSON structure includes modules: system, interfaces, routing, 
counters, global_protect, and vpn. Each module contains firewall data with 
success status and nested statistics.''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # From JSON file (generated by pa_query.py -o json all-stats > stats.json)
  python influxdb_converter.py --input stats.json
  
  # Direct pipe from pa_query.py
  python pa_query.py -o json all-stats | python influxdb_converter.py
  
  # Save to file for batch InfluxDB import
  python influxdb_converter.py --input stats.json --output metrics.txt
  
  # Verbose mode for debugging
  python influxdb_converter.py --input stats.json --verbose
  
  # Pipe directly to InfluxDB write API
  python pa_query.py -o json all-stats | python influxdb_converter.py | \\
    curl -XPOST 'http://localhost:8086/write?db=palo_alto' --data-binary @-

Note: This converter expects the specific JSON structure produced by pa_query.py.
      Using other data sources may result in conversion errors.
        '''
    )
    
    parser.add_argument(
        '--input', '-i',
        type=str,
        help='Input JSON file from pa_query.py all-stats (if not provided, reads from stdin)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output file (if not provided, writes to stdout)'
    )
    
    parser.add_argument(
        '--timestamp', '-t',
        type=int,
        help='Unix timestamp in nanoseconds (default: current time)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging to stderr'
    )
    
    args = parser.parse_args()
    
    # Check if we have input data available
    if not args.input and sys.stdin.isatty():
        # No input file and stdin is a terminal (not piped)
        parser.print_help()
        print("\nError: No input provided. Use --input FILE or pipe JSON data via stdin.", file=sys.stderr)
        sys.exit(1)
    
    # Read input data
    try:
        if args.input:
            with open(args.input, 'r') as f:
                data = json.load(f)
        else:
            data = json.load(sys.stdin)
    except FileNotFoundError:
        print(f"Error: Input file '{args.input}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        if not args.input:
            # If reading from stdin and got JSON error, likely no data was piped
            print("Error: No valid JSON data received from stdin.\n", file=sys.stderr)
            parser.print_help(sys.stderr)
            print("\nProvide JSON input via --input FILE or pipe data from another command.", file=sys.stderr)
        else:
            print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Convert data
    try:
        converter = PaloAltoInfluxDBConverter(
            timestamp=args.timestamp,
            verbose=args.verbose
        )
        
        lines = converter.convert(data)
        
        # Write output
        output_text = '\n'.join(lines)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_text)
                f.write('\n')  # Final newline
            
            if args.verbose:
                stats = converter.get_stats()
                print(f"\n{'='*60}", file=sys.stderr)
                print("Conversion Summary:", file=sys.stderr)
                print(f"{'='*60}", file=sys.stderr)
                print(f"Total lines generated: {stats['total_lines']}", file=sys.stderr)
                print(f"Total errors: {stats['total_errors']}", file=sys.stderr)
                print(f"Output written to: {args.output}", file=sys.stderr)
                print(f"{'='*60}", file=sys.stderr)
        else:
            print(output_text)
    
    except Exception as e:
        print(f"Error during conversion: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()


