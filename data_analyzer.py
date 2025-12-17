#!/usr/bin/env python3
"""
Comprehensive Data Structure Analyzer for Palo Alto Firewall Metrics

This tool analyzes the complete JSON output from pa_query.py all-stats and categorizes 
data into InfluxDB schema components: measurements, tags, and fields.

Analyzes ALL modules:
- System (system_info, resource_usage, disk_usage, ha_status)
- Interfaces (interface_info, interface_counters)
- Routing (bgp_summary, bgp_peer_status, routing_table, bgp_routes, static_routes)
- Counters (global_counters, session_info)
- GlobalProtect (gateway_summary, gateway_statistics, portal_statistics, portal_summary)
- VPN (vpn_flows, vpn_gateways, vpn_tunnels, ipsec_sa, active_tunnels)

Usage:
    # From JSON file
    python data_analyzer.py --input complete_stats.json
    
    # From live query via pipe
    python pa_query.py -o json all-stats | python data_analyzer.py
    
    # Export schema to file
    python data_analyzer.py --input stats.json --export schema.json

Note: This analyzer uses 'hostname' tags throughout the schema proposals.
The actual converter (influxdb_converter.py) extracts the firewall's real hostname
from system data and uses it consistently across all measurements.
"""

import json
import sys
from typing import Dict, Any, List, Tuple
from collections import defaultdict
from pathlib import Path

try:
    from tabulate import tabulate
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Note: Install 'rich' for better formatting: pip install rich")


class InfluxDBSchemaProposal:
    """A proposal for an InfluxDB measurement schema."""
    
    def __init__(self, measurement: str, description: str, category: str):
        self.measurement = measurement
        self.description = description
        self.category = category
        self.tags = {}
        self.fields = {}
        self.cardinality = "low"
        self.update_frequency = "frequently (every collection)"
        self.notes = []
        self.example_values = {}
        self.data_points_per_collection = 1
    
    def add_tag(self, key: str, example_value: Any, description: str = ""):
        """Add a tag (dimensional data for filtering)."""
        self.tags[key] = {
            'example': example_value,
            'type': self._get_data_type(example_value),
            'description': description
        }
    
    def add_field(self, key: str, example_value: Any, unit: str = "", description: str = ""):
        """Add a field (metric data)."""
        self.fields[key] = {
            'example': example_value,
            'type': self._get_data_type(example_value),
            'unit': unit,
            'description': description
        }
    
    def _get_data_type(self, value: Any) -> str:
        """Determine InfluxDB data type."""
        if isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int):
            return "integer"
        elif isinstance(value, float):
            return "float"
        elif isinstance(value, str):
            return "string"
        else:
            return "string"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for export."""
        return {
            'measurement': self.measurement,
            'description': self.description,
            'category': self.category,
            'tags': self.tags,
            'fields': self.fields,
            'cardinality': self.cardinality,
            'update_frequency': self.update_frequency,
            'data_points_per_collection': self.data_points_per_collection,
            'notes': self.notes
        }


class ComprehensiveDataAnalyzer:
    """Comprehensive analyzer for all Palo Alto firewall data modules."""
    
    def __init__(self, data: Dict[str, Any]):
        """Initialize with complete stats data."""
        self.data = self._normalize_routing_data(data)
        self.console = Console() if RICH_AVAILABLE else None
        self.proposals = []
        self.firewall_tag_note = (
            "Note: All measurements use 'hostname' tags "
            "(the firewall's actual hostname from system data) for consistent identification"
        )
    
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
            
            # Normalize bgp_summary
            if 'bgp_summary' in routing_data:
                bgp_summary = routing_data['bgp_summary']
                if 'entry' in bgp_summary and isinstance(bgp_summary['entry'], dict):
                    entry = bgp_summary['entry']
                    vrf_name = entry.get('@virtual-router', 'default')
                    normalized_entry = {k: v for k, v in entry.items() if not k.startswith('@')}
                    routing_data['bgp_summary'] = {vrf_name: normalized_entry}
            
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
        
        return data
    
    # ==================== SYSTEM MODULE ====================
    
    def analyze_system_module(self):
        """Analyze the system module."""
        if 'system' not in self.data:
            return
        
        for firewall_name, fw_data in self.data['system'].items():
            if not fw_data.get('success'):
                continue
            
            data = fw_data['data']
            
            # System Identity
            if 'system_info' in data and data['system_info'] and 'system' in data['system_info']:
                system = data['system_info']['system']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_system_identity',
                    'System identification and static configuration information',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'), 'Device hostname (primary identifier)')
                proposal.add_tag('model', system.get('model'), 'Device model')
                proposal.add_tag('family', system.get('family'), 'Device family')
                proposal.add_tag('serial', system.get('serial'), 'Serial number')
                
                proposal.add_field('sw_version', system.get('sw-version'), '', 'Software version')
                proposal.add_field('vm_cores', system.get('vm-cores'), 'cores', 'Number of VM cores')
                proposal.add_field('vm_mem_mb', round(system.get('vm-mem', 0) / 1024, 2), 'MiB', 'VM memory')
                proposal.add_field('operational_mode', system.get('operational-mode'), '', 'Operational mode')
                proposal.add_field('advanced_routing', system.get('advanced-routing'), '', 'Advanced routing status')
                proposal.add_field('multi_vsys', system.get('multi-vsys'), '', 'Multi-vsys capability status')
                proposal.add_field('ip_address', system.get('ip-address'), '', 'Management IP address')
                proposal.add_field('mac_address', system.get('mac-address'), '', 'Management MAC address')
                proposal.add_field('ipv6_address', system.get('ipv6-address'), '', 'Management IPv6 address')
                
                # Convert yes/no to boolean for display
                is_dhcp = system.get('is-dhcp')
                is_dhcp_bool = True if is_dhcp == 'yes' else False if is_dhcp == 'no' else None
                proposal.add_field('is_dhcp', is_dhcp_bool, '', 'Using DHCP for IPv4')
                
                is_dhcp6 = system.get('is-dhcp6')
                is_dhcp6_bool = True if is_dhcp6 == 'yes' else False if is_dhcp6 == 'no' else None
                proposal.add_field('is_dhcp6', is_dhcp6_bool, '', 'Using DHCP for IPv6')
                
                proposal.update_frequency = 'rarely (on system change)'
                proposal.notes.append('Static system information that rarely changes')
                proposal.notes.append('Network configuration fields (IP, MAC) help with asset tracking')
                self.proposals.append(proposal)
            
            # System Uptime
            if 'system_info' in data and data['system_info'] and 'system' in data['system_info']:
                system = data['system_info']['system']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_system_uptime',
                    'System uptime metrics',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'))
                
                proposal.add_field('uptime_seconds', system.get('_uptime_seconds'), 's', 'Uptime in seconds')
                proposal.add_field('uptime_days', round(system.get('_uptime_seconds', 0) / 86400, 2), 'days', 'Uptime in days')
                
                self.proposals.append(proposal)
            
            # Content Versions
            if 'system_info' in data and data['system_info'] and 'system' in data['system_info']:
                system = data['system_info']['system']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_content_versions',
                    'Content and security package versions',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'))
                
                proposal.add_field('app_version', system.get('app-version'), '', 'Application and threat content version')
                proposal.add_field('av_version', system.get('av-version'), '', 'Anti-virus content version (0 = not installed)')
                proposal.add_field('threat_version', system.get('threat-version'), '', 'Threat prevention content version (0 = not installed)')
                proposal.add_field('wf_private_version', system.get('wf-private-version'), '', 'WildFire private cloud version')
                proposal.add_field('wildfire_version', system.get('wildfire-version'), '', 'WildFire content version')
                proposal.add_field('wildfire_rt', system.get('wildfire-rt'), '', 'WildFire real-time status')
                proposal.add_field('url_filtering_version', system.get('url-filtering-version'), '', 'URL filtering database version')
                proposal.add_field('url_db', system.get('url-db'), '', 'URL database source')
                proposal.add_field('logdb_version', system.get('logdb-version'), '', 'Log database version')
                proposal.add_field('device_dictionary_version', system.get('device-dictionary-version'), '', 'Device dictionary version')
                proposal.add_field('global_protect_client_package_version', system.get('global-protect-client-package-version'), '', 'GlobalProtect client package version')
                
                proposal.update_frequency = 'frequently (with content updates - typically daily/weekly)'
                proposal.notes.append('Critical for security compliance monitoring')
                proposal.notes.append('Alert on outdated content versions')
                proposal.notes.append('Version 0 typically indicates the feature is not licensed or not installed')
                self.proposals.append(proposal)
            
            # MAC Count
            if 'system_info' in data and data['system_info'] and 'system' in data['system_info']:
                system = data['system_info']['system']
                
                # VM firewalls use 'vm-mac-count', hardware firewalls use 'mac_count'
                mac_count = system.get('vm-mac-count') or system.get('mac_count')
                
                if mac_count is not None:
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_mac_count',
                        'MAC address allocation count',
                        'system'
                    )
                    proposal.add_tag('hostname', system.get('hostname'), 'Device hostname')
                    proposal.add_tag('model', system.get('model'), 'Device model')
                    proposal.add_tag('family', system.get('family'), 'Device family')
                    
                    proposal.add_field('mac_count', mac_count, 'addresses', 'Number of MAC addresses allocated to the device')
                    
                    proposal.update_frequency = 'rarely (on system change)'
                    proposal.notes.append('MAC address allocation for the firewall')
                    proposal.notes.append('Hardware firewalls report as "mac_count", VM firewalls as "vm-mac-count"')
                    proposal.notes.append('Useful for capacity planning and licensing tracking')
                    self.proposals.append(proposal)
            
            # CPU Usage
            if 'resource_usage' in data:
                resources = data['resource_usage']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_cpu_usage',
                    'CPU utilization breakdown by type',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'))
                
                proposal.add_field('cpu_user', resources.get('cpu_user'), '%', 'User CPU time')
                proposal.add_field('cpu_system', resources.get('cpu_system'), '%', 'System CPU time')
                proposal.add_field('cpu_nice', resources.get('cpu_nice'), '%', 'Nice CPU time')
                proposal.add_field('cpu_idle', resources.get('cpu_idle'), '%', 'Idle CPU time')
                proposal.add_field('cpu_iowait', resources.get('cpu_iowait'), '%', 'IO wait time')
                proposal.add_field('cpu_hardware_interrupt', resources.get('cpu_hardware_interrupt'), '%', 'Hardware interrupt time')
                proposal.add_field('cpu_software_interrupt', resources.get('cpu_software_interrupt'), '%', 'Software interrupt time')
                proposal.add_field('cpu_steal', resources.get('cpu_steal'), '%', 'Steal time')
                
                # Add computed total
                cpu_total = 100 - resources.get('cpu_idle', 0)
                proposal.add_field('cpu_total_used', round(cpu_total, 2), '%', 'Total CPU used (100 - idle)')
                
                proposal.notes.append('All CPU values are percentages (0-100)')
                proposal.notes.append('cpu_total_used is a computed field for easier graphing')
                self.proposals.append(proposal)
            
            # Memory Usage
            if 'resource_usage' in data:
                resources = data['resource_usage']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_memory_usage',
                    'Memory utilization metrics',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'))
                
                proposal.add_field('memory_total_mib', resources.get('memory_total_mib'), 'MiB', 'Total memory')
                proposal.add_field('memory_free_mib', resources.get('memory_free_mib'), 'MiB', 'Free memory')
                proposal.add_field('memory_used_mib', resources.get('memory_used_mib'), 'MiB', 'Used memory')
                proposal.add_field('memory_buff_cache_mib', resources.get('memory_buff_cache_mib'), 'MiB', 'Buffer/cache memory')
                proposal.add_field('memory_available_mib', resources.get('memory_available_mib'), 'MiB', 'Available memory')
                proposal.add_field('memory_usage_percent', round(resources.get('memory_usage_percent', 0), 2), '%', 'Memory usage percentage')
                
                proposal.notes.append('Memory values in MiB, percentage is 0-100')
                self.proposals.append(proposal)
            
            # Swap Usage
            if 'resource_usage' in data:
                resources = data['resource_usage']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_swap_usage',
                    'Swap space utilization',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'))
                
                proposal.add_field('swap_total_mib', resources.get('swap_total_mib'), 'MiB', 'Total swap')
                proposal.add_field('swap_free_mib', resources.get('swap_free_mib'), 'MiB', 'Free swap')
                proposal.add_field('swap_used_mib', resources.get('swap_used_mib'), 'MiB', 'Used swap')
                proposal.add_field('swap_usage_percent', resources.get('swap_usage_percent'), '%', 'Swap usage percentage')
                
                self.proposals.append(proposal)
            
            # Load Average
            if 'resource_usage' in data:
                resources = data['resource_usage']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_load_average',
                    'System load averages',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'))
                
                proposal.add_field('load_1min', resources.get('load_average_1min'), '', '1 minute load average')
                proposal.add_field('load_5min', resources.get('load_average_5min'), '', '5 minute load average')
                proposal.add_field('load_15min', resources.get('load_average_15min'), '', '15 minute load average')
                
                self.proposals.append(proposal)
            
            # Task Statistics
            if 'resource_usage' in data:
                resources = data['resource_usage']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_task_stats',
                    'Process and task statistics',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'))
                
                proposal.add_field('tasks_total', resources.get('tasks_total'), '', 'Total tasks')
                proposal.add_field('tasks_running', resources.get('tasks_running'), '', 'Running tasks')
                proposal.add_field('tasks_sleeping', resources.get('tasks_sleeping'), '', 'Sleeping tasks')
                proposal.add_field('tasks_stopped', resources.get('tasks_stopped'), '', 'Stopped tasks')
                proposal.add_field('tasks_zombie', resources.get('tasks_zombie'), '', 'Zombie tasks')
                
                self.proposals.append(proposal)
            
            # Disk Usage (per mount point)
            if 'disk_usage' in data:
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_disk_usage',
                    'Disk usage per mount point',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'))
                proposal.add_tag('mount_point', '/', 'Mount point path')
                proposal.add_tag('device', '/dev/root', 'Device name')
                
                # Take first mount as example
                first_mount = next(iter(data['disk_usage'].values()))
                proposal.add_field('use_percent', first_mount.get('use_percent'), '%', 'Disk usage percentage')
                proposal.add_field('size', first_mount.get('size'), '', 'Total size (needs parsing)')
                proposal.add_field('used', first_mount.get('used'), '', 'Used space (needs parsing)')
                proposal.add_field('available', first_mount.get('available'), '', 'Available space (needs parsing)')
                
                proposal.cardinality = 'medium'
                proposal.data_points_per_collection = len(data['disk_usage'])
                proposal.notes.append(f'Multiple data points per collection (one per mount)')
                proposal.notes.append(f'Example has {len(data["disk_usage"])} mount points')
                proposal.notes.append('Size values need parsing from strings (12G, 6.9G, etc.)')
                self.proposals.append(proposal)
            
            # HA Status
            if 'ha_status' in data:
                ha = data['ha_status']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_ha_status',
                    'High Availability configuration and status',
                    'system'
                )
                proposal.add_tag('hostname', system.get('hostname'))
                
                proposal.add_field('enabled', ha.get('enabled'), '', 'HA enabled status')
                
                # Add comprehensive HA fields when enabled
                if ha.get('enabled') == 'yes' and 'group' in ha:
                    group = ha['group']
                    
                    # Core HA State Information
                    proposal.add_field('ha_mode', group.get('mode'), '', 'HA mode (Active-Passive, Active-Active)')
                    
                    if 'local-info' in group:
                        local_info = group['local-info']
                        proposal.add_field('local_state', local_info.get('state'), '', 'Local firewall state (active, passive, suspended)')
                        proposal.add_field('local_state_duration', local_info.get('state-duration'), 's', 'Time in current state (seconds)')
                        proposal.add_field('local_priority', local_info.get('priority'), '', 'Local priority value (higher = preferred active)')
                        proposal.add_field('preempt_flap_cnt', local_info.get('preempt-flap-cnt'), '', 'Preemptive failover count')
                        proposal.add_field('nonfunc_flap_cnt', local_info.get('nonfunc-flap-cnt'), '', 'Non-functional device failover count')
                        proposal.add_field('max_flaps', local_info.get('max-flaps'), '', 'Maximum flaps threshold')
                        
                        # Synchronization Status
                        proposal.add_field('state_sync', local_info.get('state-sync'), '', 'Config sync status (Complete, Incomplete)')
                        proposal.add_field('state_sync_type', local_info.get('state-sync-type'), '', 'Sync type (ethernet, ip)')
                        
                        # Version Compatibility (11 fields)
                        proposal.add_field('dlp_compat', local_info.get('DLP'), '', 'DLP version compatibility (Match, Mismatch)')
                        proposal.add_field('nd_compat', local_info.get('ND'), '', 'Network Discovery version compatibility')
                        proposal.add_field('oc_compat', local_info.get('OC'), '', 'OpenConfig version compatibility')
                        proposal.add_field('build_compat', local_info.get('build-compat'), '', 'Software build compatibility')
                        proposal.add_field('url_compat', local_info.get('url-compat'), '', 'URL filtering compatibility')
                        proposal.add_field('app_compat', local_info.get('app-compat'), '', 'App/threat content compatibility')
                        proposal.add_field('iot_compat', local_info.get('iot-compat'), '', 'IoT content compatibility')
                        proposal.add_field('av_compat', local_info.get('av-compat'), '', 'Antivirus content compatibility')
                        proposal.add_field('threat_compat', local_info.get('threat-compat'), '', 'Threat content compatibility')
                        proposal.add_field('vpnclient_compat', local_info.get('vpnclient-compat'), '', 'VPN client compatibility')
                        proposal.add_field('gpclient_compat', local_info.get('gpclient-compat'), '', 'GlobalProtect client compatibility')
                    
                    if 'peer-info' in group:
                        peer_info = group['peer-info']
                        proposal.add_field('peer_state', peer_info.get('state'), '', 'Peer firewall state')
                        proposal.add_field('peer_state_duration', peer_info.get('state-duration'), 's', 'Peer time in current state')
                        proposal.add_field('peer_priority', peer_info.get('priority'), '', 'Peer priority value')
                        
                        # Connection Health
                        proposal.add_field('peer_conn_status', peer_info.get('conn-status'), '', 'Overall peer connection status (up, down)')
                        if 'conn-ha1' in peer_info:
                            proposal.add_field('peer_conn_ha1_status', peer_info['conn-ha1'].get('conn-status'), '', 'HA1 control link status')
                        if 'conn-ha2' in peer_info:
                            proposal.add_field('peer_conn_ha2_status', peer_info['conn-ha2'].get('conn-status'), '', 'HA2 data link status')
                    
                    # Running sync status
                    proposal.add_field('running_sync', group.get('running-sync'), '', 'Running config sync status (synchronized, not synchronized)')
                    proposal.add_field('running_sync_enabled', group.get('running-sync-enabled'), '', 'Running config sync enabled')
                
                proposal.update_frequency = 'frequently (every collection)'
                proposal.notes.append('Limited data when HA is disabled (only "enabled" field)')
                proposal.notes.append('Comprehensive metrics when HA is enabled')
                proposal.notes.append('Critical for monitoring HA health, failovers, and configuration sync')
                proposal.notes.append('Alert on state changes, sync failures, or version mismatches')
                self.proposals.append(proposal)
            
            # CPU Dataplane Tasks
            if 'extended_cpu' in data:
                extended_cpu = data['extended_cpu']
                
                # Navigate to resource monitor data
                resource_monitor = extended_cpu.get('resource-monitor', {})
                data_processors = resource_monitor.get('data-processors', resource_monitor)
                dp0 = data_processors.get('dp0', {})
                second_data = dp0.get('second', {})
                
                if second_data:
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_cpu_dataplane_tasks',
                        'Dataplane task CPU utilization and resource utilization',
                        'system'
                    )
                    proposal.add_tag('hostname', system.get('hostname'))
                    proposal.add_tag('dp_id', 'dp0', 'Dataplane processor ID')
                    
                    # Task CPU percentages
                    if 'task' in second_data and second_data['task']:
                        task_data = second_data['task']
                        proposal.add_field('task_flow_lookup', task_data.get('flow_lookup'), '%', 'Flow lookup task CPU')
                        proposal.add_field('task_flow_fastpath', task_data.get('flow_fastpath'), '%', 'Flow fastpath task CPU')
                        proposal.add_field('task_flow_slowpath', task_data.get('flow_slowpath'), '%', 'Flow slowpath task CPU')
                        proposal.add_field('task_flow_forwarding', task_data.get('flow_forwarding'), '%', 'Flow forwarding task CPU')
                        proposal.add_field('task_flow_mgmt', task_data.get('flow_mgmt'), '%', 'Flow management task CPU')
                        proposal.add_field('task_flow_ctrl', task_data.get('flow_ctrl'), '%', 'Flow control task CPU')
                        proposal.add_field('task_nac_result', task_data.get('nac_result'), '%', 'NAC result task CPU')
                        proposal.add_field('task_flow_np', task_data.get('flow_np'), '%', 'Flow network processor task CPU')
                        proposal.add_field('task_dfa_result', task_data.get('dfa_result'), '%', 'DFA result task CPU')
                        proposal.add_field('task_module_internal', task_data.get('module_internal'), '%', 'Module internal task CPU')
                        proposal.add_field('task_aho_result', task_data.get('aho_result'), '%', 'Aho-Corasick result task CPU')
                        proposal.add_field('task_zip_result', task_data.get('zip_result'), '%', 'Compression result task CPU')
                        proposal.add_field('task_pktlog_forwarding', task_data.get('pktlog_forwarding'), '%', 'Packet log forwarding task CPU')
                        proposal.add_field('task_send_out', task_data.get('send_out'), '%', 'Send out task CPU')
                        proposal.add_field('task_flow_host', task_data.get('flow_host'), '%', 'Flow host task CPU')
                        proposal.add_field('task_send_host', task_data.get('send_host'), '%', 'Send host task CPU')
                        proposal.add_field('task_fpga_result', task_data.get('fpga_result'), '%', 'FPGA result task CPU')
                    
                    # Resource utilization (averaged over 60 seconds)
                    if 'resource-utilization' in second_data:
                        proposal.add_field('resource_session_avg', 0, '%', 'Session resource utilization (60s avg)')
                        proposal.add_field('resource_packet_buffer_avg', 0, '%', 'Packet buffer utilization (60s avg)')
                        proposal.add_field('resource_packet_descriptor_avg', 0, '%', 'Packet descriptor utilization (60s avg)')
                        proposal.add_field('resource_sw_tags_descriptor_avg', 0, '%', 'SW tags descriptor utilization (60s avg)')
                    
                    # CPU core count
                    if 'cpu-load-average' in second_data:
                        cpu_load = second_data['cpu-load-average']
                        if 'entry' in cpu_load:
                            entries = cpu_load['entry']
                            if not isinstance(entries, list):
                                entries = [entries]
                            proposal.add_field('cpu_cores', len(entries), 'cores', 'Number of dataplane CPU cores')
                    
                    proposal.update_frequency = 'frequently (every collection)'
                    proposal.cardinality = 'low'
                    proposal.data_points_per_collection = 1
                    proposal.notes.append('Task CPU percentages are instantaneous (current second)')
                    proposal.notes.append('Resource utilization values are averaged over 60 seconds')
                    proposal.notes.append('Provides detailed visibility into dataplane processing tasks')
                    proposal.notes.append('Alert on high task CPU (>80%) or resource exhaustion (>85%)')
                    self.proposals.append(proposal)
            
            # CPU Dataplane Cores (per-core metrics)
            if 'extended_cpu' in data:
                extended_cpu = data['extended_cpu']
                
                # Navigate to resource monitor data
                resource_monitor = extended_cpu.get('resource-monitor', {})
                data_processors = resource_monitor.get('data-processors', resource_monitor)
                dp0 = data_processors.get('dp0', {})
                second_data = dp0.get('second', {})
                
                if 'cpu-load-average' in second_data:
                    cpu_load = second_data['cpu-load-average']
                    if 'entry' in cpu_load:
                        entries = cpu_load['entry']
                        if not isinstance(entries, list):
                            entries = [entries]
                        
                        # Use first core as example
                        first_core = entries[0] if entries else {}
                        
                        proposal = InfluxDBSchemaProposal(
                            'palo_alto_cpu_dataplane_cores',
                            'Per-core dataplane CPU utilization',
                            'system'
                        )
                        proposal.add_tag('hostname', system.get('hostname'))
                        proposal.add_tag('dp_id', 'dp0', 'Dataplane processor ID')
                        proposal.add_tag('core_id', str(first_core.get('coreid', 0)), 'Core ID')
                        
                        proposal.add_field('cpu_utilization_avg', 0, '%', 'Average CPU utilization over 60 seconds')
                        
                        proposal.update_frequency = 'frequently (every collection)'
                        proposal.cardinality = 'medium'
                        proposal.data_points_per_collection = len(entries)
                        proposal.notes.append(f'One data point per dataplane core ({len(entries)} cores detected)')
                        proposal.notes.append('CPU utilization is averaged over 60 seconds')
                        proposal.notes.append('Useful for detecting core imbalance or hot cores')
                        proposal.notes.append('Alert on individual core >90% or imbalance >50% between cores')
                        self.proposals.append(proposal)
    
    # ==================== ENVIRONMENTAL MODULE ====================
    
    def analyze_environmental_module(self):
        """Analyze the environmental module (hardware firewalls only)."""
        if 'system' not in self.data:
            return
        
        for firewall_name, fw_data in self.data['system'].items():
            if not fw_data.get('success'):
                continue
            
            data = fw_data['data']
            
            # Environmental data is only available on hardware firewalls
            if 'environmental' not in data:
                continue
            
            env_data = data['environmental']
            hostname = data.get('system_info', {}).get('system', {}).get('hostname', firewall_name)
            
            # Thermal Sensors
            if 'thermal' in env_data:
                thermal = env_data['thermal']
                # Find first slot with entries to use as example
                for slot_name, slot_data in thermal.items():
                    if 'entry' in slot_data and slot_data['entry']:
                        entries = slot_data['entry']
                        first_entry = entries[0]
                        
                        proposal = InfluxDBSchemaProposal(
                            'palo_alto_env_thermal',
                            'Thermal sensor temperature readings',
                            'environmental'
                        )
                        proposal.add_tag('hostname', hostname, 'Device hostname')
                        proposal.add_tag('slot', first_entry.get('slot'), 'Hardware slot number')
                        proposal.add_tag('description', first_entry.get('description'), 'Sensor description/location')
                        
                        proposal.add_field('temperature_c', first_entry.get('DegreesC'), '°C', 'Current temperature')
                        proposal.add_field('min_temp_c', first_entry.get('min'), '°C', 'Minimum threshold')
                        proposal.add_field('max_temp_c', first_entry.get('max'), '°C', 'Maximum threshold')
                        proposal.add_field('alarm', first_entry.get('alarm'), '', 'Alarm status')
                        
                        proposal.update_frequency = 'frequently (every collection)'
                        proposal.cardinality = 'medium'
                        proposal.data_points_per_collection = len(entries)
                        proposal.notes.append(f'One data point per thermal sensor ({len(entries)} sensors detected)')
                        proposal.notes.append('Hardware firewalls only - not available on VM firewalls')
                        proposal.notes.append('Monitor for temperature approaching max threshold')
                        proposal.notes.append('Alert on alarm=true or temperature >90% of max threshold')
                        self.proposals.append(proposal)
                        break
            
            # Fan Sensors
            if 'fan' in env_data:
                fan = env_data['fan']
                # Find first slot with entries to use as example
                for slot_name, slot_data in fan.items():
                    if 'entry' in slot_data and slot_data['entry']:
                        entries = slot_data['entry']
                        first_entry = entries[0]
                        
                        proposal = InfluxDBSchemaProposal(
                            'palo_alto_env_fan',
                            'Fan speed measurements',
                            'environmental'
                        )
                        proposal.add_tag('hostname', hostname, 'Device hostname')
                        proposal.add_tag('slot', first_entry.get('slot'), 'Hardware slot number')
                        proposal.add_tag('description', first_entry.get('description'), 'Fan description/location')
                        
                        proposal.add_field('rpm', first_entry.get('RPMs'), 'RPM', 'Current fan speed')
                        proposal.add_field('min_rpm', first_entry.get('min'), 'RPM', 'Minimum threshold')
                        proposal.add_field('alarm', first_entry.get('alarm'), '', 'Alarm status')
                        
                        proposal.update_frequency = 'frequently (every collection)'
                        proposal.cardinality = 'medium'
                        proposal.data_points_per_collection = len(entries)
                        proposal.notes.append(f'One data point per fan ({len(entries)} fans detected)')
                        proposal.notes.append('Hardware firewalls only - not available on VM firewalls')
                        proposal.notes.append('Monitor for RPM falling below minimum threshold')
                        proposal.notes.append('Alert on alarm=true or RPM below minimum')
                        self.proposals.append(proposal)
                        break
            
            # Power/Voltage Sensors
            if 'power' in env_data:
                power = env_data['power']
                # Find first slot with entries to use as example
                for slot_name, slot_data in power.items():
                    if 'entry' in slot_data and slot_data['entry']:
                        entries = slot_data['entry']
                        first_entry = entries[0]
                        
                        proposal = InfluxDBSchemaProposal(
                            'palo_alto_env_power',
                            'Voltage sensor readings',
                            'environmental'
                        )
                        proposal.add_tag('hostname', hostname, 'Device hostname')
                        proposal.add_tag('slot', first_entry.get('slot'), 'Hardware slot number')
                        proposal.add_tag('description', first_entry.get('description'), 'Voltage sensor description')
                        
                        proposal.add_field('volts', first_entry.get('Volts'), 'V', 'Current voltage')
                        proposal.add_field('min_volts', first_entry.get('min'), 'V', 'Minimum threshold')
                        proposal.add_field('max_volts', first_entry.get('max'), 'V', 'Maximum threshold')
                        proposal.add_field('alarm', first_entry.get('alarm'), '', 'Alarm status')
                        
                        proposal.update_frequency = 'frequently (every collection)'
                        proposal.cardinality = 'medium'
                        proposal.data_points_per_collection = len(entries)
                        proposal.notes.append(f'One data point per voltage sensor ({len(entries)} sensors detected)')
                        proposal.notes.append('Hardware firewalls only - not available on VM firewalls')
                        proposal.notes.append('Monitor for voltage outside min/max range')
                        proposal.notes.append('Alert on alarm=true or voltage out of range')
                        self.proposals.append(proposal)
                        break
            
            # Power Supply Status
            if 'power-supply' in env_data:
                ps = env_data['power-supply']
                # Find first slot with entries to use as example
                for slot_name, slot_data in ps.items():
                    if 'entry' in slot_data and slot_data['entry']:
                        entries = slot_data['entry']
                        first_entry = entries[0]
                        
                        proposal = InfluxDBSchemaProposal(
                            'palo_alto_env_power_supply',
                            'Power supply status and presence',
                            'environmental'
                        )
                        proposal.add_tag('hostname', hostname, 'Device hostname')
                        proposal.add_tag('slot', first_entry.get('slot'), 'Hardware slot number')
                        proposal.add_tag('description', first_entry.get('description'), 'Power supply description')
                        
                        proposal.add_field('inserted', first_entry.get('Inserted'), '', 'Power supply inserted/present')
                        proposal.add_field('min_required', first_entry.get('min'), '', 'Minimum required status')
                        proposal.add_field('alarm', first_entry.get('alarm'), '', 'Alarm status')
                        
                        proposal.update_frequency = 'frequently (every collection)'
                        proposal.cardinality = 'low'
                        proposal.data_points_per_collection = len(entries)
                        proposal.notes.append(f'One data point per power supply ({len(entries)} supplies detected)')
                        proposal.notes.append('Hardware firewalls only - not available on VM firewalls')
                        proposal.notes.append('Monitor for power supply removal or failure')
                        proposal.notes.append('Alert on alarm=true or inserted=false')
                        self.proposals.append(proposal)
                        break
    
    # ==================== INTERFACE MODULE ====================
    
    def analyze_interface_module(self):
        """Analyze the interface module."""
        if 'interfaces' not in self.data:
            return
        
        for firewall_name, fw_data in self.data['interfaces'].items():
            if not fw_data.get('success'):
                continue
            
            data = fw_data['data']
            
            # Interface Info
            if 'interface_info' in data and data['interface_info'] and 'hw' in data['interface_info']:
                hw = data['interface_info']['hw']
                if 'entry' in hw and hw['entry']:
                    first_int = hw['entry'][0]
                    
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_interface_info',
                        'Interface hardware information and status',
                        'interfaces'
                    )
                    # Get hostname from system data if available
                    hostname = None
                    if firewall_name in self.data.get('system', {}):
                        sys_data = self.data['system'][firewall_name]
                        if sys_data.get('success') and 'system_info' in sys_data.get('data', {}):
                            hostname = sys_data['data']['system_info'].get('system', {}).get('hostname', firewall_name)
                    proposal.add_tag('hostname', hostname or firewall_name)
                    proposal.add_tag('interface', first_int.get('name'), 'Interface name')
                    proposal.add_tag('type', str(first_int.get('type')), 'Interface type')
                    
                    proposal.add_field('state', first_int.get('state'), '', 'Interface state (up/down)')
                    proposal.add_field('speed', first_int.get('speed'), 'Mbps', 'Interface speed')
                    proposal.add_field('duplex', first_int.get('duplex'), '', 'Duplex mode')
                    proposal.add_field('mac', first_int.get('mac'), '', 'MAC address')
                    proposal.add_field('mode', first_int.get('mode'), '', 'Interface mode')
                    proposal.add_field('fec', first_int.get('fec'), '', 'FEC status')
                    
                    proposal.cardinality = 'medium'
                    proposal.data_points_per_collection = len(hw['entry'])
                    proposal.notes.append(f'One data point per physical interface ({len(hw["entry"])} interfaces)')
                    self.proposals.append(proposal)
            
            # Interface Logical Info (ifnet)
            if 'interface_info' in data and data['interface_info'] and 'ifnet' in data['interface_info']:
                ifnet = data['interface_info']['ifnet']
                if 'entry' in ifnet and ifnet['entry']:
                    first_int = ifnet['entry'][0]
                    
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_interface_logical',
                        'Interface logical configuration (zones, IPs, routing)',
                        'interfaces'
                    )
                    # Get hostname from system data if available
                    hostname = None
                    if firewall_name in self.data.get('system', {}):
                        sys_data = self.data['system'][firewall_name]
                        if sys_data.get('success') and 'system_info' in sys_data.get('data', {}):
                            hostname = sys_data['data']['system_info'].get('system', {}).get('hostname', firewall_name)
                    proposal.add_tag('hostname', hostname or firewall_name)
                    proposal.add_tag('interface', first_int.get('name'), 'Interface name')
                    proposal.add_tag('zone', first_int.get('zone'), 'Security zone')
                    proposal.add_tag('vsys', str(first_int.get('vsys')), 'Virtual system')
                    
                    proposal.add_field('ip', first_int.get('ip'), '', 'IP address/mask')
                    proposal.add_field('fwd', first_int.get('fwd'), '', 'Forwarding (routing) info')
                    proposal.add_field('tag', first_int.get('tag'), '', 'VLAN tag')
                    
                    proposal.cardinality = 'medium'
                    proposal.data_points_per_collection = len(ifnet['entry'])
                    proposal.notes.append(f'Logical interface configuration')
                    self.proposals.append(proposal)
            
            # Interface Hardware Counters
            if 'interface_counters' in data and data['interface_counters'] and 'hw' in data['interface_counters']:
                hw = data['interface_counters']['hw']
                if 'entry' in hw and hw['entry']:
                    first_int = hw['entry'][0]
                    port = first_int.get('port', {})
                    
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_interface_counters_hw',
                        'Interface hardware/port traffic counters (physical layer)',
                        'interfaces'
                    )
                    # Get hostname from system data if available
                    hostname = None
                    if firewall_name in self.data.get('system', {}):
                        sys_data = self.data['system'][firewall_name]
                        if sys_data.get('success') and 'system_info' in sys_data.get('data', {}):
                            hostname = sys_data['data']['system_info'].get('system', {}).get('hostname', firewall_name)
                    proposal.add_tag('hostname', hostname or firewall_name)
                    proposal.add_tag('interface', first_int.get('name'), 'Interface name')
                    
                    # Port-level RX counters
                    proposal.add_field('rx_bytes', port.get('rx-bytes'), 'bytes', 'Received bytes (port level)')
                    proposal.add_field('rx_unicast', port.get('rx-unicast'), 'packets', 'Received unicast packets')
                    proposal.add_field('rx_multicast', port.get('rx-multicast'), 'packets', 'Received multicast packets')
                    proposal.add_field('rx_broadcast', port.get('rx-broadcast'), 'packets', 'Received broadcast packets')
                    proposal.add_field('rx_error', port.get('rx-error'), 'packets', 'Receive errors')
                    proposal.add_field('rx_discards', port.get('rx-discards'), 'packets', 'Receive discards')
                    
                    # Port-level TX counters
                    proposal.add_field('tx_bytes', port.get('tx-bytes'), 'bytes', 'Transmitted bytes (port level)')
                    proposal.add_field('tx_unicast', port.get('tx-unicast'), 'packets', 'Transmitted unicast packets')
                    proposal.add_field('tx_multicast', port.get('tx-multicast'), 'packets', 'Transmitted multicast packets')
                    proposal.add_field('tx_broadcast', port.get('tx-broadcast'), 'packets', 'Transmitted broadcast packets')
                    proposal.add_field('tx_error', port.get('tx-error'), 'packets', 'Transmit errors')
                    proposal.add_field('tx_discards', port.get('tx-discards'), 'packets', 'Transmit discards')
                    
                    proposal.add_field('link_down_count', port.get('link-down'), '', 'Link down count')
                    
                    # Interface-level counters
                    proposal.add_field('ibytes', first_int.get('ibytes'), 'bytes', 'Input bytes')
                    proposal.add_field('obytes', first_int.get('obytes'), 'bytes', 'Output bytes')
                    proposal.add_field('ipackets', first_int.get('ipackets'), 'packets', 'Input packets')
                    proposal.add_field('opackets', first_int.get('opackets'), 'packets', 'Output packets')
                    proposal.add_field('ierrors', first_int.get('ierrors'), 'packets', 'Input errors')
                    proposal.add_field('idrops', first_int.get('idrops'), 'packets', 'Input drops')
                    
                    proposal.cardinality = 'medium'
                    proposal.data_points_per_collection = len(hw['entry'])
                    proposal.notes.append('Physical port statistics for network performance monitoring')
                    proposal.notes.append('Counter values are cumulative (use derivative in Grafana)')
                    proposal.notes.append('One data point per physical interface')
                    self.proposals.append(proposal)
            
            # Interface Logical Counters
            if 'interface_counters' in data and data['interface_counters'] and 'ifnet' in data['interface_counters']:
                ifnet = data['interface_counters']['ifnet']
                if 'ifnet' in ifnet and 'entry' in ifnet['ifnet']:
                    entries = ifnet['ifnet']['entry']
                    if entries:
                        first_int = entries[0]
                        
                        proposal = InfluxDBSchemaProposal(
                            'palo_alto_interface_counters_logical',
                            'Interface logical/firewall-level counters (security processing)',
                            'interfaces'
                        )
                        # Get hostname from system data if available
                        hostname = None
                        if firewall_name in self.data.get('system', {}):
                            sys_data = self.data['system'][firewall_name]
                            if sys_data.get('success') and 'system_info' in sys_data.get('data', {}):
                                hostname = sys_data['data']['system_info'].get('system', {}).get('hostname', firewall_name)
                        proposal.add_tag('hostname', hostname or firewall_name)
                        proposal.add_tag('interface', first_int.get('name'), 'Interface name')
                        
                        # Basic traffic counters
                        proposal.add_field('ibytes', first_int.get('ibytes'), 'bytes', 'Input bytes (firewall level)')
                        proposal.add_field('obytes', first_int.get('obytes'), 'bytes', 'Output bytes (firewall level)')
                        proposal.add_field('ipackets', first_int.get('ipackets'), 'packets', 'Input packets')
                        proposal.add_field('opackets', first_int.get('opackets'), 'packets', 'Output packets')
                        proposal.add_field('ierrors', first_int.get('ierrors'), 'packets', 'Input errors')
                        proposal.add_field('idrops', first_int.get('idrops'), 'packets', 'Input drops')
                        
                        # Firewall processing counters
                        proposal.add_field('flowstate', first_int.get('flowstate'), 'packets', 'Flow state drops')
                        proposal.add_field('ifwderrors', first_int.get('ifwderrors'), 'packets', 'Forwarding errors')
                        
                        # Routing/forwarding drops
                        proposal.add_field('noroute', first_int.get('noroute'), 'packets', 'No route drops')
                        proposal.add_field('noarp', first_int.get('noarp'), 'packets', 'No ARP entry drops')
                        proposal.add_field('noneigh', first_int.get('noneigh'), 'packets', 'No neighbor drops')
                        proposal.add_field('neighpend', first_int.get('neighpend'), 'packets', 'Neighbor pending drops')
                        proposal.add_field('nomac', first_int.get('nomac'), 'packets', 'No MAC drops')
                        
                        # Security drops
                        proposal.add_field('zonechange', first_int.get('zonechange'), 'packets', 'Zone change drops')
                        proposal.add_field('land', first_int.get('land'), 'packets', 'LAND attack drops')
                        proposal.add_field('pod', first_int.get('pod'), 'packets', 'Ping of death drops')
                        proposal.add_field('teardrop', first_int.get('teardrop'), 'packets', 'Teardrop attack drops')
                        proposal.add_field('ipspoof', first_int.get('ipspoof'), 'packets', 'IP spoofing drops')
                        proposal.add_field('macspoof', first_int.get('macspoof'), 'packets', 'MAC spoofing drops')
                        proposal.add_field('icmp_frag', first_int.get('icmp_frag'), 'packets', 'ICMP fragment drops')
                        
                        # Encapsulation
                        proposal.add_field('l2_encap', first_int.get('l2_encap'), 'packets', 'L2 encapsulation')
                        proposal.add_field('l2_decap', first_int.get('l2_decap'), 'packets', 'L2 decapsulation')
                        
                        # Connection counters
                        proposal.add_field('tcp_conn', first_int.get('tcp_conn'), 'connections', 'TCP connections')
                        proposal.add_field('udp_conn', first_int.get('udp_conn'), 'connections', 'UDP connections')
                        proposal.add_field('sctp_conn', first_int.get('sctp_conn'), 'connections', 'SCTP connections')
                        proposal.add_field('other_conn', first_int.get('other_conn'), 'connections', 'Other connections')
                        
                        proposal.cardinality = 'medium'
                        proposal.data_points_per_collection = len(entries)
                        proposal.notes.append('Firewall/security processing statistics')
                        proposal.notes.append('Includes logical interfaces (subinterfaces like tunnel.10)')
                        proposal.notes.append('Critical for troubleshooting security policy drops and routing issues')
                        proposal.notes.append('Counter values are cumulative (use derivative in Grafana)')
                        self.proposals.append(proposal)
    
    # ==================== ROUTING MODULE ====================
    
    def analyze_routing_module(self):
        """Analyze the routing module."""
        if 'routing' not in self.data:
            return
        
        for firewall_name, fw_data in self.data['routing'].items():
            if not fw_data.get('success'):
                continue
            
            data = fw_data['data']
            
            # BGP Summary (only if operational statistics are present, not just config)
            if 'bgp_summary' in data:
                summary = data['bgp_summary']
                # Check if this is operational data (has stats) vs config data (per-VRF settings)
                # Operational data has: total_peers, peers_established, peers_down, total_prefixes
                # Config data has: router-id, local-as, graceful-restart (per VRF)
                has_operational_stats = (
                    'total_peers' in summary or 
                    'peers_established' in summary or
                    isinstance(summary, dict) and not any(isinstance(v, dict) for v in summary.values())
                )
                
                if has_operational_stats:
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_bgp_summary',
                        'BGP routing protocol summary (operational statistics)',
                        'routing'
                    )
                    # Get hostname from system data if available  
                    hostname = firewall_name
                    if firewall_name in self.data.get('system', {}):
                        sys_data = self.data['system'][firewall_name]
                        if sys_data.get('success') and 'system_info' in sys_data.get('data', {}):
                            hostname = sys_data['data']['system_info'].get('system', {}).get('hostname', firewall_name)
                    proposal.add_tag('hostname', hostname)
                    proposal.add_tag('router_id', summary.get('router_id'), 'BGP router ID')
                    proposal.add_tag('local_as', str(summary.get('local_as')), 'Local AS number')
                    
                    proposal.add_field('total_peers', summary.get('total_peers'), '', 'Total BGP peers')
                    proposal.add_field('peers_established', summary.get('peers_established'), '', 'Established peers')
                    proposal.add_field('peers_down', summary.get('peers_down'), '', 'Down peers')
                    proposal.add_field('total_prefixes', summary.get('total_prefixes'), '', 'Total prefixes received')
                    
                    proposal.notes.append('High-level BGP operational status')
                    proposal.notes.append('Note: This is different from per-VRF BGP configuration')
                    self.proposals.append(proposal)
            
            # BGP Peer Status (per peer)
            if 'bgp_peer_status' in data and data['bgp_peer_status']:
                first_peer_name = next(iter(data['bgp_peer_status']))
                first_peer = data['bgp_peer_status'][first_peer_name]
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_bgp_peer',
                    'BGP peer status and statistics',
                    'routing'
                )
                proposal.add_tag('hostname', firewall_name)
                proposal.add_tag('peer_name', first_peer_name, 'BGP peer name')
                proposal.add_tag('peer_ip', first_peer.get('peer-ip'), 'Peer IP address')
                proposal.add_tag('peer_group', first_peer.get('peer-group-name'), 'Peer group name')
                proposal.add_tag('state', first_peer.get('state'), 'BGP session state')
                
                proposal.add_field('remote_as', first_peer.get('remote-as'), '', 'Remote AS number')
                proposal.add_field('local_as', first_peer.get('local-as'), '', 'Local AS number')
                proposal.add_field('status_time', first_peer.get('status-time'), 's', 'Time in current state')
                proposal.add_field('state_up', 1 if first_peer.get('state') == 'Established' else 0, 'boolean', 'Peer is up')
                
                # Message statistics if available
                if 'detail' in first_peer and 'messageStats' in first_peer['detail']:
                    stats = first_peer['detail']['messageStats']
                    proposal.add_field('messages_sent', stats.get('totalSent'), '', 'Total messages sent')
                    proposal.add_field('messages_received', stats.get('totalRecv'), '', 'Total messages received')
                    proposal.add_field('updates_sent', stats.get('updatesSent'), '', 'Update messages sent')
                    proposal.add_field('updates_received', stats.get('updatesRecv'), '', 'Update messages received')
                    proposal.add_field('keepalives_sent', stats.get('keepalivesSent'), '', 'Keepalives sent')
                    proposal.add_field('keepalives_received', stats.get('keepalivesRecv'), '', 'Keepalives received')
                    proposal.add_field('notifications_sent', stats.get('notificationsSent'), '', 'Notifications sent')
                    proposal.add_field('notifications_received', stats.get('notificationsRecv'), '', 'Notifications received')
                
                proposal.cardinality = 'medium'
                proposal.data_points_per_collection = len(data['bgp_peer_status'])
                proposal.notes.append(f'One data point per BGP peer ({len(data["bgp_peer_status"])} peers)')
                proposal.notes.append('Critical for BGP monitoring and alerting')
                proposal.notes.append('state_up field makes it easy to alert on peer down')
                self.proposals.append(proposal)
            
            # BGP Path Monitor (per monitored destination)
            if 'bgp_path_monitor' in data and data['bgp_path_monitor'] and 'entry' in data['bgp_path_monitor']:
                entries = data['bgp_path_monitor']['entry']
                if entries:
                    first_entry = entries[0]
                    
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_bgp_path_monitor',
                        'BGP path monitoring status per destination',
                        'routing'
                    )
                    proposal.add_tag('hostname', firewall_name)
                    proposal.add_tag('destination', first_entry.get('destination'), 'Monitored destination prefix')
                    proposal.add_tag('nexthop', first_entry.get('nexthop'), 'Next hop')
                    proposal.add_tag('interface', first_entry.get('interface'), 'Egress interface')
                    proposal.add_tag('pathmonitor_status', first_entry.get('pathmonitor-status'), 'Path monitor status (Up/Down)')
                    
                    proposal.add_field('metric', first_entry.get('metric'), '', 'Route metric')
                    proposal.add_field('pathmonitor_condition', first_entry.get('pathmonitor-cond'), '', 'Monitor condition (All/Any)')
                    proposal.add_field('path_up', 1 if first_entry.get('pathmonitor-status') == 'Up' else 0, 'boolean', 'Path is up')
                    
                    # Monitor destination statuses (can have multiple monitors per path)
                    monitor_count = 0
                    for i in range(10):  # Check up to 10 possible monitors
                        if f'monitordst-{i}' in first_entry:
                            monitor_count += 1
                            proposal.add_field(f'monitor_{i}_destination', first_entry.get(f'monitordst-{i}'), '', f'Monitor destination {i}')
                            proposal.add_field(f'monitor_{i}_status', first_entry.get(f'monitorstatus-{i}'), '', f'Monitor {i} status')
                            proposal.add_field(f'monitor_{i}_interval_count', first_entry.get(f'interval-count-{i}'), '', f'Monitor {i} success/total')
                        else:
                            break
                    
                    proposal.cardinality = 'medium'
                    proposal.data_points_per_collection = len(entries)
                    proposal.notes.append(f'One data point per monitored path ({len(entries)} paths)')
                    proposal.notes.append('Critical for monitoring route failover capability')
                    proposal.notes.append('path_up field makes it easy to alert on path down')
                    proposal.notes.append(f'Example shows {monitor_count} health check monitors per path')
                    self.proposals.append(proposal)
            
            # Route Counts from Routing Table (preferred method)
            if 'routing_table' in data and data['routing_table']:
                # Count routes per protocol and per VRF
                protocol_counts = defaultdict(int)
                vrf_counts = {}
                total_routes = 0
                
                for vrf_name, vrf_routes in data['routing_table'].items():
                    vrf_protocol_counts = defaultdict(int)
                    for prefix, route_list in vrf_routes.items():
                        if isinstance(route_list, list):
                            for route in route_list:
                                protocol = route.get('protocol', 'unknown')
                                # Normalize protocol name: lowercase, strip whitespace, replace spaces with underscores
                                protocol_normalized = str(protocol).lower().strip().replace(' ', '_')
                                protocol_counts[protocol_normalized] += 1
                                vrf_protocol_counts[protocol_normalized] += 1
                                total_routes += 1
                    vrf_counts[vrf_name] = dict(vrf_protocol_counts)
                
                # Create ONE measurement proposal showing the first VRF as example
                # This is a single measurement with VRF as a tag, not multiple measurements
                first_vrf_name = next(iter(vrf_counts))
                first_vrf_counts = vrf_counts[first_vrf_name]
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_routing_table_counts',
                    'Route counts per protocol and VRF from routing table',
                    'routing'
                )
                proposal.add_tag('hostname', firewall_name)
                proposal.add_tag('vrf', first_vrf_name, 'Virtual Router / VRF name')
                
                # Add counts per protocol
                for protocol, count in first_vrf_counts.items():
                    proposal.add_field(f'routes_{protocol}', count, 'routes', f'Number of {protocol} routes')
                
                proposal.add_field('routes_total', sum(first_vrf_counts.values()), 'routes', 'Total routes in VRF')
                
                proposal.cardinality = 'low to medium'
                proposal.data_points_per_collection = len(vrf_counts)
                proposal.notes.append(f'One data point per VRF ({len(vrf_counts)} VRFs found: {", ".join(vrf_counts.keys())})')
                proposal.notes.append('Primary source for route counts')
                proposal.notes.append('Protocols found: ' + ', '.join(protocol_counts.keys()))
                proposal.notes.append('Protocol names are normalized: lowercase, no spaces (e.g., "Local" becomes "local")')
                proposal.notes.append('Use for monitoring routing table growth and protocol distribution')
                proposal.notes.append('This is a SINGLE measurement with multiple data points (one per VRF)')
                self.proposals.append(proposal)
                
                # Don't process other firewalls since we're just showing schema
                break
            
            # Fallback: Route Counts from Individual Protocol Modules
            # This is used when routing_table is disabled but individual modules are enabled
            else:
                # Check for static_routes
                if 'static_routes' in data and data['static_routes']:
                    static_count = 0
                    vrf_list = []
                    for vrf_name, vrf_routes in data['static_routes'].items():
                        vrf_list.append(vrf_name)
                        for prefix, route_list in vrf_routes.items():
                            if isinstance(route_list, list):
                                static_count += len(route_list)
                    
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_static_routes_count',
                        'Static route counts (fallback when routing_table disabled)',
                        'routing'
                    )
                    proposal.add_tag('hostname', firewall_name)
                    proposal.add_field('static_routes', static_count, 'routes', 'Number of static routes')
                    
                    proposal.cardinality = 'low'
                    proposal.notes.append('Fallback measurement when routing_table is disabled')
                    proposal.notes.append(f'Covers VRFs: {", ".join(vrf_list)}')
                    self.proposals.append(proposal)
                
                # Check for bgp_routes
                if 'bgp_routes' in data and data['bgp_routes']:
                    bgp_count = 0
                    vrf_list = []
                    for vrf_name, vrf_routes in data['bgp_routes'].items():
                        vrf_list.append(vrf_name)
                        for prefix, route_list in vrf_routes.items():
                            if isinstance(route_list, list):
                                bgp_count += len(route_list)
                    
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_bgp_routes_count',
                        'BGP route counts (fallback when routing_table disabled)',
                        'routing'
                    )
                    proposal.add_tag('hostname', firewall_name)
                    proposal.add_field('bgp_routes', bgp_count, 'routes', 'Number of BGP routes')
                    
                    proposal.cardinality = 'low'
                    proposal.notes.append('Fallback measurement when routing_table is disabled')
                    proposal.notes.append(f'Covers VRFs: {", ".join(vrf_list)}')
                    self.proposals.append(proposal)
    
    # ==================== COUNTERS MODULE ====================
    
    def analyze_counters_module(self):
        """Analyze the global counters module."""
        if 'counters' not in self.data:
            return
        
        for firewall_name, fw_data in self.data['counters'].items():
            if not fw_data.get('success'):
                continue
            
            data = fw_data['data']
            
            # Global Counters
            if 'global_counters' in data and data['global_counters'] and 'global' in data['global_counters']:
                global_data = data['global_counters']['global']
                if global_data and 'counters' in global_data and global_data['counters'] and 'entry' in global_data['counters']:
                    entries = global_data['counters']['entry']
                    
                    # Group counters by category
                    categories = defaultdict(list)
                    for entry in entries:
                        category = entry.get('category', 'other')
                        categories[category].append(entry)
                    
                    # Create proposals for each major category
                    for category, category_entries in categories.items():
                        if len(category_entries) > 5:  # Only create separate measurement for significant categories
                            first_entry = category_entries[0]
                            
                            proposal = InfluxDBSchemaProposal(
                                f'palo_alto_counters_{category}',
                                f'Global {category} counters',
                                'counters'
                            )
                            proposal.add_tag('hostname', firewall_name)
                            
                            # Add sample fields from first few entries
                            for entry in category_entries[:10]:  # Limit to first 10 to avoid clutter
                                counter_name = entry.get('name', '')
                                proposal.add_field(
                                    counter_name,
                                    entry.get('value'),
                                    '',
                                    entry.get('desc', '')
                                )
                                # Also add rate if available
                                if 'rate' in entry:
                                    proposal.add_field(
                                        f'{counter_name}_rate',
                                        entry.get('rate'),
                                        '/s',
                                        f'{entry.get("desc", "")} rate'
                                    )
                            
                            proposal.notes.append(f'{len(category_entries)} counters in this category')
                            proposal.notes.append('Counter values are cumulative')
                            proposal.notes.append('Rate values show current rate per second')
                            self.proposals.append(proposal)
    
    # ==================== GLOBALPROTECT MODULE ====================
    
    def analyze_globalprotect_module(self):
        """Analyze the GlobalProtect module."""
        if 'global_protect' not in self.data:
            return
        
        for firewall_name, fw_data in self.data['global_protect'].items():
            if not fw_data.get('success'):
                continue
            
            data = fw_data['data']
            
            # Gateway Summary
            if 'gateway_summary' in data and data['gateway_summary'] and 'entry' in data['gateway_summary']:
                entries = data['gateway_summary']['entry']
                if entries:
                    first_gw = entries[0]
                    
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_gp_gateway',
                        'GlobalProtect gateway statistics',
                        'globalprotect'
                    )
                    proposal.add_tag('hostname', firewall_name)
                    proposal.add_tag('gateway_name', first_gw.get('name'), 'Gateway name')
                    
                    proposal.add_field('current_users', first_gw.get('CurrentUsers'), '', 'Current connected users')
                    proposal.add_field('previous_users', first_gw.get('PreviousUsers'), '', 'Previous user count')
                    proposal.add_field('max_concurrent_tunnels', first_gw.get('gateway_max_concurrent_tunnel'), '', 'Max concurrent tunnels')
                    proposal.add_field('successful_ipsec_connections', first_gw.get('gateway_successful_ip_sec_connections'), '', 'Successful IPsec connections')
                    proposal.add_field('total_tunnel_count', first_gw.get('record_gateway_tunnel_count'), '', 'Total tunnel count')
                    
                    proposal.cardinality = 'low to medium'
                    proposal.data_points_per_collection = len(entries)
                    proposal.notes.append('One data point per GlobalProtect gateway')
                    self.proposals.append(proposal)
            
            # Portal Summary
            if 'portal_summary' in data and data['portal_summary'] and 'entry' in data['portal_summary']:
                entries = data['portal_summary']['entry']
                if entries:
                    first_portal = entries[0]
                    
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_gp_portal',
                        'GlobalProtect portal statistics',
                        'globalprotect'
                    )
                    proposal.add_tag('hostname', firewall_name)
                    proposal.add_tag('portal_name', first_portal.get('name'), 'Portal name')
                    
                    proposal.add_field('successful_connections', first_portal.get('successful_connections'), '', 'Successful connections')
                    
                    proposal.cardinality = 'low'
                    proposal.data_points_per_collection = len(entries)
                    self.proposals.append(proposal)
    
    # ==================== VPN MODULE ====================
    
    def analyze_vpn_module(self):
        """Analyze the VPN tunnels module."""
        if 'vpn' not in self.data:
            return
        
        for firewall_name, fw_data in self.data['vpn'].items():
            if not fw_data.get('success'):
                continue
            
            data = fw_data['data']
            
            # VPN Flows Summary
            if 'vpn_flows' in data:
                flows = data['vpn_flows']
                
                proposal = InfluxDBSchemaProposal(
                    'palo_alto_vpn_flows',
                    'VPN flow summary statistics',
                    'vpn'
                )
                proposal.add_tag('hostname', firewall_name)
                
                proposal.add_field('num_ipsec', flows.get('num_ipsec'), '', 'Number of IPsec flows')
                proposal.add_field('num_sslvpn', flows.get('num_sslvpn'), '', 'Number of SSL VPN flows')
                proposal.add_field('total_flows', flows.get('total'), '', 'Total VPN flows')
                
                proposal.cardinality = 'low'
                proposal.notes.append('Summary of all VPN flows')
                self.proposals.append(proposal)
            
            # IPsec Flow Operational State (from vpn_flows.IPSec.entry)
            if 'vpn_flows' in data and data['vpn_flows'] and data['vpn_flows'].get('IPSec'):
                ipsec_data = data['vpn_flows']['IPSec']
                flow_entries = []
                if isinstance(ipsec_data, dict) and 'entry' in ipsec_data:
                    flow_entries = ipsec_data['entry']
                    # Ensure it's a list
                    if not isinstance(flow_entries, list):
                        flow_entries = [flow_entries]
                
                if flow_entries:
                    first_flow = flow_entries[0]
                    
                    proposal = InfluxDBSchemaProposal(
                        'palo_alto_ipsec_flow',
                        'Active IPsec flow operational state',
                        'vpn'
                    )
                    proposal.add_tag('hostname', firewall_name)
                    proposal.add_tag('flow_name', first_flow.get('name'), 'Flow/tunnel name')
                    
                    proposal.add_field('flow_id', first_flow.get('id'), '', 'Flow ID')
                    proposal.add_field('gateway_id', first_flow.get('gwid'), '', 'Associated gateway ID')
                    proposal.add_field('inner_interface', first_flow.get('inner-if'), '', 'Inner (logical) interface')
                    proposal.add_field('outer_interface', first_flow.get('outer-if'), '', 'Outer (physical) interface')
                    proposal.add_field('state', first_flow.get('state'), '', 'Flow state (active/down)')
                    proposal.add_field('ipsec_mode', first_flow.get('ipsec-mode'), '', 'IPsec mode (tunnel/transport)')
                    proposal.add_field('local_ip', first_flow.get('localip'), '', 'Local endpoint IP address')
                    proposal.add_field('peer_ip', first_flow.get('peerip'), '', 'Peer endpoint IP address')
                    proposal.add_field('monitoring', first_flow.get('mon'), '', 'Path monitoring status (on/off)')
                    proposal.add_field('owner', first_flow.get('owner'), '', 'Owner ID')
                    proposal.add_field('state_up', 1 if first_flow.get('state') == 'active' else 0, 'boolean', 'Flow is active (1=active, 0=down)')
                    
                    proposal.cardinality = 'medium'
                    proposal.data_points_per_collection = len(flow_entries)
                    proposal.notes.append(f'One data point per active IPsec flow ({len(flow_entries)} flows)')
                    proposal.notes.append('Captures operational state from vpn_flows.IPSec.entry')
                    proposal.notes.append('Different from palo_alto_vpn_tunnel which shows configuration')
                    proposal.notes.append('Critical for real-time flow state monitoring')
                    self.proposals.append(proposal)
            
            # VPN Tunnels (per tunnel from active_tunnels or vpn_tunnels)
            tunnel_data = data.get('active_tunnels') or data.get('vpn_tunnels')
            if tunnel_data and tunnel_data.get('entries'):
                entries = tunnel_data['entries']
                if isinstance(entries, dict) and 'entry' in entries:
                    tunnel_entries = entries['entry']
                    # Ensure it's a list
                    if not isinstance(tunnel_entries, list):
                        tunnel_entries = [tunnel_entries]
                    
                    if tunnel_entries:
                        first_tunnel = tunnel_entries[0]
                        
                        proposal = InfluxDBSchemaProposal(
                            'palo_alto_vpn_tunnel',
                            'Individual VPN tunnel configuration and status',
                            'vpn'
                        )
                        proposal.add_tag('hostname', firewall_name)
                        proposal.add_tag('tunnel_name', first_tunnel.get('name'), 'Tunnel name')
                        proposal.add_tag('gateway', first_tunnel.get('gw'), 'Associated gateway name')
                        
                        proposal.add_field('tunnel_id', first_tunnel.get('id'), '', 'Tunnel ID')
                        proposal.add_field('protocol', first_tunnel.get('proto'), '', 'IPsec protocol (ESP/AH)')
                        proposal.add_field('mode', first_tunnel.get('mode'), '', 'Tunnel mode')
                        proposal.add_field('dh_group', first_tunnel.get('dh'), '', 'Diffie-Hellman group for PFS')
                        proposal.add_field('encryption', first_tunnel.get('enc'), '', 'Encryption algorithm')
                        proposal.add_field('hash', first_tunnel.get('hash'), '', 'Hash algorithm')
                        proposal.add_field('lifetime', first_tunnel.get('life'), 's', 'SA lifetime in seconds')
                        proposal.add_field('kb_limit', first_tunnel.get('kb'), 'KB', 'KB limit (0 = unlimited)')
                        
                        proposal.cardinality = 'medium'
                        proposal.data_points_per_collection = len(tunnel_entries)
                        proposal.notes.append(f'One data point per VPN tunnel ({len(tunnel_entries)} tunnels)')
                        proposal.notes.append('Tracks tunnel configuration parameters')
                        self.proposals.append(proposal)
            
            # VPN Gateways (per gateway)
            if 'vpn_gateways' in data and data['vpn_gateways'] and data['vpn_gateways'].get('entries'):
                gateways_data = data['vpn_gateways']
                if isinstance(gateways_data, dict) and 'entries' in gateways_data:
                    entries = gateways_data['entries']
                    if isinstance(entries, dict) and 'entry' in entries:
                        gateway_entries = entries['entry']
                        # Ensure it's a list
                        if not isinstance(gateway_entries, list):
                            gateway_entries = [gateway_entries]
                        
                        if gateway_entries:
                            first_gw = gateway_entries[0]
                            
                            # Prefer v2 (IKEv2) over v1
                            ike_version = first_gw.get('v2') if first_gw.get('v2') else first_gw.get('v1')
                            
                            # Extract peer and local IPs from ID strings
                            peer_id = ike_version.get('peer-id', '') if ike_version else ''
                            local_id = ike_version.get('local-id', '') if ike_version else ''
                            peer_ip = peer_id.split('ipaddr:')[-1].rstrip(')') if 'ipaddr:' in peer_id else peer_id
                            local_ip = local_id.split('ipaddr:')[-1].rstrip(')') if 'ipaddr:' in local_id else local_id
                            
                            proposal = InfluxDBSchemaProposal(
                                'palo_alto_vpn_gateway',
                                'VPN gateway (IKE) configuration and parameters',
                                'vpn'
                            )
                            proposal.add_tag('hostname', firewall_name)
                            proposal.add_tag('gateway_name', first_gw.get('name'), 'Gateway name')
                            
                            proposal.add_field('gateway_id', first_gw.get('id'), '', 'Gateway ID')
                            proposal.add_field('socket', first_gw.get('sock'), '', 'Socket number')
                            proposal.add_field('nat_t', first_gw.get('natt'), '', 'NAT traversal (0=disabled, 1=enabled)')
                            proposal.add_field('peer_ip', peer_ip, '', 'Peer gateway IP address')
                            proposal.add_field('local_ip', local_ip, '', 'Local gateway IP address')
                            proposal.add_field('ike_version', 2 if first_gw.get('v2') else 1, '', 'IKE version (1 or 2)')
                            proposal.add_field('authentication', ike_version.get('auth') if ike_version else None, '', 'Authentication method')
                            proposal.add_field('dh_group', ike_version.get('dh') if ike_version else None, '', 'Diffie-Hellman group')
                            proposal.add_field('encryption', ike_version.get('enc') if ike_version else None, '', 'Encryption algorithm')
                            proposal.add_field('hash', ike_version.get('hash') if ike_version else None, '', 'Hash algorithm')
                            proposal.add_field('prf', ike_version.get('prf') if ike_version and 'prf' in ike_version else None, '', 'Pseudo-Random Function (IKEv2 only)')
                            proposal.add_field('lifetime', ike_version.get('life') if ike_version else None, 's', 'IKE SA lifetime in seconds')
                            
                            proposal.cardinality = 'medium'
                            proposal.data_points_per_collection = len(gateway_entries)
                            proposal.notes.append(f'One data point per VPN gateway ({len(gateway_entries)} gateways)')
                            proposal.notes.append('Contains IKE (Phase 1) parameters')
                            proposal.notes.append('Prefers IKEv2 settings over IKEv1 when both are configured')
                            self.proposals.append(proposal)
            
            # IPsec Security Associations (per SA)
            if 'ipsec_sa' in data and data['ipsec_sa'] and data['ipsec_sa'].get('entries'):
                sa_data = data['ipsec_sa']
                if isinstance(sa_data, dict) and 'entries' in sa_data:
                    entries = sa_data['entries']
                    if isinstance(entries, dict) and 'entry' in entries:
                        sa_entries = entries['entry']
                        # Ensure it's a list
                        if not isinstance(sa_entries, list):
                            sa_entries = [sa_entries]
                        
                        if sa_entries:
                            first_sa = sa_entries[0]
                            
                            # Calculate percentage of lifetime remaining
                            lifetime = first_sa.get('life')
                            remain = first_sa.get('remain')
                            remain_percent = None
                            if lifetime and remain and lifetime > 0:
                                remain_percent = round((remain / lifetime) * 100, 2)
                            
                            proposal = InfluxDBSchemaProposal(
                                'palo_alto_ipsec_sa',
                                'Active IPsec Security Associations with lifetime tracking',
                                'vpn'
                            )
                            proposal.add_tag('hostname', firewall_name)
                            proposal.add_tag('tunnel_name', first_sa.get('name'), 'Tunnel name')
                            proposal.add_tag('gateway', first_sa.get('gateway'), 'Gateway name')
                            
                            proposal.add_field('gateway_id', first_sa.get('gwid'), '', 'Gateway ID')
                            proposal.add_field('tunnel_id', first_sa.get('tid'), '', 'Tunnel ID')
                            proposal.add_field('remote_ip', first_sa.get('remote'), '', 'Remote peer IP address')
                            proposal.add_field('protocol', first_sa.get('proto'), '', 'IPsec protocol')
                            proposal.add_field('encryption', first_sa.get('enc'), '', 'Encryption algorithm')
                            proposal.add_field('hash', first_sa.get('hash'), '', 'Hash algorithm')
                            proposal.add_field('inbound_spi', first_sa.get('i_spi'), '', 'Inbound SPI (Security Parameter Index)')
                            proposal.add_field('outbound_spi', first_sa.get('o_spi'), '', 'Outbound SPI')
                            proposal.add_field('lifetime_seconds', lifetime, 's', 'SA lifetime')
                            proposal.add_field('remaining_seconds', remain, 's', 'Time remaining until rekey')
                            proposal.add_field('remaining_percent', remain_percent, '%', 'Percentage of lifetime remaining')
                            
                            proposal.cardinality = 'medium'
                            proposal.data_points_per_collection = len(sa_entries)
                            proposal.notes.append(f'One data point per active IPsec SA ({len(sa_entries)} SAs)')
                            proposal.notes.append('Critical for monitoring tunnel health and rekey timing')
                            proposal.notes.append('Alert when remaining_seconds < 300 (5 minutes)')
                            self.proposals.append(proposal)
    
    # ==================== ANALYSIS AND REPORTING ====================
    
    def analyze_all(self):
        """Perform complete analysis of all modules."""
        self.analyze_system_module()
        self.analyze_environmental_module()
        self.analyze_interface_module()
        self.analyze_routing_module()
        self.analyze_counters_module()
        self.analyze_globalprotect_module()
        self.analyze_vpn_module()
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate a summary of all proposals."""
        # Count unique measurement names
        unique_measurements = set()
        measurements_by_category = defaultdict(list)
        total_tags = 0
        total_fields = 0
        cardinality_distribution = defaultdict(int)
        
        for proposal in self.proposals:
            measurement_name = proposal.measurement
            unique_measurements.add(measurement_name)
            
            category = proposal.category
            if measurement_name not in measurements_by_category[category]:
                measurements_by_category[category].append(measurement_name)
            
            total_tags += len([t for t in proposal.tags.values() if t is not None])
            total_fields += len([f for f in proposal.fields.values() if f is not None])
            cardinality_distribution[proposal.cardinality] += 1
        
        summary = {
            'total_measurements': len(unique_measurements),
            'measurements_by_category': dict(measurements_by_category),
            'total_tags': total_tags,
            'total_fields': total_fields,
            'cardinality_distribution': dict(cardinality_distribution),
        }
        
        return summary
    
    def print_summary(self):
        """Print analysis summary."""
        summary = self.generate_summary()
        
        if RICH_AVAILABLE:
            # Summary panel
            summary_text = f"[bold]Total Unique Measurements:[/bold] {summary['total_measurements']}\n\n"
            summary_text += "[bold]By Category:[/bold]\n"
            for category, measurements in sorted(summary['measurements_by_category'].items()):
                summary_text += f"  • {category}: {len(measurements)} unique measurements\n"
            
            panel = Panel(summary_text, title="[bold green]Analysis Summary[/bold green]", border_style="green")
            self.console.print("\n")
            self.console.print(panel)
        else:
            print("\n" + "="*80)
            print("ANALYSIS SUMMARY")
            print("="*80)
            print(f"Total Unique Measurements: {summary['total_measurements']}")
            print("\nBy Category:")
            for category, measurements in sorted(summary['measurements_by_category'].items()):
                print(f"  • {category}: {len(measurements)} unique measurements")
    
    def print_proposal(self, proposal: InfluxDBSchemaProposal, index: int):
        """Print a single measurement proposal."""
        if RICH_AVAILABLE:
            self._print_proposal_rich(proposal, index)
        else:
            self._print_proposal_plain(proposal, index)
    
    def _print_proposal_rich(self, proposal: InfluxDBSchemaProposal, index: int):
        """Print proposal using Rich formatting."""
        # Main info table
        table = Table(
            title=f"[bold cyan]{index}. {proposal.measurement}[/bold cyan]",
            box=box.ROUNDED,
            show_header=True
        )
        table.add_column("Property", style="yellow", no_wrap=True)
        table.add_column("Value", style="white")
        
        table.add_row("Category", proposal.category)
        table.add_row("Description", proposal.description)
        table.add_row("Cardinality", proposal.cardinality)
        table.add_row("Update Frequency", proposal.update_frequency)
        table.add_row("Data Points", str(proposal.data_points_per_collection))
        
        self.console.print(table)
        
        # Tags table
        if proposal.tags:
            tags_table = Table(title="Tags (Dimensions)", box=box.SIMPLE, show_header=True)
            tags_table.add_column("Tag Key", style="green")
            tags_table.add_column("Example", style="white")
            tags_table.add_column("Type", style="blue")
            tags_table.add_column("Description", style="dim")
            
            for key, info in proposal.tags.items():
                tags_table.add_row(
                    key,
                    str(info['example'])[:40],
                    info['type'],
                    info.get('description', '')[:40]
                )
            
            self.console.print(tags_table)
        
        # Fields table
        if proposal.fields:
            fields_table = Table(title="Fields (Metrics)", box=box.SIMPLE, show_header=True)
            fields_table.add_column("Field Key", style="magenta")
            fields_table.add_column("Example", style="white")
            fields_table.add_column("Type", style="blue")
            fields_table.add_column("Unit", style="cyan")
            fields_table.add_column("Description", style="dim")
            
            for key, info in proposal.fields.items():
                fields_table.add_row(
                    key,
                    str(info['example'])[:20],
                    info['type'],
                    info.get('unit', '')[:10],
                    info.get('description', '')[:40]
                )
            
            self.console.print(fields_table)
        
        # Notes
        if proposal.notes:
            self.console.print(f"\n[dim]Notes:[/dim]")
            for note in proposal.notes:
                self.console.print(f"  [dim]• {note}[/dim]")
        
        self.console.print("\n")
    
    def _print_proposal_plain(self, proposal: InfluxDBSchemaProposal, index: int):
        """Print proposal using plain text."""
        print(f"\n{'='*80}")
        print(f"{index}. {proposal.measurement}")
        print(f"{'='*80}")
        print(f"Category: {proposal.category}")
        print(f"Description: {proposal.description}")
        print(f"Cardinality: {proposal.cardinality}")
        print(f"Update Frequency: {proposal.update_frequency}")
        print(f"Data Points per Collection: {proposal.data_points_per_collection}")
        
        if proposal.tags:
            print(f"\nTags (Dimensions):")
            print(f"{'-'*80}")
            for key, info in proposal.tags.items():
                print(f"  {key:25} = {str(info['example'])[:30]:30} ({info['type']})")
        
        if proposal.fields:
            print(f"\nFields (Metrics):")
            print(f"{'-'*80}")
            for key, info in proposal.fields.items():
                unit = f" {info.get('unit')}" if info.get('unit') else ""
                print(f"  {key:25} = {str(info['example'])[:15]:15} ({info['type']}{unit})")
        
        if proposal.notes:
            print(f"\nNotes:")
            for note in proposal.notes:
                print(f"  • {note}")
    
    def export_schema(self, output_file: str):
        """Export schema proposals to JSON."""
        summary = self.generate_summary()
        
        schema = {
            'version': '1.0',
            'generated_for': 'Palo Alto Networks Firewall Monitoring',
            'total_unique_measurements': summary['total_measurements'],
            'total_proposals': len(self.proposals),
            'note': 'total_proposals may be higher than unique measurements due to per-VRF examples',
            'measurements': [p.to_dict() for p in self.proposals]
        }
        
        with open(output_file, 'w') as f:
            json.dump(schema, f, indent=2)
        
        print(f"\n✅ Schema proposals exported to: {output_file}")
    
    def run_analysis(self, export_file: str = None):
        """Run complete analysis and display results."""
        print("\n" + "="*80)
        print("PALO ALTO FIREWALL - COMPREHENSIVE DATA ANALYSIS")
        print("InfluxDB Schema Design")
        print("="*80 + "\n")
        
        # Perform analysis
        self.analyze_all()
        
        # Print summary first
        self.print_summary()
        
        # Print all proposals
        for idx, proposal in enumerate(self.proposals, 1):
            self.print_proposal(proposal, idx)
        
        # Export if requested
        if export_file:
            self.export_schema(export_file)
        
        # Final note
        if RICH_AVAILABLE:
            note = Panel(
                self.firewall_tag_note,
                title="[bold yellow]Important Note[/bold yellow]",
                border_style="yellow"
            )
            self.console.print(note)
        else:
            print("\n" + "="*80)
            print("IMPORTANT NOTE")
            print("="*80)
            print(self.firewall_tag_note)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='''Analyze Palo Alto firewall data for InfluxDB schema design.

This analyzer is designed to process JSON output from:
    pa_query.py -o json all-stats

The analyzer examines the data structure and proposes an InfluxDB schema
with measurements, tags, and fields for effective time-series monitoring.''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # From JSON file (generated by pa_query.py -o json all-stats > stats.json)
  python data_analyzer.py stats.json
  python data_analyzer.py --input stats.json
  
  # Direct pipe from pa_query.py
  python pa_query.py -o json all-stats | python data_analyzer.py
  
  # Export schema to JSON file
  python data_analyzer.py stats.json --export schema.json
  python data_analyzer.py --input stats.json --export schema.json
  
  # Pipe and export in one command
  python pa_query.py -o json all-stats | python data_analyzer.py --export schema.json

Note: This analyzer expects the specific JSON structure produced by pa_query.py.
      Using other data sources may result in analysis errors.
        '''
    )
    
    parser.add_argument(
        'input_file',
        nargs='?',
        type=str,
        help='Input JSON file from pa_query.py all-stats (if not provided, reads from stdin)'
    )
    
    parser.add_argument(
        '--input', '-i',
        type=str,
        dest='input_flag',
        help='Input JSON file from pa_query.py all-stats (alternative to positional argument)'
    )
    
    parser.add_argument(
        '--export',
        '-e',
        metavar='FILE',
        help='Export schema to JSON file'
    )
    
    args = parser.parse_args()
    
    # Determine input source (prioritize positional argument, then flag, then stdin)
    input_file = args.input_file or args.input_flag
    
    # Check if we have input data available
    if not input_file and sys.stdin.isatty():
        # No input file and stdin is a terminal (not piped)
        parser.print_help()
        print("\nError: No input provided. Provide a file path or pipe JSON data via stdin.", file=sys.stderr)
        sys.exit(1)
    
    # Load the data
    data = None
    try:
        if input_file:
            with open(input_file, 'r') as f:
                data = json.load(f)
        else:
            data = json.load(sys.stdin)
    except FileNotFoundError:
        print(f"❌ Error: Input file '{input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        if not input_file:
            # If reading from stdin and got JSON error, likely no data was piped
            print("❌ Error: No valid JSON data received from stdin.\n", file=sys.stderr)
            parser.print_help(sys.stderr)
            print("\nProvide JSON input via file path or pipe data from another command.", file=sys.stderr)
        else:
            print(f"❌ Error: Invalid JSON in '{input_file}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error reading input: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Run analysis (data will always be defined here if we reach this point)
    analyzer = ComprehensiveDataAnalyzer(data)
    analyzer.run_analysis(export_file=args.export)


if __name__ == '__main__':
    main()
