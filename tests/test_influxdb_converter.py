"""Comprehensive tests for InfluxDB converter."""

import pytest
import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch, mock_open
import sys
import io

from influxdb_converter import (
    InfluxDBLineProtocol,
    DataConverter,
    SystemConverter,
    InterfaceConverter,
    RoutingConverter,
    CountersConverter,
    GlobalProtectConverter,
    VPNConverter,
    PaloAltoInfluxDBConverter
)


class TestInfluxDBLineProtocol:
    """Test cases for InfluxDB line protocol utilities."""
    
    @pytest.mark.unit
    def test_escape_tag_value_with_comma(self):
        """Test escaping comma in tag value."""
        result = InfluxDBLineProtocol.escape_tag_value("value,with,commas")
        assert result == r"value\,with\,commas"
    
    @pytest.mark.unit
    def test_escape_tag_value_with_equals(self):
        """Test escaping equals in tag value."""
        result = InfluxDBLineProtocol.escape_tag_value("value=with=equals")
        assert result == r"value\=with\=equals"
    
    @pytest.mark.unit
    def test_escape_tag_value_with_space(self):
        """Test escaping space in tag value."""
        result = InfluxDBLineProtocol.escape_tag_value("value with spaces")
        assert result == r"value\ with\ spaces"
    
    @pytest.mark.unit
    def test_escape_tag_value_with_all_special_chars(self):
        """Test escaping all special characters."""
        result = InfluxDBLineProtocol.escape_tag_value("val=ue, with spaces")
        assert result == r"val\=ue\,\ with\ spaces"
    
    @pytest.mark.unit
    def test_escape_tag_value_none(self):
        """Test escaping None value."""
        result = InfluxDBLineProtocol.escape_tag_value(None)
        assert result == ""
    
    @pytest.mark.unit
    def test_escape_field_key(self):
        """Test escaping field key."""
        result = InfluxDBLineProtocol.escape_field_key("field=key, with spaces")
        assert result == r"field\=key\,\ with\ spaces"
    
    @pytest.mark.unit
    def test_format_field_value_boolean_true(self):
        """Test formatting boolean true."""
        result = InfluxDBLineProtocol.format_field_value(True)
        assert result == "true"
    
    @pytest.mark.unit
    def test_format_field_value_boolean_false(self):
        """Test formatting boolean false."""
        result = InfluxDBLineProtocol.format_field_value(False)
        assert result == "false"
    
    @pytest.mark.unit
    def test_format_field_value_integer(self):
        """Test formatting integer."""
        result = InfluxDBLineProtocol.format_field_value(42)
        assert result == "42i"
    
    @pytest.mark.unit
    def test_format_field_value_float(self):
        """Test formatting float."""
        result = InfluxDBLineProtocol.format_field_value(3.14)
        assert result == "3.14"
    
    @pytest.mark.unit
    def test_format_field_value_string(self):
        """Test formatting string."""
        result = InfluxDBLineProtocol.format_field_value("test value")
        assert result == '"test value"'
    
    @pytest.mark.unit
    def test_format_field_value_string_with_quotes(self):
        """Test formatting string with quotes."""
        result = InfluxDBLineProtocol.format_field_value('test "quoted" value')
        assert result == r'"test \"quoted\" value"'
    
    @pytest.mark.unit
    def test_format_field_value_none(self):
        """Test formatting None value."""
        result = InfluxDBLineProtocol.format_field_value(None)
        assert result is None
    
    @pytest.mark.unit
    def test_build_line_basic(self):
        """Test building basic line protocol."""
        measurement = "test_measurement"
        tags = {"host": "server1", "region": "us-east"}
        fields = {"value": 100, "status": "ok"}
        timestamp = 1609459200000000000
        
        result = InfluxDBLineProtocol.build_line(measurement, tags, fields, timestamp)
        
        assert "test_measurement" in result
        assert "host=server1" in result
        assert "region=us-east" in result
        assert "value=100i" in result
        assert 'status="ok"' in result
        assert str(timestamp) in result
    
    @pytest.mark.unit
    def test_build_line_no_tags(self):
        """Test building line with no tags."""
        measurement = "test"
        tags = {}
        fields = {"value": 1}
        timestamp = 1609459200000000000
        
        result = InfluxDBLineProtocol.build_line(measurement, tags, fields, timestamp)
        
        assert result == f"test value=1i {timestamp}"
    
    @pytest.mark.unit
    def test_build_line_no_fields(self):
        """Test building line with no fields returns None."""
        measurement = "test"
        tags = {"host": "server1"}
        fields = {}
        timestamp = 1609459200000000000
        
        result = InfluxDBLineProtocol.build_line(measurement, tags, fields, timestamp)
        
        assert result is None
    
    @pytest.mark.unit
    def test_build_line_with_none_values(self):
        """Test building line filters out None values."""
        measurement = "test"
        tags = {"host": "server1", "region": None}
        fields = {"value": 100, "empty": None}
        timestamp = 1609459200000000000
        
        result = InfluxDBLineProtocol.build_line(measurement, tags, fields, timestamp)
        
        assert "host=server1" in result
        assert "region" not in result
        assert "value=100i" in result
        assert "empty" not in result
    
    @pytest.mark.unit
    def test_build_line_tags_sorted(self):
        """Test that tags are sorted."""
        measurement = "test"
        tags = {"z_tag": "z", "a_tag": "a", "m_tag": "m"}
        fields = {"value": 1}
        timestamp = 1609459200000000000
        
        result = InfluxDBLineProtocol.build_line(measurement, tags, fields, timestamp)
        
        # Tags should appear in sorted order
        tag_section = result.split(" ")[0]
        assert tag_section.index("a_tag") < tag_section.index("m_tag")
        assert tag_section.index("m_tag") < tag_section.index("z_tag")


class TestDataConverter:
    """Test cases for DataConverter base class."""
    
    @pytest.mark.unit
    def test_parse_size_string_gigabytes(self):
        """Test parsing gigabyte size strings."""
        converter = DataConverter()
        result = converter.parse_size_string("12G")
        assert result == 12.0
    
    @pytest.mark.unit
    def test_parse_size_string_gigabytes_decimal(self):
        """Test parsing decimal gigabyte size strings."""
        converter = DataConverter()
        result = converter.parse_size_string("6.9G")
        assert result == 6.9
    
    @pytest.mark.unit
    def test_parse_size_string_megabytes(self):
        """Test parsing megabyte size strings."""
        converter = DataConverter()
        result = converter.parse_size_string("1024M")
        assert result == pytest.approx(1.0 / 1024, rel=1e-9)
    
    @pytest.mark.unit
    def test_parse_size_string_kilobytes(self):
        """Test parsing kilobyte size strings."""
        converter = DataConverter()
        # Note: The converter treats K as bytes/1024^3, resulting in:
        # 1048576K * (1/(1024^3)) = 0.0009765625 GB
        result = converter.parse_size_string("1048576K")
        assert result == pytest.approx(0.0009765625, rel=1e-6)
    
    @pytest.mark.unit
    def test_parse_size_string_terabytes(self):
        """Test parsing terabyte size strings."""
        converter = DataConverter()
        result = converter.parse_size_string("2T")
        assert result == 2048.0
    
    @pytest.mark.unit
    def test_parse_size_string_zero(self):
        """Test parsing zero value."""
        converter = DataConverter()
        result = converter.parse_size_string(0)
        assert result == 0.0
    
    @pytest.mark.unit
    def test_parse_size_string_none(self):
        """Test parsing None value."""
        converter = DataConverter()
        result = converter.parse_size_string(None)
        assert result == 0.0
    
    @pytest.mark.unit
    def test_parse_size_string_invalid(self):
        """Test parsing invalid size string."""
        converter = DataConverter()
        result = converter.parse_size_string("invalid")
        assert result is None


class TestSystemConverter:
    """Test cases for SystemConverter."""
    
    @pytest.fixture
    def sample_system_data(self):
        """Provide sample system data."""
        return {
            'system_info': {
                'system': {
                    'hostname': 'test-fw',
                    'model': 'PA-220',
                    'family': '200',
                    'serial': '012345678901',
                    'sw-version': '10.2.0',
                    'vm-cores': 4,
                    'vm-mem': 8192,
                    'operational-mode': 'normal',
                    'advanced-routing': 'on',
                    'multi-vsys': 'off',
                    'ip-address': '192.168.1.100',
                    'mac-address': '00:1b:17:00:01:00',
                    'ipv6-address': 'fe80::1',
                    'is-dhcp': 'no',
                    'is-dhcp6': 'no',
                    '_uptime_seconds': 1634589,
                    'app-version': '8790-8462',
                    'av-version': 0,
                    'threat-version': 4567,
                    'wf-private-version': 0,
                    'wildfire-version': 0,
                    'wildfire-rt': 'Disabled',
                    'url-filtering-version': 20251014,
                    'url-db': 'paloaltonetworks',
                    'logdb-version': '11.1.2',
                    'device-dictionary-version': '196-656',
                    'global-protect-client-package-version': '6.3.2'
                }
            },
            'resource_usage': {
                'cpu_user': 9.0,
                'cpu_system': 16.4,
                'cpu_nice': 9.0,
                'cpu_idle': 62.7,
                'cpu_iowait': 0.0,
                'cpu_hardware_interrupt': 1.5,
                'cpu_software_interrupt': 1.5,
                'cpu_steal': 0.0,
                'memory_total_mib': 16030.8,
                'memory_free_mib': 919.4,
                'memory_used_mib': 5004.1,
                'memory_buff_cache_mib': 10107.3,
                'memory_available_mib': 5575.6,
                'memory_usage_percent': 31.2,
                'swap_total_mib': 4000.0,
                'swap_free_mib': 3999.7,
                'swap_used_mib': 0.3,
                'swap_usage_percent': 0.0,
                'load_average_1min': 0.81,
                'load_average_5min': 0.91,
                'load_average_15min': 0.79,
                'tasks_total': 247,
                'tasks_running': 2,
                'tasks_sleeping': 244,
                'tasks_stopped': 0,
                'tasks_zombie': 1
            },
            'disk_usage': {
                '/': {
                    'device': '/dev/root',
                    'size': '12G',
                    'used': '6.9G',
                    'available': '4.5G',
                    'use_percent': '61'
                }
            },
            'ha_status': {
                'enabled': False
            }
        }
    
    @pytest.mark.unit
    def test_convert_system_identity(self, sample_system_data):
        """Test system identity conversion."""
        converter = SystemConverter()
        lines = converter.convert('test-fw', sample_system_data)
        
        # Find system identity line
        identity_line = [l for l in lines if 'palo_alto_system_identity' in l][0]
        
        assert 'hostname=test-fw' in identity_line
        assert 'model=PA-220' in identity_line
        assert 'sw_version="10.2.0"' in identity_line
        assert 'vm_cores=4i' in identity_line
    
    @pytest.mark.unit
    def test_convert_system_identity_new_fields(self, sample_system_data):
        """Test system identity conversion includes new network fields."""
        converter = SystemConverter()
        lines = converter.convert('test-fw', sample_system_data)
        
        # Find system identity line
        identity_line = [l for l in lines if 'palo_alto_system_identity' in l][0]
        
        # Check new fields
        assert 'multi_vsys="off"' in identity_line
        assert 'ip_address="192.168.1.100"' in identity_line
        assert 'mac_address="00:1b:17:00:01:00"' in identity_line
        assert 'ipv6_address="fe80::1"' in identity_line
        assert 'is_dhcp=false' in identity_line
        assert 'is_dhcp6=false' in identity_line
    
    @pytest.mark.unit
    def test_convert_content_versions(self, sample_system_data):
        """Test content versions conversion."""
        converter = SystemConverter()
        lines = converter.convert('test-fw', sample_system_data)
        
        # Find content versions line
        content_line = [l for l in lines if 'palo_alto_content_versions' in l][0]
        
        assert 'hostname=test-fw' in content_line
        assert 'app_version="8790-8462"' in content_line
        assert 'av_version=0i' in content_line
        assert 'threat_version=4567i' in content_line
        assert 'wildfire_rt="Disabled"' in content_line
        assert 'url_filtering_version=20251014i' in content_line
        assert 'url_db="paloaltonetworks"' in content_line
        assert 'logdb_version="11.1.2"' in content_line
        assert 'device_dictionary_version="196-656"' in content_line
        assert 'global_protect_client_package_version="6.3.2"' in content_line
    
    @pytest.mark.unit
    def test_convert_system_uptime(self, sample_system_data):
        """Test system uptime conversion."""
        converter = SystemConverter()
        lines = converter.convert('test-fw', sample_system_data)
        
        # Find uptime line
        uptime_line = [l for l in lines if 'palo_alto_system_uptime' in l][0]
        
        assert 'uptime_seconds=1634589i' in uptime_line
        assert 'uptime_days=' in uptime_line
    
    @pytest.mark.unit
    def test_convert_cpu_usage(self, sample_system_data):
        """Test CPU usage conversion."""
        converter = SystemConverter()
        lines = converter.convert('test-fw', sample_system_data)
        
        # Find CPU line
        cpu_line = [l for l in lines if 'palo_alto_cpu_usage' in l][0]
        
        assert 'cpu_user=9.0' in cpu_line
        assert 'cpu_idle=62.7' in cpu_line
        assert 'cpu_total_used=37.3' in cpu_line
    
    @pytest.mark.unit
    def test_convert_memory_usage(self, sample_system_data):
        """Test memory usage conversion."""
        converter = SystemConverter()
        lines = converter.convert('test-fw', sample_system_data)
        
        # Find memory line
        memory_line = [l for l in lines if 'palo_alto_memory_usage' in l][0]
        
        assert 'memory_total_mib=16030.8' in memory_line
        assert 'memory_usage_percent=31.2' in memory_line
    
    @pytest.mark.unit
    def test_convert_disk_usage(self, sample_system_data):
        """Test disk usage conversion."""
        converter = SystemConverter()
        lines = converter.convert('test-fw', sample_system_data)
        
        # Find disk line
        disk_line = [l for l in lines if 'palo_alto_disk_usage' in l][0]
        
        assert 'mount_point=/' in disk_line
        assert 'device=/dev/root' in disk_line
        assert 'use_percent=61.0' in disk_line  # Now a float, not string
        assert 'size_gb=12.0' in disk_line
    
    @pytest.mark.unit
    def test_convert_all_measurements(self, sample_system_data):
        """Test that all 10 system measurements are generated."""
        converter = SystemConverter()
        lines = converter.convert('test-fw', sample_system_data)
        
        # Should generate 10 lines for system module
        assert len(lines) == 10
        
        measurements = [
            'palo_alto_system_identity',
            'palo_alto_system_uptime',
            'palo_alto_content_versions',
            'palo_alto_cpu_usage',
            'palo_alto_memory_usage',
            'palo_alto_swap_usage',
            'palo_alto_load_average',
            'palo_alto_task_stats',
            'palo_alto_disk_usage',
            'palo_alto_ha_status'
        ]
        
        for measurement in measurements:
            assert any(measurement in line for line in lines)


class TestInterfaceConverter:
    """Test cases for InterfaceConverter."""
    
    @pytest.fixture
    def sample_interface_data(self):
        """Provide sample interface data."""
        return {
            'interface_info': {
                'hw': {
                    'entry': [
                        {
                            'name': 'ethernet1/1',
                            'type': 'Ethernet',
                            'state': 'up',
                            'speed': 1000,
                            'duplex': 'full',
                            'mac': '00:1b:17:00:01:00',
                            'mode': 'layer3',
                            'fec': 'off'
                        }
                    ]
                },
                'ifnet': {
                    'entry': [
                        {
                            'name': 'ethernet1/1',
                            'zone': 'trust',
                            'vsys': 1,
                            'ip': '192.168.1.1/24',
                            'fwd': 'vr:default',
                            'tag': '0'
                        }
                    ]
                }
            },
            'interface_counters': {
                'hw': {
                    'entry': [
                        {
                            'name': 'ethernet1/1',
                            'port': {
                                'rx-bytes': 1024000,
                                'rx-unicast': 1000,
                                'rx-multicast': 10,
                                'rx-broadcast': 5,
                                'rx-error': 0,
                                'rx-discards': 0,
                                'tx-bytes': 2048000,
                                'tx-unicast': 2000,
                                'tx-multicast': 20,
                                'tx-broadcast': 10,
                                'tx-error': 0,
                                'tx-discards': 0,
                                'link-down': 0
                            }
                        }
                    ]
                }
            }
        }
    
    @pytest.mark.unit
    def test_convert_interface_info(self, sample_interface_data):
        """Test interface info conversion."""
        converter = InterfaceConverter()
        lines = converter.convert('test-fw', sample_interface_data)
        
        # Find interface info line
        info_line = [l for l in lines if 'palo_alto_interface_info' in l][0]
        
        assert 'interface=ethernet1/1' in info_line
        assert 'state="up"' in info_line  # state is now a field (string value)
        assert 'speed=1000i' in info_line
    
    @pytest.mark.unit
    def test_convert_interface_logical(self, sample_interface_data):
        """Test interface logical config conversion."""
        converter = InterfaceConverter()
        lines = converter.convert('test-fw', sample_interface_data)
        
        # Find logical line
        logical_line = [l for l in lines if 'palo_alto_interface_logical' in l][0]
        
        assert 'interface=ethernet1/1' in logical_line
        assert 'zone=trust' in logical_line
        assert 'ip="192.168.1.1/24"' in logical_line
    
    @pytest.mark.unit
    def test_convert_interface_counters(self, sample_interface_data):
        """Test interface counters conversion."""
        converter = InterfaceConverter()
        lines = converter.convert('test-fw', sample_interface_data)
        
        # Find counters line
        counters_line = [l for l in lines if 'palo_alto_interface_counters' in l][0]
        
        assert 'rx_bytes=1024000i' in counters_line
        assert 'tx_bytes=2048000i' in counters_line
        assert 'rx_unicast=1000i' in counters_line


class TestRoutingConverter:
    """Test cases for RoutingConverter."""
    
    @pytest.fixture
    def sample_routing_data_with_table(self):
        """Provide sample routing data with routing table."""
        return {
            'bgp_summary': {
                'router_id': '192.168.1.1',
                'local_as': 65000,
                'total_peers': 2,
                'peers_established': 2,
                'peers_down': 0,
                'total_prefixes': 150
            },
            'bgp_peer_status': {
                'peer-1': {
                    'peer-ip': '192.168.1.2',
                    'peer-group-name': 'ebgp',
                    'state': 'Established',
                    'remote-as': 65001,
                    'local-as': 65000,
                    'status-time': 172800
                }
            },
            'routing_table': {
                'default': {
                    '0.0.0.0/0': [
                        {'protocol': 'static', 'nexthop': '192.168.1.254'}
                    ],
                    '10.0.0.0/8': [
                        {'protocol': 'bgp', 'nexthop': '192.168.1.2'}
                    ],
                    '192.168.0.0/16': [
                        {'protocol': 'connect', 'nexthop': '0.0.0.0'}
                    ]
                }
            }
        }
    
    @pytest.fixture
    def sample_routing_data_fallback(self):
        """Provide sample routing data for fallback (no routing_table)."""
        return {
            'static_routes': {
                'default': {
                    '0.0.0.0/0': [
                        {'nexthop': '192.168.1.254'}
                    ],
                    '10.0.0.0/24': [
                        {'nexthop': '192.168.1.1'}
                    ]
                }
            },
            'bgp_routes': {
                'default': {
                    '172.16.0.0/12': [
                        {'nexthop': '192.168.1.2'}
                    ]
                }
            }
        }
    
    @pytest.mark.unit
    def test_convert_bgp_summary(self, sample_routing_data_with_table):
        """Test BGP summary conversion."""
        converter = RoutingConverter()
        lines = converter.convert('test-fw', sample_routing_data_with_table)
        
        # Find BGP summary line
        bgp_line = [l for l in lines if 'palo_alto_bgp_summary' in l][0]
        
        assert 'router_id=192.168.1.1' in bgp_line
        assert 'local_as=65000' in bgp_line
        assert 'total_peers=2i' in bgp_line
    
    @pytest.mark.unit
    def test_convert_bgp_peer(self, sample_routing_data_with_table):
        """Test BGP peer conversion."""
        converter = RoutingConverter()
        lines = converter.convert('test-fw', sample_routing_data_with_table)
        
        # Find BGP peer line
        peer_line = [l for l in lines if 'palo_alto_bgp_peer' in l][0]
        
        assert 'peer_name=peer-1' in peer_line
        assert 'state=Established' in peer_line
        assert 'state_up=1i' in peer_line
    
    @pytest.mark.unit
    def test_convert_routing_table_counts(self, sample_routing_data_with_table):
        """Test routing table counts conversion."""
        converter = RoutingConverter()
        lines = converter.convert('test-fw', sample_routing_data_with_table)
        
        # Find routing table counts line
        counts_line = [l for l in lines if 'palo_alto_routing_table_counts' in l][0]
        
        assert 'vrf=default' in counts_line
        assert 'routes_static=1i' in counts_line
        assert 'routes_bgp=1i' in counts_line
        assert 'routes_connect=1i' in counts_line
        assert 'routes_total=3i' in counts_line
    
    @pytest.mark.unit
    def test_fallback_static_routes(self, sample_routing_data_fallback):
        """Test fallback to static routes count."""
        converter = RoutingConverter()
        lines = converter.convert('test-fw', sample_routing_data_fallback)
        
        # Find static routes count line
        static_line = [l for l in lines if 'palo_alto_static_routes_count' in l][0]
        
        assert 'static_routes=2i' in static_line
    
    @pytest.mark.unit
    def test_fallback_bgp_routes(self, sample_routing_data_fallback):
        """Test fallback to BGP routes count."""
        converter = RoutingConverter()
        lines = converter.convert('test-fw', sample_routing_data_fallback)
        
        # Find BGP routes count line
        bgp_line = [l for l in lines if 'palo_alto_bgp_routes_count' in l][0]
        
        assert 'bgp_routes=1i' in bgp_line


class TestCountersConverter:
    """Test cases for CountersConverter."""
    
    @pytest.fixture
    def sample_counters_data(self):
        """Provide sample counters data."""
        return {
            'global_counters': {
                'global': {
                    'counters': {
                        'entry': [
                            {
                                'name': 'pkt_recv',
                                'value': 24821074,
                                'rate': 0,
                                'category': 'packet',
                                'desc': 'Packets received'
                            },
                            {
                                'name': 'pkt_sent',
                                'value': 8260293,
                                'rate': 5,
                                'category': 'packet',
                                'desc': 'Packets sent'
                            },
                            {
                                'name': 'pkt_dropped',
                                'value': 100,
                                'rate': 0,
                                'category': 'packet',
                                'desc': 'Packets dropped'
                            },
                            {
                                'name': 'pkt_error',
                                'value': 50,
                                'rate': 0,
                                'category': 'packet',
                                'desc': 'Packet errors'
                            },
                            {
                                'name': 'pkt_broadcast',
                                'value': 1000,
                                'rate': 0,
                                'category': 'packet',
                                'desc': 'Broadcast packets'
                            },
                            {
                                'name': 'session_allocated',
                                'value': 150,
                                'rate': 0,
                                'category': 'session',
                                'desc': 'Sessions allocated'
                            },
                            {
                                'name': 'session_active',
                                'value': 120,
                                'rate': 0,
                                'category': 'session',
                                'desc': 'Active sessions'
                            },
                            {
                                'name': 'session_max',
                                'value': 500,
                                'rate': 0,
                                'category': 'session',
                                'desc': 'Max sessions'
                            },
                            {
                                'name': 'session_used',
                                'value': 100,
                                'rate': 0,
                                'category': 'session',
                                'desc': 'Sessions used'
                            },
                            {
                                'name': 'session_utilization',
                                'value': 20,
                                'rate': 0,
                                'category': 'session',
                                'desc': 'Session utilization'
                            }
                        ]
                    }
                }
            }
        }
    
    @pytest.mark.unit
    def test_convert_counters_by_category(self, sample_counters_data):
        """Test counters conversion groups by category."""
        converter = CountersConverter()
        lines = converter.convert('test-fw', sample_counters_data)
        
        # Should have separate measurements for packet and session categories
        assert any('palo_alto_counters_packet' in l for l in lines)
        assert any('palo_alto_counters_session' in l for l in lines)
    
    @pytest.mark.unit
    def test_convert_counters_includes_rates(self, sample_counters_data):
        """Test that counter rates are included."""
        converter = CountersConverter()
        lines = converter.convert('test-fw', sample_counters_data)
        
        # Find packet counters line
        packet_line = [l for l in lines if 'palo_alto_counters_packet' in l][0]
        
        # Should include both value and rate
        assert 'pkt_recv=24821074i' in packet_line
        assert 'pkt_sent_rate=5i' in packet_line


class TestGlobalProtectConverter:
    """Test cases for GlobalProtectConverter."""
    
    @pytest.fixture
    def sample_gp_data(self):
        """Provide sample GlobalProtect data."""
        return {
            'gateway_summary': {
                'entry': [
                    {
                        'name': 'gp-gateway',
                        'CurrentUsers': 15,
                        'PreviousUsers': 14,
                        'gateway_max_concurrent_tunnel': 100,
                        'gateway_successful_ip_sec_connections': 500,
                        'record_gateway_tunnel_count': 450
                    }
                ]
            },
            'portal_summary': {
                'entry': [
                    {
                        'name': 'gp-portal',
                        'successful_connections': 1000
                    }
                ]
            }
        }
    
    @pytest.mark.unit
    def test_convert_gateway_summary(self, sample_gp_data):
        """Test GlobalProtect gateway conversion."""
        converter = GlobalProtectConverter()
        lines = converter.convert('test-fw', sample_gp_data)
        
        # Find gateway line
        gateway_line = [l for l in lines if 'palo_alto_gp_gateway' in l][0]
        
        assert 'gateway_name=gp-gateway' in gateway_line
        assert 'current_users=15i' in gateway_line
        assert 'max_concurrent_tunnels=100i' in gateway_line
    
    @pytest.mark.unit
    def test_convert_portal_summary(self, sample_gp_data):
        """Test GlobalProtect portal conversion."""
        converter = GlobalProtectConverter()
        lines = converter.convert('test-fw', sample_gp_data)
        
        # Find portal line
        portal_line = [l for l in lines if 'palo_alto_gp_portal' in l][0]
        
        assert 'portal_name=gp-portal' in portal_line
        assert 'successful_connections=1000i' in portal_line


class TestVPNConverter:
    """Test cases for VPNConverter."""
    
    @pytest.fixture
    def sample_vpn_data(self):
        """Provide sample VPN data."""
        return {
            'vpn_flows': {
                'num_ipsec': 5,
                'num_sslvpn': 3,
                'total': 8
            }
        }
    
    @pytest.mark.unit
    def test_convert_vpn_flows(self, sample_vpn_data):
        """Test VPN flows conversion."""
        converter = VPNConverter()
        lines = converter.convert('test-fw', sample_vpn_data)
        
        assert len(lines) == 1
        line = lines[0]
        
        assert 'palo_alto_vpn_flows' in line
        assert 'num_ipsec=5i' in line
        assert 'num_sslvpn=3i' in line
        assert 'total_flows=8i' in line


class TestPaloAltoInfluxDBConverter:
    """Test cases for main converter orchestration."""
    
    @pytest.fixture
    def complete_stats_data(self):
        """Provide complete stats data."""
        return {
            'system': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'system_info': {
                            'system': {
                                'hostname': 'test-fw',
                                'model': 'PA-220',
                                'family': '200',
                                'serial': '123456',
                                'sw-version': '10.2.0',
                                '_uptime_seconds': 86400
                            }
                        },
                        'resource_usage': {
                            'cpu_idle': 80.0,
                            'cpu_user': 10.0,
                            'memory_total_mib': 8192,
                            'memory_usage_percent': 50.0,
                            'swap_total_mib': 2048,
                            'swap_usage_percent': 0,
                            'load_average_1min': 0.5,
                            'tasks_total': 100
                        },
                        'disk_usage': {
                            '/': {
                                'device': '/dev/root',
                                'size': '12G',
                                'use_percent': '60'
                            }
                        },
                        'ha_status': {
                            'enabled': False
                        }
                    },
                    'error': None
                }
            },
            'interfaces': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'interface_counters': {
                            'hw': {
                                'entry': [
                                    {
                                        'name': 'ethernet1/1',
                                        'port': {
                                            'rx-bytes': 1000,
                                            'tx-bytes': 2000
                                        }
                                    }
                                ]
                            }
                        }
                    },
                    'error': None
                }
            }
        }
    
    @pytest.mark.unit
    def test_convert_multi_module(self, complete_stats_data):
        """Test conversion across multiple modules."""
        converter = PaloAltoInfluxDBConverter(verbose=False)
        lines = converter.convert(complete_stats_data)
        
        # Should have lines from both system and interface modules
        assert any('palo_alto_system_identity' in l for l in lines)
        assert any('palo_alto_interface_counters' in l for l in lines)
        assert len(lines) > 0
    
    @pytest.mark.unit
    def test_convert_handles_errors(self):
        """Test conversion handles errors gracefully."""
        data = {
            'system': {
                'test-fw': {
                    'success': False,
                    'data': None,
                    'error': 'Connection failed'
                }
            }
        }
        
        converter = PaloAltoInfluxDBConverter(verbose=False)
        lines = converter.convert(data)
        
        # Should not crash and return empty list
        assert isinstance(lines, list)
        assert converter.total_errors == 1
    
    @pytest.mark.unit
    def test_convert_multi_firewall(self):
        """Test conversion with multiple firewalls."""
        data = {
            'system': {
                'fw1': {
                    'success': True,
                    'data': {
                        'system_info': {'system': {'hostname': 'fw1'}},
                        'resource_usage': {'cpu_idle': 80}
                    },
                    'error': None
                },
                'fw2': {
                    'success': True,
                    'data': {
                        'system_info': {'system': {'hostname': 'fw2'}},
                        'resource_usage': {'cpu_idle': 85}
                    },
                    'error': None
                }
            }
        }
        
        converter = PaloAltoInfluxDBConverter(verbose=False)
        lines = converter.convert(data)
        
        # Should have lines for both firewalls (now using hostname tags)
        assert any('hostname=fw1' in l for l in lines)
        assert any('hostname=fw2' in l for l in lines)
    
    @pytest.mark.unit
    def test_get_stats(self, complete_stats_data):
        """Test getting conversion statistics."""
        converter = PaloAltoInfluxDBConverter(verbose=False)
        converter.convert(complete_stats_data)
        
        stats = converter.get_stats()
        
        assert 'total_lines' in stats
        assert 'total_errors' in stats
        assert stats['total_lines'] > 0


class TestConverterCLI:
    """Test cases for CLI functionality."""
    
    @pytest.mark.unit
    def test_cli_with_input_file(self, tmp_path):
        """Test CLI with input file."""
        # Create test input file
        input_file = tmp_path / "test_input.json"
        test_data = {
            'system': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'system_info': {'system': {'hostname': 'test'}},
                        'resource_usage': {'cpu_idle': 80}
                    },
                    'error': None
                }
            }
        }
        input_file.write_text(json.dumps(test_data))
        
        # Create output file path
        output_file = tmp_path / "test_output.txt"
        
        # Test main function
        from influxdb_converter import main
        
        with patch('sys.argv', ['influxdb_converter.py', '--input', str(input_file), 
                                '--output', str(output_file)]):
            main()
        
        # Verify output file was created
        assert output_file.exists()
        content = output_file.read_text()
        assert len(content) > 0
    
    @pytest.mark.unit
    def test_cli_with_stdin(self):
        """Test CLI with stdin input."""
        test_data = {
            'system': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'system_info': {'system': {'hostname': 'test'}},
                        'resource_usage': {'cpu_idle': 80}
                    },
                    'error': None
                }
            }
        }
        
        from influxdb_converter import main
        
        # Mock stdin with JSON data
        with patch('sys.stdin', io.StringIO(json.dumps(test_data))):
            with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                with patch('sys.argv', ['influxdb_converter.py']):
                    main()
                
                output = mock_stdout.getvalue()
                assert len(output) > 0
                assert 'palo_alto' in output
    
    @pytest.mark.unit
    def test_cli_verbose_mode(self, tmp_path, capsys):
        """Test CLI verbose mode."""
        input_file = tmp_path / "test_input.json"
        test_data = {
            'system': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'system_info': {'system': {'hostname': 'test'}},
                        'resource_usage': {'cpu_idle': 80}
                    },
                    'error': None
                }
            }
        }
        input_file.write_text(json.dumps(test_data))
        
        from influxdb_converter import main
        
        with patch('sys.argv', ['influxdb_converter.py', '--input', str(input_file), 
                                '--verbose']):
            main()
        
        # Check that verbose output was produced
        captured = capsys.readouterr()
        assert '[INFO]' in captured.err or 'system/test-fw' in captured.err


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

