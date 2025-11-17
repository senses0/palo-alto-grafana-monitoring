"""Unit tests for statistics collection modules."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from src.stats.system import SystemStats
from src.stats.network_interfaces import InterfaceStats
from src.stats.global_counters import GlobalCounters
from src.stats.global_protect import GlobalProtectStats
from src.stats.routing import RoutingStats
from src.stats.vpn_tunnels import VpnTunnelStats
from src.palo_alto_client.exceptions import PaloAltoError


class TestSystemStats:
    """Test cases for SystemStats."""
    
    @pytest.fixture
    def system_stats_fixture(self, mock_client):
        """Set up test fixtures."""
        system_stats = SystemStats(mock_client)
        return system_stats
    
    @pytest.mark.unit
    def test_init(self, system_stats_fixture):
        """Test initialization."""
        assert system_stats_fixture is not None
        assert system_stats_fixture.client is not None
    
    @patch('src.stats.system.datetime')
    def test_get_system_data(self, mock_datetime, system_stats_fixture, mock_client):
        """Test getting complete system data."""
        # Mock datetime
        mock_datetime.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
        
        # Mock the execute_on_all_firewalls method
        expected_result = {
            'test-fw': {
                'success': True,
                'data': {
                    'system_info': {'system': {'hostname': 'test-fw'}},
                    'resource_usage': {'cpu': '10%', 'memory': '50%'},
                    'disk_usage': {'disk': '80%'},
                    'ha_status': {'ha_state': 'active'},
                    'environmental': {'temp': '45C'},
                    'hardware_info': {'model': 'PA-220'},
                    'timestamp': '2024-01-01T12:00:00'
                },
                'error': None
            }
        }
        mock_client.execute_on_all_firewalls.return_value = expected_result
        
        result = system_stats_fixture.get_system_data()
        
        # Verify the result structure
        assert isinstance(result, dict)
        assert 'test-fw' in result
        assert result['test-fw']['success'] is True
        assert 'data' in result['test-fw']
        
        # Verify execute_on_all_firewalls was called
        mock_client.execute_on_all_firewalls.assert_called_once()
    
    @pytest.mark.unit
    def test_get_system_data_with_exceptions(self, system_stats_fixture, mock_client):
        """Test system data collection with exceptions in individual methods."""
        # Mock the execute_on_all_firewalls method to return error
        expected_result = {
            'test-fw': {
                'success': False,
                'data': None,
                'error': 'System error occurred'
            }
        }
        mock_client.execute_on_all_firewalls.return_value = expected_result
        
        result = system_stats_fixture.get_system_data()
        
        # Should still return a dict with error information
        assert isinstance(result, dict)
        assert 'test-fw' in result
        assert result['test-fw']['success'] is False
        assert 'error' in result['test-fw']
        
        # Verify execute_on_all_firewalls was called
        mock_client.execute_on_all_firewalls.assert_called_once()
    
    @pytest.mark.unit
    def test_parse_top_output(self, system_stats_fixture):
        """Test parsing top command output."""
        top_output = """top - 12:26:55 up 6 days,  1:15,  0 users,  load average: 0.81, 0.91, 0.79
Tasks: 247 total,   2 running, 244 sleeping,   0 stopped,   1 zombie
%Cpu(s):  9.0 us, 16.4 sy,  9.0 ni, 62.7 id,  0.0 wa,  1.5 hi,  1.5 si,  0.0 st
MiB Mem :  16030.8 total,    919.4 free,   5004.1 used,  10107.3 buff/cache
MiB Swap:   4000.0 total,   3999.7 free,      0.2 used.   5575.6 avail Mem"""
        
        result = system_stats_fixture.parse_top_output(top_output)
        
        assert isinstance(result, dict)
        assert 'uptime_days' in result
        assert 'load_average_1min' in result
        assert 'tasks_total' in result
        assert 'cpu_user' in result
        assert 'memory_total_mib' in result
    
    @pytest.mark.unit
    def test_parse_disk_space_string(self, system_stats_fixture):
        """Test parsing disk space string."""
        disk_output = """Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/root       1000000  800000    200000  80% /
/dev/data       2000000 1500000    500000  75% /data"""
        
        result = system_stats_fixture.parse_disk_space_string(disk_output)
        
        assert isinstance(result, dict)
        assert '/' in result
        assert '/data' in result
        assert result['/']['use_percent'] == '80'
        assert result['/data']['use_percent'] == '75'


class TestInterfaceStats:
    """Test cases for InterfaceStats."""
    
    @pytest.fixture
    def interface_stats_fixture(self, mock_client):
        """Set up test fixtures."""
        interface_stats = InterfaceStats(mock_client)
        return interface_stats
    
    @pytest.mark.unit
    def test_init(self, interface_stats_fixture):
        """Test initialization."""
        assert interface_stats_fixture is not None
        assert interface_stats_fixture.client is not None
    
    @patch('src.stats.network_interfaces.datetime')
    def test_get_interface_data(self, mock_datetime, interface_stats_fixture, mock_client):
        """Test getting interface data."""
        # Mock datetime
        mock_datetime.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
        
        # Mock the execute_on_all_firewalls method
        expected_result = {
            'test-fw': {
                'success': True,
                'data': {
                    'interface_counters': {
                        'ethernet1/1': {
                            'ibytes': '1000',
                            'obytes': '2000',
                            'ipackets': '10',
                            'opackets': '20'
                        }
                    },
                    'timestamp': '2024-01-01T12:00:00'
                },
                'error': None
            }
        }
        mock_client.execute_on_all_firewalls.return_value = expected_result
        
        result = interface_stats_fixture.get_interface_data()
        
        # Verify the result structure
        assert isinstance(result, dict)
        assert 'test-fw' in result
        assert result['test-fw']['success'] is True
        assert 'data' in result['test-fw']
        
        # Verify execute_on_all_firewalls was called
        mock_client.execute_on_all_firewalls.assert_called_once()


class TestGlobalCounters:
    """Test cases for GlobalCounters."""
    
    @pytest.fixture
    def global_counters_fixture(self, mock_client):
        """Set up test fixtures."""
        global_counters = GlobalCounters(mock_client)
        return global_counters
    
    @pytest.mark.unit
    def test_init(self, global_counters_fixture):
        """Test initialization."""
        assert global_counters_fixture is not None
        assert global_counters_fixture.client is not None
    
    @patch('src.stats.global_counters.datetime')
    def test_get_counter_data(self, mock_datetime, global_counters_fixture, mock_client):
        """Test getting global counters data."""
        # Mock datetime
        mock_datetime.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
        
        # Mock the execute_on_all_firewalls method
        expected_result = {
            'test-fw': {
                'success': True,
                'data': {
                    'global_counters': {
                        'global': {
                            'counters': {
                                'entry': [
                                    {
                                        'name': 'pkt_recv',
                                        'value': 24821074,
                                        'rate': 0,
                                        'severity': 'info',
                                        'category': 'packet',
                                        'aspect': 'pktproc',
                                        'desc': 'Packets received',
                                        'id': 17
                                    }
                                ]
                            }
                        }
                    },
                    'timestamp': '2024-01-01T12:00:00'
                },
                'error': None
            }
        }
        mock_client.execute_on_all_firewalls.return_value = expected_result
        
        result = global_counters_fixture.get_counter_data()
        
        # Verify the result structure
        assert isinstance(result, dict)
        assert 'test-fw' in result
        assert result['test-fw']['success'] is True
        assert 'data' in result['test-fw']
        
        # Verify execute_on_all_firewalls was called
        mock_client.execute_on_all_firewalls.assert_called_once()


class TestGlobalProtectStats:
    """Test cases for GlobalProtectStats."""
    
    @pytest.fixture
    def global_protect_stats_fixture(self, mock_client):
        """Set up test fixtures."""
        global_protect_stats = GlobalProtectStats(mock_client)
        return global_protect_stats
    
    @pytest.mark.unit
    def test_init(self, global_protect_stats_fixture):
        """Test initialization."""
        assert global_protect_stats_fixture is not None
        assert global_protect_stats_fixture.client is not None
    
    @patch('src.stats.global_protect.datetime')
    def test_get_global_protect_data(self, mock_datetime, global_protect_stats_fixture, mock_client):
        """Test getting GlobalProtect data."""
        # Mock datetime
        mock_datetime.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
        
        # Mock the execute_on_all_firewalls method
        expected_result = {
            'test-fw': {
                'success': True,
                'data': {
                    'global_protect': {
                        'gateway': {
                            'entry': [
                                {
                                    'name': 'test-gateway',
                                    'connected': 'yes',
                                    'ip': '192.168.1.100'
                                }
                            ]
                        }
                    },
                    'timestamp': '2024-01-01T12:00:00'
                },
                'error': None
            }
        }
        mock_client.execute_on_all_firewalls.return_value = expected_result
        
        result = global_protect_stats_fixture.get_global_protect_data()
        
        # Verify the result structure
        assert isinstance(result, dict)
        assert 'test-fw' in result
        assert result['test-fw']['success'] is True
        assert 'data' in result['test-fw']
        
        # Verify execute_on_all_firewalls was called
        mock_client.execute_on_all_firewalls.assert_called_once()


class TestRoutingStats:
    """Test cases for RoutingStats."""
    
    @pytest.fixture
    def routing_stats_fixture(self, mock_client):
        """Set up test fixtures."""
        routing_stats = RoutingStats(mock_client)
        return routing_stats
    
    @pytest.mark.unit
    def test_init(self, routing_stats_fixture):
        """Test initialization."""
        assert routing_stats_fixture is not None
        assert routing_stats_fixture.client is not None
    
    @patch('src.stats.routing.datetime')
    def test_get_routing_data(self, mock_datetime, routing_stats_fixture, mock_client):
        """Test getting routing data."""
        # Mock datetime
        mock_datetime.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
        
        # Mock the execute_on_all_firewalls method
        expected_result = {
            'test-fw': {
                'success': True,
                'data': {
                    'routing': {
                        'route': {
                            'entry': [
                                {
                                    'destination': '0.0.0.0/0',
                                    'nexthop': '192.168.1.1',
                                    'interface': 'ethernet1/1',
                                    'metric': '10'
                                }
                            ]
                        }
                    },
                    'timestamp': '2024-01-01T12:00:00'
                },
                'error': None
            }
        }
        mock_client.execute_on_all_firewalls.return_value = expected_result
        
        result = routing_stats_fixture.get_routing_data()
        
        # Verify the result structure
        assert isinstance(result, dict)
        assert 'test-fw' in result
        assert result['test-fw']['success'] is True
        assert 'data' in result['test-fw']
        
        # Verify execute_on_all_firewalls was called
        mock_client.execute_on_all_firewalls.assert_called_once()


class TestVpnTunnelStats:
    """Test cases for VpnTunnelStats."""
    
    @pytest.fixture
    def vpn_tunnel_stats_fixture(self, mock_client):
        """Set up test fixtures."""
        vpn_tunnel_stats = VpnTunnelStats(mock_client)
        return vpn_tunnel_stats
    
    @pytest.mark.unit
    def test_init(self, vpn_tunnel_stats_fixture):
        """Test initialization."""
        assert vpn_tunnel_stats_fixture is not None
        assert vpn_tunnel_stats_fixture.client is not None
    
    @patch('src.stats.vpn_tunnels.datetime')
    def test_get_vpn_data(self, mock_datetime, vpn_tunnel_stats_fixture, mock_client):
        """Test getting VPN data."""
        # Mock datetime
        mock_datetime.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
        
        # Mock the execute_on_all_firewalls method
        expected_result = {
            'test-fw': {
                'success': True,
                'data': {
                    'vpn_flows': {
                        'entry': [
                            {
                                'name': 'test-tunnel',
                                'state': 'up',
                                'local_ip': '192.168.1.1',
                                'remote_ip': '192.168.2.1'
                            }
                        ]
                    },
                    'timestamp': '2024-01-01T12:00:00'
                },
                'error': None
            }
        }
        mock_client.execute_on_all_firewalls.return_value = expected_result
        
        result = vpn_tunnel_stats_fixture.get_vpn_data()
        
        # Verify the result structure
        assert isinstance(result, dict)
        assert 'test-fw' in result
        assert result['test-fw']['success'] is True
        assert 'data' in result['test-fw']
        
        # Verify execute_on_all_firewalls was called
        mock_client.execute_on_all_firewalls.assert_called_once()
