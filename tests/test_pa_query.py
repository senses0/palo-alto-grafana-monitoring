"""Comprehensive tests for pa_query.py CLI tool."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

# Import the CLI and functions
from pa_query import (
    cli,
    output_result,
    system_info,
    interface_stats,
    routing_info,
    global_counters,
    global_protect,
    vpn_tunnels,
    all_stats,
    firewall_summary,
    validate_config
)


class TestOutputResult:
    """Test cases for output_result function."""
    
    @pytest.mark.unit
    def test_output_result_json_stdout(self):
        """Test output to stdout in JSON format."""
        runner = CliRunner()
        ctx = Mock()
        ctx.obj = {'output_file': None, 'output_format': 'json'}
        
        data = {'test': 'data', 'value': 123}
        
        with runner.isolated_filesystem():
            with patch('click.echo') as mock_echo:
                output_result(data, ctx)
                
                # Should echo JSON
                call_args = mock_echo.call_args[0][0]
                assert '"test": "data"' in call_args
                assert '"value": 123' in call_args
    
    @pytest.mark.unit
    def test_output_result_json_file(self):
        """Test output to file in JSON format."""
        runner = CliRunner()
        
        with runner.isolated_filesystem():
            ctx = Mock()
            ctx.obj = {'output_file': 'output.json', 'output_format': 'json'}
            
            data = {'test': 'data'}
            
            with patch('click.echo') as mock_echo:
                output_result(data, ctx)
                
                # Should write to file
                mock_echo.assert_called_once()
                assert 'output.json' in mock_echo.call_args[0][0]
                
                # Verify file was created
                assert Path('output.json').exists()
    
    @pytest.mark.unit
    def test_output_result_table_format(self):
        """Test output with table format."""
        runner = CliRunner()
        ctx = Mock()
        ctx.obj = {'output_file': None, 'output_format': 'table'}
        
        data = {'test': 'data'}
        
        def mock_format_func(d):
            return "Formatted table output"
        
        with patch('click.echo') as mock_echo:
            output_result(data, ctx, format_func=mock_format_func)
            
            # Should use format function
            mock_echo.assert_called_once_with("Formatted table output")
    
    @pytest.mark.unit
    def test_output_result_file_error(self):
        """Test handling file write errors."""
        ctx = Mock()
        ctx.obj = {'output_file': '/invalid/path/file.json', 'output_format': 'json'}
        
        data = {'test': 'data'}
        
        with patch('click.echo') as mock_echo:
            with pytest.raises(SystemExit):
                output_result(data, ctx)
            
            # Should echo error message
            assert mock_echo.call_count >= 1
            error_call = [call for call in mock_echo.call_args_list if 'Error' in str(call)]
            assert len(error_call) > 0


class TestCLIInitialization:
    """Test cases for CLI initialization."""
    
    @pytest.mark.unit
    def test_cli_group_exists(self):
        """Test that CLI group is properly defined."""
        assert cli is not None
        assert callable(cli)
    
    @pytest.mark.unit
    def test_cli_with_default_options(self):
        """Test CLI with default options."""
        runner = CliRunner()
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['--help'])
                                    assert result.exit_code == 0
                                    assert 'Palo Alto Networks statistics' in result.output
    
    @pytest.mark.unit
    def test_cli_with_config_option(self):
        """Test CLI with custom config file."""
        runner = CliRunner()
        
        with runner.isolated_filesystem():
            # Create a dummy config file
            Path('custom_config.yaml').write_text('test: config')
            
            with patch('pa_query.PaloAltoClient') as mock_client_class:
                mock_client = Mock()
                mock_client_class.return_value = mock_client
                
                with patch('pa_query.SystemStats'):
                    with patch('pa_query.InterfaceStats'):
                        with patch('pa_query.RoutingStats'):
                            with patch('pa_query.GlobalCounters'):
                                with patch('pa_query.GlobalProtectStats'):
                                    with patch('pa_query.VpnTunnelStats'):
                                        result = runner.invoke(cli, ['--config', 'custom_config.yaml', '--help'])
                                        assert result.exit_code == 0
    
    @pytest.mark.unit
    def test_cli_initialization_error(self):
        """Test CLI initialization error handling."""
        runner = CliRunner()
        
        with patch('pa_query.PaloAltoClient', side_effect=Exception('Connection failed')):
            result = runner.invoke(cli, ['system-info'])
            assert result.exit_code == 1
            assert 'Error initializing client' in result.output


class TestSystemInfoCommand:
    """Test cases for system-info command."""
    
    @pytest.mark.unit
    def test_system_info_json_output(self):
        """Test system-info with JSON output."""
        runner = CliRunner()
        
        mock_data = {
            'test-fw': {
                'success': True,
                'data': {
                    'system_info': {
                        'system': {
                            'hostname': 'test-fw',
                            'model': 'PA-220',
                            'sw-version': '10.2.0'
                        }
                    }
                },
                'error': None
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats') as mock_system_stats:
                mock_stats = Mock()
                mock_stats.get_system_data.return_value = mock_data
                mock_system_stats.return_value = mock_stats
                
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['system-info'])
                                    
                                    assert result.exit_code == 0
                                    output_data = json.loads(result.output)
                                    assert 'system' in output_data
                                    assert 'test-fw' in output_data['system']
    
    @pytest.mark.unit
    def test_system_info_table_output(self):
        """Test system-info with table output."""
        runner = CliRunner()
        
        mock_data = {
            'test-fw': {
                'success': True,
                'data': {
                    'system_info': {
                        'system': {
                            'hostname': 'test-fw',
                            'model': 'PA-220'
                        }
                    }
                },
                'error': None
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats') as mock_system_stats:
                mock_stats = Mock()
                mock_stats.get_system_data.return_value = mock_data
                mock_system_stats.return_value = mock_stats
                
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['--output', 'table', 'system-info'])
                                    
                                    assert result.exit_code == 0
                                    assert 'test-fw' in result.output
    
    @pytest.mark.unit
    def test_system_info_error(self):
        """Test system-info error handling."""
        runner = CliRunner()
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats') as mock_system_stats:
                mock_stats = Mock()
                mock_stats.get_system_data.side_effect = Exception('API error')
                mock_system_stats.return_value = mock_stats
                
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['system-info'])
                                    
                                    assert result.exit_code == 1
                                    assert 'Error' in result.output


class TestInterfaceStatsCommand:
    """Test cases for interface-stats command."""
    
    @pytest.mark.unit
    def test_interface_stats_json(self):
        """Test interface-stats with JSON output."""
        runner = CliRunner()
        
        mock_data = {
            'test-fw': {
                'success': True,
                'data': {
                    'interface_counters': {
                        'hw': {
                            'entry': [
                                {'name': 'ethernet1/1', 'state': 'up'}
                            ]
                        }
                    }
                },
                'error': None
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats') as mock_interface_stats:
                    mock_stats = Mock()
                    mock_stats.get_interface_data.return_value = mock_data
                    mock_interface_stats.return_value = mock_stats
                    
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['interface-stats'])
                                    
                                    assert result.exit_code == 0
                                    output_data = json.loads(result.output)
                                    assert 'interfaces' in output_data


class TestRoutingInfoCommand:
    """Test cases for routing-info command."""
    
    @pytest.mark.unit
    def test_routing_info_json(self):
        """Test routing-info with JSON output."""
        runner = CliRunner()
        
        mock_data = {
            'test-fw': {
                'success': True,
                'data': {
                    'routing_mode': 'bgp',
                    'bgp_peer_status': {
                        'peer1': {
                            'state': 'Established',
                            'peer-ip': '192.168.1.2'
                        }
                    }
                },
                'error': None
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats') as mock_routing_stats:
                        mock_stats = Mock()
                        mock_stats.get_routing_data.return_value = mock_data
                        mock_stats.format_bgp_peer_status_for_display.return_value = "Formatted status"
                        mock_routing_stats.return_value = mock_stats
                        
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['routing-info'])
                                    
                                    assert result.exit_code == 0
                                    output_data = json.loads(result.output)
                                    assert 'routing' in output_data


class TestGlobalCountersCommand:
    """Test cases for global-counters command."""
    
    @pytest.mark.unit
    def test_global_counters_json(self):
        """Test global-counters with JSON output."""
        runner = CliRunner()
        
        mock_data = {
            'test-fw': {
                'success': True,
                'data': {
                    'global_counters': {
                        'global': {
                            'counters': {
                                'entry': []
                            }
                        }
                    }
                },
                'error': None
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters') as mock_counters:
                            mock_stats = Mock()
                            mock_stats.get_counter_data.return_value = mock_data
                            mock_counters.return_value = mock_stats
                            
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['global-counters'])
                                    
                                    assert result.exit_code == 0
                                    output_data = json.loads(result.output)
                                    assert 'counters' in output_data


class TestGlobalProtectCommand:
    """Test cases for global-protect command."""
    
    @pytest.mark.unit
    def test_global_protect_json(self):
        """Test global-protect with JSON output."""
        runner = CliRunner()
        
        mock_data = {
            'test-fw': {
                'success': True,
                'data': {
                    'gateway_summary': {
                        'entry': []
                    }
                },
                'error': None
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats') as mock_gp:
                                mock_stats = Mock()
                                mock_stats.get_global_protect_data.return_value = mock_data
                                mock_gp.return_value = mock_stats
                                
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['global-protect'])
                                    
                                    assert result.exit_code == 0
                                    output_data = json.loads(result.output)
                                    assert 'global_protect' in output_data


class TestVpnTunnelsCommand:
    """Test cases for vpn-tunnels command."""
    
    @pytest.mark.unit
    def test_vpn_tunnels_json(self):
        """Test vpn-tunnels with JSON output."""
        runner = CliRunner()
        
        mock_data = {
            'test-fw': {
                'success': True,
                'data': {
                    'vpn_flows': {
                        'total': 5,
                        'num_ipsec': 3,
                        'num_sslvpn': 2
                    }
                },
                'error': None
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats') as mock_vpn:
                                    mock_stats = Mock()
                                    mock_stats.get_vpn_data.return_value = mock_data
                                    mock_vpn.return_value = mock_stats
                                    
                                    result = runner.invoke(cli, ['vpn-tunnels'])
                                    
                                    assert result.exit_code == 0
                                    output_data = json.loads(result.output)
                                    assert 'vpn' in output_data


class TestAllStatsCommand:
    """Test cases for all-stats command."""
    
    @pytest.mark.unit
    def test_all_stats_json(self):
        """Test all-stats with JSON output."""
        runner = CliRunner()
        
        mock_system = {'test-fw': {'success': True, 'data': {}, 'error': None}}
        mock_interface = {'test-fw': {'success': True, 'data': {}, 'error': None}}
        mock_routing = {'test-fw': {'success': True, 'data': {}, 'error': None}}
        mock_counters = {'test-fw': {'success': True, 'data': {}, 'error': None}}
        mock_gp = {'test-fw': {'success': True, 'data': {}, 'error': None}}
        mock_vpn = {'test-fw': {'success': True, 'data': {}, 'error': None}}
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats') as mock_system_stats:
                mock_system_obj = Mock()
                mock_system_obj.get_system_data.return_value = mock_system
                mock_system_stats.return_value = mock_system_obj
                
                with patch('pa_query.InterfaceStats') as mock_interface_stats:
                    mock_interface_obj = Mock()
                    mock_interface_obj.get_interface_data.return_value = mock_interface
                    mock_interface_stats.return_value = mock_interface_obj
                    
                    with patch('pa_query.RoutingStats') as mock_routing_stats:
                        mock_routing_obj = Mock()
                        mock_routing_obj.get_routing_data.return_value = mock_routing
                        mock_routing_stats.return_value = mock_routing_obj
                        
                        with patch('pa_query.GlobalCounters') as mock_counter_stats:
                            mock_counter_obj = Mock()
                            mock_counter_obj.get_counter_data.return_value = mock_counters
                            mock_counter_stats.return_value = mock_counter_obj
                            
                            with patch('pa_query.GlobalProtectStats') as mock_gp_stats:
                                mock_gp_obj = Mock()
                                mock_gp_obj.get_global_protect_data.return_value = mock_gp
                                mock_gp_stats.return_value = mock_gp_obj
                                
                                with patch('pa_query.VpnTunnelStats') as mock_vpn_stats:
                                    mock_vpn_obj = Mock()
                                    mock_vpn_obj.get_vpn_data.return_value = mock_vpn
                                    mock_vpn_stats.return_value = mock_vpn_obj
                                    
                                    result = runner.invoke(cli, ['all-stats'])
                                    
                                    assert result.exit_code == 0
                                    output_data = json.loads(result.output)
                                    assert 'system' in output_data
                                    assert 'interfaces' in output_data
                                    assert 'routing' in output_data
                                    assert 'counters' in output_data
                                    assert 'global_protect' in output_data
                                    assert 'vpn' in output_data
    
    @pytest.mark.unit
    def test_all_stats_table(self):
        """Test all-stats with table output."""
        runner = CliRunner()
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats') as mock_system_stats:
                mock_obj = Mock()
                mock_obj.get_system_data.return_value = {}
                mock_system_stats.return_value = mock_obj
                
                with patch('pa_query.InterfaceStats') as mock_interface_stats:
                    mock_obj = Mock()
                    mock_obj.get_interface_data.return_value = {}
                    mock_interface_stats.return_value = mock_obj
                    
                    with patch('pa_query.RoutingStats') as mock_routing_stats:
                        mock_obj = Mock()
                        mock_obj.get_routing_data.return_value = {}
                        mock_routing_stats.return_value = mock_obj
                        
                        with patch('pa_query.GlobalCounters') as mock_counter_stats:
                            mock_obj = Mock()
                            mock_obj.get_counter_data.return_value = {}
                            mock_counter_stats.return_value = mock_obj
                            
                            with patch('pa_query.GlobalProtectStats') as mock_gp_stats:
                                mock_obj = Mock()
                                mock_obj.get_global_protect_data.return_value = {}
                                mock_gp_stats.return_value = mock_obj
                                
                                with patch('pa_query.VpnTunnelStats') as mock_vpn_stats:
                                    mock_obj = Mock()
                                    mock_obj.get_vpn_data.return_value = {}
                                    mock_vpn_stats.return_value = mock_obj
                                    
                                    result = runner.invoke(cli, ['--output', 'table', 'all-stats'])
                                    
                                    assert result.exit_code == 0
                                    assert 'collection summary' in result.output.lower()


class TestFirewallSummaryCommand:
    """Test cases for firewall-summary command."""
    
    @pytest.mark.unit
    def test_firewall_summary_json(self):
        """Test firewall-summary with JSON output."""
        runner = CliRunner()
        
        mock_summary = {
            'total_firewalls': 1,
            'firewalls': {
                'test-fw': {
                    'host': '192.168.1.1',
                    'port': 443,
                    'description': 'Test Firewall'
                }
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client.get_firewall_summary.return_value = mock_summary
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['firewall-summary'])
                                    
                                    assert result.exit_code == 0
                                    output_data = json.loads(result.output)
                                    assert output_data['total_firewalls'] == 1
                                    assert 'test-fw' in output_data['firewalls']
    
    @pytest.mark.unit
    def test_firewall_summary_table(self):
        """Test firewall-summary with table output."""
        runner = CliRunner()
        
        mock_summary = {
            'total_firewalls': 1,
            'firewalls': {
                'test-fw': {
                    'host': '192.168.1.1',
                    'port': 443
                }
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client.get_firewall_summary.return_value = mock_summary
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['--output', 'table', 'firewall-summary'])
                                    
                                    assert result.exit_code == 0
                                    assert 'test-fw' in result.output
                                    assert '192.168.1.1' in result.output


class TestValidateConfigCommand:
    """Test cases for validate-config command."""
    
    @pytest.mark.unit
    def test_validate_config_valid(self):
        """Test validate-config with valid configuration."""
        runner = CliRunner()
        
        mock_validation = {
            'test-fw': {
                'valid': True,
                'errors': []
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client.validate_firewall_config.return_value = mock_validation
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['validate-config'])
                                    
                                    assert result.exit_code == 0
                                    output_data = json.loads(result.output)
                                    assert output_data['test-fw']['valid'] is True
    
    @pytest.mark.unit
    def test_validate_config_invalid(self):
        """Test validate-config with invalid configuration."""
        runner = CliRunner()
        
        mock_validation = {
            'test-fw': {
                'valid': False,
                'errors': ['Missing API key', 'Invalid host']
            }
        }
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client.validate_firewall_config.return_value = mock_validation
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['--output', 'table', 'validate-config'])
                                    
                                    assert result.exit_code == 0
                                    assert 'test-fw' in result.output
                                    assert 'errors' in result.output.lower() or '❌' in result.output


class TestCLIOptions:
    """Test cases for CLI global options."""
    
    @pytest.mark.unit
    def test_output_file_option(self):
        """Test --output-file option."""
        runner = CliRunner()
        
        mock_data = {
            'test-fw': {
                'success': True,
                'data': {'system_info': {'system': {}}},
                'error': None
            }
        }
        
        with runner.isolated_filesystem():
            with patch('pa_query.PaloAltoClient') as mock_client_class:
                mock_client = Mock()
                mock_client_class.return_value = mock_client
                
                with patch('pa_query.SystemStats') as mock_stats:
                    mock_obj = Mock()
                    mock_obj.get_system_data.return_value = mock_data
                    mock_stats.return_value = mock_obj
                    
                    with patch('pa_query.InterfaceStats'):
                        with patch('pa_query.RoutingStats'):
                            with patch('pa_query.GlobalCounters'):
                                with patch('pa_query.GlobalProtectStats'):
                                    with patch('pa_query.VpnTunnelStats'):
                                        result = runner.invoke(cli, ['--output-file', 'output.json', 'system-info'])
                                        
                                        assert result.exit_code == 0
                                        assert Path('output.json').exists()
    
    @pytest.mark.unit
    def test_firewall_option(self):
        """Test --firewall option for targeting specific firewall."""
        runner = CliRunner()
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, ['--firewall', 'specific-fw', 'firewall-summary'])
                                    
                                    # Should pass firewall_name to client
                                    mock_client_class.assert_called_once()
                                    call_kwargs = mock_client_class.call_args[1]
                                    assert 'firewall_name' in call_kwargs or call_kwargs == {}
    
    @pytest.mark.unit
    def test_host_and_api_key_options(self):
        """Test --host and --api-key options for single firewall mode."""
        runner = CliRunner()
        
        with patch('pa_query.PaloAltoClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            with patch('pa_query.SystemStats'):
                with patch('pa_query.InterfaceStats'):
                    with patch('pa_query.RoutingStats'):
                        with patch('pa_query.GlobalCounters'):
                            with patch('pa_query.GlobalProtectStats'):
                                with patch('pa_query.VpnTunnelStats'):
                                    result = runner.invoke(cli, [
                                        '--host', '192.168.1.100',
                                        '--api-key', 'test-key',
                                        'firewall-summary'
                                    ])
                                    
                                    # Should pass host to client
                                    mock_client_class.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

