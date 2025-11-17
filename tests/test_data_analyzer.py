"""Comprehensive tests for data_analyzer.py."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
import sys
import io

from data_analyzer import (
    InfluxDBSchemaProposal,
    ComprehensiveDataAnalyzer,
    main
)


class TestInfluxDBSchemaProposal:
    """Test cases for InfluxDBSchemaProposal class."""
    
    @pytest.mark.unit
    def test_initialization(self):
        """Test schema proposal initialization."""
        proposal = InfluxDBSchemaProposal(
            'test_measurement',
            'Test description',
            'test_category'
        )
        
        assert proposal.measurement == 'test_measurement'
        assert proposal.description == 'Test description'
        assert proposal.category == 'test_category'
        assert proposal.tags == {}
        assert proposal.fields == {}
        assert proposal.cardinality == "low"
    
    @pytest.mark.unit
    def test_add_tag(self):
        """Test adding tag to schema proposal."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        proposal.add_tag('host', 'server1', 'Server hostname')
        
        assert 'host' in proposal.tags
        assert proposal.tags['host']['example'] == 'server1'
        assert proposal.tags['host']['type'] == 'string'
        assert proposal.tags['host']['description'] == 'Server hostname'
    
    @pytest.mark.unit
    def test_add_field(self):
        """Test adding field to schema proposal."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        proposal.add_field('cpu_usage', 45.5, '%', 'CPU usage percentage')
        
        assert 'cpu_usage' in proposal.fields
        assert proposal.fields['cpu_usage']['example'] == 45.5
        assert proposal.fields['cpu_usage']['type'] == 'float'
        assert proposal.fields['cpu_usage']['unit'] == '%'
        assert proposal.fields['cpu_usage']['description'] == 'CPU usage percentage'
    
    @pytest.mark.unit
    def test_get_data_type_boolean(self):
        """Test data type detection for boolean."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        assert proposal._get_data_type(True) == 'boolean'
        assert proposal._get_data_type(False) == 'boolean'
    
    @pytest.mark.unit
    def test_get_data_type_integer(self):
        """Test data type detection for integer."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        assert proposal._get_data_type(42) == 'integer'
        assert proposal._get_data_type(0) == 'integer'
    
    @pytest.mark.unit
    def test_get_data_type_float(self):
        """Test data type detection for float."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        assert proposal._get_data_type(3.14) == 'float'
        assert proposal._get_data_type(0.0) == 'float'
    
    @pytest.mark.unit
    def test_get_data_type_string(self):
        """Test data type detection for string."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        assert proposal._get_data_type('test') == 'string'
        assert proposal._get_data_type('') == 'string'
    
    @pytest.mark.unit
    def test_to_dict(self):
        """Test converting proposal to dictionary."""
        proposal = InfluxDBSchemaProposal('test_measurement', 'Test desc', 'test_cat')
        proposal.add_tag('host', 'server1')
        proposal.add_field('value', 100)
        proposal.notes.append('Test note')
        
        result = proposal.to_dict()
        
        assert result['measurement'] == 'test_measurement'
        assert result['description'] == 'Test desc'
        assert result['category'] == 'test_cat'
        assert 'host' in result['tags']
        assert 'value' in result['fields']
        assert 'Test note' in result['notes']


class TestComprehensiveDataAnalyzer:
    """Test cases for ComprehensiveDataAnalyzer class."""
    
    @pytest.fixture
    def sample_system_data(self):
        """Provide sample system data for testing."""
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
                                'serial': '012345678901',
                                'sw-version': '10.2.0',
                                'vm-cores': 4,
                                'vm-mem': 8192,
                                '_uptime_seconds': 86400
                            }
                        },
                        'resource_usage': {
                            'cpu_user': 10.0,
                            'cpu_idle': 80.0,
                            'memory_total_mib': 8192,
                            'memory_usage_percent': 50.0
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
                    }
                }
            }
        }
    
    @pytest.fixture
    def sample_interface_data(self):
        """Provide sample interface data."""
        return {
            'interfaces': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'interface_info': {
                            'hw': {
                                'entry': [
                                    {
                                        'name': 'ethernet1/1',
                                        'type': 'Ethernet',
                                        'state': 'up',
                                        'speed': 1000
                                    }
                                ]
                            },
                            'ifnet': {
                                'entry': [
                                    {
                                        'name': 'ethernet1/1',
                                        'zone': 'trust',
                                        'ip': '192.168.1.1/24'
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
                                            'rx-bytes': 1000,
                                            'tx-bytes': 2000
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }
    
    @pytest.mark.unit
    def test_initialization(self, sample_system_data):
        """Test analyzer initialization."""
        analyzer = ComprehensiveDataAnalyzer(sample_system_data)
        
        assert analyzer.data == sample_system_data
        assert analyzer.proposals == []
    
    @pytest.mark.unit
    def test_analyze_system_module(self, sample_system_data):
        """Test analyzing system module."""
        analyzer = ComprehensiveDataAnalyzer(sample_system_data)
        analyzer.analyze_system_module()
        
        # Should create multiple proposals for system module
        assert len(analyzer.proposals) > 0
        
        # Check for system identity proposal
        identity_proposal = [p for p in analyzer.proposals if 'system_identity' in p.measurement]
        assert len(identity_proposal) > 0
        
        # Check for CPU usage proposal
        cpu_proposal = [p for p in analyzer.proposals if 'cpu_usage' in p.measurement]
        assert len(cpu_proposal) > 0
    
    @pytest.mark.unit
    def test_analyze_interface_module(self, sample_interface_data):
        """Test analyzing interface module."""
        analyzer = ComprehensiveDataAnalyzer(sample_interface_data)
        analyzer.analyze_interface_module()
        
        # Should create proposals for interface module
        assert len(analyzer.proposals) > 0
        
        # Check for interface info proposal
        info_proposal = [p for p in analyzer.proposals if 'interface_info' in p.measurement]
        assert len(info_proposal) > 0
    
    @pytest.mark.unit
    def test_analyze_routing_module(self):
        """Test analyzing routing module."""
        routing_data = {
            'routing': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'bgp_peer_status': {
                            'peer1': {
                                'peer-ip': '192.168.1.2',
                                'state': 'Established',
                                'remote-as': 65001
                            }
                        },
                        'routing_table': {
                            'default': {
                                '0.0.0.0/0': [
                                    {'protocol': 'static'}
                                ],
                                '10.0.0.0/8': [
                                    {'protocol': 'bgp'}
                                ]
                            }
                        }
                    }
                }
            }
        }
        
        analyzer = ComprehensiveDataAnalyzer(routing_data)
        analyzer.analyze_routing_module()
        
        # Should create proposals for routing
        assert len(analyzer.proposals) > 0
        
        # Check for BGP peer proposal
        peer_proposal = [p for p in analyzer.proposals if 'bgp_peer' in p.measurement]
        assert len(peer_proposal) > 0
    
    @pytest.mark.unit
    def test_analyze_counters_module(self):
        """Test analyzing counters module."""
        counters_data = {
            'counters': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'global_counters': {
                            'global': {
                                'counters': {
                                    'entry': [
                                        {'name': 'pkt_recv', 'value': 1000, 'category': 'packet'},
                                        {'name': 'pkt_sent', 'value': 2000, 'category': 'packet'},
                                        {'name': 'pkt_dropped', 'value': 50, 'category': 'packet'},
                                        {'name': 'pkt_error', 'value': 10, 'category': 'packet'},
                                        {'name': 'pkt_broadcast', 'value': 100, 'category': 'packet'},
                                        {'name': 'pkt_multicast', 'value': 200, 'category': 'packet'},
                                        {'name': 'session_active', 'value': 100, 'category': 'session'},
                                        {'name': 'session_max', 'value': 500, 'category': 'session'},
                                        {'name': 'session_total', 'value': 450, 'category': 'session'},
                                        {'name': 'session_used', 'value': 400, 'category': 'session'},
                                        {'name': 'session_util', 'value': 80, 'category': 'session'},
                                        {'name': 'session_aged', 'value': 50, 'category': 'session'}
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        }
        
        analyzer = ComprehensiveDataAnalyzer(counters_data)
        analyzer.analyze_counters_module()
        
        # Should create proposals for counters (requires 5+ entries per category)
        assert len(analyzer.proposals) > 0
    
    @pytest.mark.unit
    def test_analyze_globalprotect_module(self):
        """Test analyzing GlobalProtect module."""
        gp_data = {
            'global_protect': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'gateway_summary': {
                            'entry': [
                                {
                                    'name': 'gp-gateway',
                                    'CurrentUsers': 10
                                }
                            ]
                        },
                        'portal_summary': {
                            'entry': [
                                {
                                    'name': 'gp-portal',
                                    'successful_connections': 100
                                }
                            ]
                        }
                    }
                }
            }
        }
        
        analyzer = ComprehensiveDataAnalyzer(gp_data)
        analyzer.analyze_globalprotect_module()
        
        # Should create proposals for GlobalProtect
        assert len(analyzer.proposals) > 0
    
    @pytest.mark.unit
    def test_analyze_vpn_module(self):
        """Test analyzing VPN module."""
        vpn_data = {
            'vpn': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'vpn_flows': {
                            'num_ipsec': 5,
                            'num_sslvpn': 3,
                            'total': 8
                        }
                    }
                }
            }
        }
        
        analyzer = ComprehensiveDataAnalyzer(vpn_data)
        analyzer.analyze_vpn_module()
        
        # Should create proposals for VPN
        assert len(analyzer.proposals) > 0
        
        # Check for VPN flows proposal
        flows_proposal = [p for p in analyzer.proposals if 'vpn_flows' in p.measurement]
        assert len(flows_proposal) > 0
    
    @pytest.mark.unit
    def test_analyze_all(self, sample_system_data):
        """Test analyzing all modules."""
        analyzer = ComprehensiveDataAnalyzer(sample_system_data)
        analyzer.analyze_all()
        
        # Should analyze system module at minimum
        assert len(analyzer.proposals) > 0
    
    @pytest.mark.unit
    def test_generate_summary(self, sample_system_data):
        """Test generating analysis summary."""
        analyzer = ComprehensiveDataAnalyzer(sample_system_data)
        analyzer.analyze_all()
        
        summary = analyzer.generate_summary()
        
        assert 'total_measurements' in summary
        assert 'measurements_by_category' in summary
        assert 'total_tags' in summary
        assert 'total_fields' in summary
        assert summary['total_measurements'] > 0
    
    @pytest.mark.unit
    def test_export_schema(self, sample_system_data, tmp_path):
        """Test exporting schema to JSON."""
        analyzer = ComprehensiveDataAnalyzer(sample_system_data)
        analyzer.analyze_all()
        
        output_file = tmp_path / "schema.json"
        analyzer.export_schema(str(output_file))
        
        assert output_file.exists()
        
        # Verify JSON structure
        with open(output_file, 'r') as f:
            schema = json.load(f)
        
        assert 'version' in schema
        assert 'measurements' in schema
        assert 'total_unique_measurements' in schema
        assert len(schema['measurements']) > 0
    
    @pytest.mark.unit
    @patch('data_analyzer.RICH_AVAILABLE', False)
    def test_print_summary_without_rich(self, sample_system_data, capsys):
        """Test printing summary without rich library."""
        analyzer = ComprehensiveDataAnalyzer(sample_system_data)
        analyzer.analyze_all()
        
        analyzer.print_summary()
        
        captured = capsys.readouterr()
        assert 'ANALYSIS SUMMARY' in captured.out or 'Analysis Summary' in captured.out
    
    @pytest.mark.unit
    @patch('data_analyzer.RICH_AVAILABLE', True)
    def test_print_proposal_with_rich(self, sample_system_data):
        """Test printing proposal with rich formatting."""
        analyzer = ComprehensiveDataAnalyzer(sample_system_data)
        analyzer.analyze_all()
        
        if analyzer.proposals:
            # Should not raise exception
            analyzer.print_proposal(analyzer.proposals[0], 1)
    
    @pytest.mark.unit
    @patch('data_analyzer.RICH_AVAILABLE', False)
    def test_print_proposal_without_rich(self, sample_system_data, capsys):
        """Test printing proposal without rich formatting."""
        analyzer = ComprehensiveDataAnalyzer(sample_system_data)
        analyzer.analyze_all()
        
        if analyzer.proposals:
            analyzer.print_proposal(analyzer.proposals[0], 1)
            
            captured = capsys.readouterr()
            assert len(captured.out) > 0
    
    @pytest.mark.unit
    def test_run_analysis(self, sample_system_data, tmp_path, capsys):
        """Test running complete analysis."""
        analyzer = ComprehensiveDataAnalyzer(sample_system_data)
        
        output_file = tmp_path / "schema.json"
        analyzer.run_analysis(export_file=str(output_file))
        
        # Should export file
        assert output_file.exists()
        
        # Should print output
        captured = capsys.readouterr()
        assert len(captured.out) > 0


class TestMainFunction:
    """Test cases for main CLI function."""
    
    @pytest.mark.unit
    def test_main_with_valid_file(self, tmp_path):
        """Test main function with valid input file."""
        # Create test input file
        input_file = tmp_path / "test_input.json"
        test_data = {
            'system': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'system_info': {'system': {'hostname': 'test'}},
                        'resource_usage': {'cpu_idle': 80}
                    }
                }
            }
        }
        input_file.write_text(json.dumps(test_data))
        
        # Run main
        with patch('sys.argv', ['data_analyzer.py', str(input_file)]):
            with patch('sys.exit') as mock_exit:
                main()
                # Should not exit with error
                assert not mock_exit.called or mock_exit.call_args[0][0] == 0
    
    @pytest.mark.unit
    def test_main_with_export(self, tmp_path):
        """Test main function with export option."""
        # Create test input file
        input_file = tmp_path / "test_input.json"
        test_data = {
            'system': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'system_info': {'system': {'hostname': 'test'}},
                        'resource_usage': {'cpu_idle': 80}
                    }
                }
            }
        }
        input_file.write_text(json.dumps(test_data))
        
        output_file = tmp_path / "schema.json"
        
        # Run main with export
        with patch('sys.argv', ['data_analyzer.py', str(input_file), '--export', str(output_file)]):
            main()
        
        # Verify export file was created
        assert output_file.exists()
    
    @pytest.mark.unit
    def test_main_with_missing_file(self, capsys):
        """Test main function with missing input file."""
        with patch('sys.argv', ['data_analyzer.py', 'nonexistent.json']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 1
            
            captured = capsys.readouterr()
            assert 'not found' in captured.err.lower()
    
    @pytest.mark.unit
    def test_main_with_invalid_json(self, tmp_path, capsys):
        """Test main function with invalid JSON file."""
        # Create invalid JSON file
        input_file = tmp_path / "invalid.json"
        input_file.write_text("{ invalid json content")
        
        with patch('sys.argv', ['data_analyzer.py', str(input_file)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 1
            
            captured = capsys.readouterr()
            assert 'invalid json' in captured.err.lower() or 'error' in captured.err.lower()
    
    @pytest.mark.unit
    def test_main_default_filename(self, tmp_path):
        """Test main function with positional argument."""
        # Create input file
        input_file = tmp_path / "complete_stats.json"
        test_data = {
            'system': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'system_info': {'system': {}},
                        'resource_usage': {}
                    }
                }
            }
        }
        input_file.write_text(json.dumps(test_data))
        
        # Test with positional argument
        with patch('sys.argv', ['data_analyzer.py', str(input_file)]):
            main()


class TestDataAnalyzerEdgeCases:
    """Test cases for edge cases and error handling."""
    
    @pytest.mark.unit
    def test_analyze_empty_data(self):
        """Test analyzing empty data."""
        analyzer = ComprehensiveDataAnalyzer({})
        analyzer.analyze_all()
        
        # Should handle empty data gracefully
        assert analyzer.proposals == []
    
    @pytest.mark.unit
    def test_analyze_data_with_failed_firewall(self):
        """Test analyzing data with failed firewall."""
        data = {
            'system': {
                'test-fw': {
                    'success': False,
                    'data': None,
                    'error': 'Connection failed'
                }
            }
        }
        
        analyzer = ComprehensiveDataAnalyzer(data)
        analyzer.analyze_all()
        
        # Should skip failed firewalls
        assert len(analyzer.proposals) == 0
    
    @pytest.mark.unit
    def test_analyze_partial_data(self):
        """Test analyzing data with partial information."""
        data = {
            'system': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'system_info': {
                            'system': {
                                'hostname': 'test'
                                # Missing most fields
                            }
                        }
                        # Missing resource_usage, disk_usage, etc.
                    }
                }
            }
        }
        
        analyzer = ComprehensiveDataAnalyzer(data)
        analyzer.analyze_all()
        
        # Should handle partial data
        assert len(analyzer.proposals) > 0
    
    @pytest.mark.unit
    def test_proposal_with_none_values(self):
        """Test proposal with None values in tags and fields."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        proposal.add_tag('key1', None)
        proposal.add_field('field1', None)
        
        result = proposal.to_dict()
        
        # Should include None values
        assert 'key1' in result['tags']
        assert 'field1' in result['fields']
    
    @pytest.mark.unit
    def test_routing_data_fallback_logic(self):
        """Test routing module fallback logic."""
        # Data with static_routes and bgp_routes but no routing_table
        data = {
            'routing': {
                'test-fw': {
                    'success': True,
                    'data': {
                        'static_routes': {
                            'default': {
                                '0.0.0.0/0': [{}]
                            }
                        },
                        'bgp_routes': {
                            'default': {
                                '10.0.0.0/8': [{}]
                            }
                        }
                    }
                }
            }
        }
        
        analyzer = ComprehensiveDataAnalyzer(data)
        analyzer.analyze_routing_module()
        
        # Should create fallback proposals
        assert len(analyzer.proposals) > 0


class TestSchemaProposalTypes:
    """Test cases for different data types in schema proposals."""
    
    @pytest.mark.unit
    def test_add_boolean_field(self):
        """Test adding boolean field."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        proposal.add_field('enabled', True)
        
        assert proposal.fields['enabled']['type'] == 'boolean'
    
    @pytest.mark.unit
    def test_add_integer_field(self):
        """Test adding integer field."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        proposal.add_field('count', 100)
        
        assert proposal.fields['count']['type'] == 'integer'
    
    @pytest.mark.unit
    def test_add_float_field(self):
        """Test adding float field."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        proposal.add_field('percentage', 45.7)
        
        assert proposal.fields['percentage']['type'] == 'float'
    
    @pytest.mark.unit
    def test_add_string_field(self):
        """Test adding string field."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        proposal.add_field('name', 'test-value')
        
        assert proposal.fields['name']['type'] == 'string'
    
    @pytest.mark.unit
    def test_mixed_type_tags_and_fields(self):
        """Test proposal with mixed types."""
        proposal = InfluxDBSchemaProposal('test', 'desc', 'cat')
        proposal.add_tag('host', 'server1')
        proposal.add_tag('zone', 'us-east-1')
        proposal.add_field('active', True)
        proposal.add_field('count', 42)
        proposal.add_field('percentage', 75.5)
        proposal.add_field('status', 'running')
        
        result = proposal.to_dict()
        
        assert len(result['tags']) == 2
        assert len(result['fields']) == 4


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

