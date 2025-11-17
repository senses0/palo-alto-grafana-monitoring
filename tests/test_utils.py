"""Tests for utility modules."""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
import json
import tempfile
import os
from datetime import datetime

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.parsers import parse_json_fields, parse_data_types
from src.utils.validators import DataValidator
from src.utils.logger import get_logger, get_firewall_logger, update_logger_firewall_context
from src.utils.stats_config import StatsCollectionConfig


class TestDataParsers:
    """Test cases for data parsing utilities."""
    
    @pytest.mark.unit
    def test_parse_json_fields(self):
        """Test parsing JSON fields."""
        test_data = {
            'name': 'test',
            'json': '{"key": "value", "number": 123}',
            'nested': {
                'json': '{"nested_key": "nested_value"}'
            }
        }
        
        result = parse_json_fields(test_data)
        
        # Should merge JSON fields into root level
        assert result['name'] == 'test'
        assert result['key'] == 'value'
        assert result['number'] == 123
        assert result['nested']['nested_key'] == 'nested_value'
    
    @pytest.mark.unit
    def test_parse_data_types(self):
        """Test parsing data types."""
        test_data = {
            'count': '123',
            'enabled': 'True',
            'disabled': 'false',
            'nested': {'value': '456', 'active': 'False'},
            'list': ['789', 'True', 'invalid']
        }
        
        result = parse_data_types(test_data)
        
        # Should convert string numbers and booleans
        assert result['count'] == 123
        assert result['enabled'] == True
        assert result['disabled'] == False
        assert result['nested']['value'] == 456
        assert result['nested']['active'] == False
        assert result['list'][0] == 789
        assert result['list'][1] == True
        assert result['list'][2] == 'invalid'  # Should remain string





class TestDataValidator:
    """Test cases for DataValidator utility."""
    
    @pytest.fixture
    def validator_fixture(self):
        """Set up test fixtures."""
        validator = DataValidator()
        return validator
    
    @pytest.mark.unit
    def test_init(self, validator_fixture):
        """Test initialization."""
        assert validator_fixture is not None
    
    @pytest.mark.unit
    def test_validate_ip_address(self, validator_fixture):
        """Test IP address validation."""
        valid_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        invalid_ips = ['256.1.1.1', '192.168.1', '192.168.1.256', 'invalid']
        
        for ip in valid_ips:
            assert validator_fixture.validate_ip_address(ip) is True, f"IP {ip} should be valid"
        
        for ip in invalid_ips:
            assert validator_fixture.validate_ip_address(ip) is False, f"IP {ip} should be invalid"
    
    @pytest.mark.unit
    def test_validate_port(self, validator_fixture):
        """Test port validation."""
        valid_ports = [1, 80, 443, 8080, 65535]
        invalid_ports = [0, 65536, -1, 'invalid']
        
        for port in valid_ports:
            assert validator_fixture.validate_port(port) is True, f"Port {port} should be valid"
        
        for port in invalid_ports:
            assert validator_fixture.validate_port(port) is False, f"Port {port} should be invalid"
    
    @pytest.mark.unit
    def test_validate_api_key(self, validator_fixture):
        """Test API key validation."""
        valid_keys = ['LUFRPT1234567890abcdef', 'test_api_key_123']
        invalid_keys = ['', 'short', None]
        
        for key in valid_keys:
            assert validator_fixture.validate_api_key(key) is True, f"API key {key} should be valid"
        
        for key in invalid_keys:
            assert validator_fixture.validate_api_key(key) is False, f"API key {key} should be invalid"
    
    @pytest.mark.unit
    def test_validate_timestamp(self, validator_fixture):
        """Test timestamp validation."""
        valid_timestamps = [
            '2024-01-01T12:00:00',
            '2024-01-01T12:00:00.123456',
            '2024-01-01 12:00:00'
        ]
        invalid_timestamps = ['invalid', '2024-13-01T12:00:00', '']
        
        for timestamp in valid_timestamps:
            assert validator_fixture.validate_timestamp(timestamp) is True, f"Timestamp {timestamp} should be valid"
        
        for timestamp in invalid_timestamps:
            assert validator_fixture.validate_timestamp(timestamp) is False, f"Timestamp {timestamp} should be invalid"
    
    @pytest.mark.unit
    def test_validate_response_data(self, validator_fixture):
        """Test response data validation."""
        valid_data = {
            'success': True,
            'data': {'key': 'value'},
            'timestamp': '2024-01-01T12:00:00'
        }
        invalid_data = {
            'success': 'not_boolean',
            'data': None,
            'timestamp': 'invalid'
        }
        
        is_valid, errors = validator_fixture.validate_response_data(valid_data)
        assert is_valid is True
        assert len(errors) == 0
        
        is_valid, errors = validator_fixture.validate_response_data(invalid_data)
        assert is_valid is False
        assert len(errors) > 0


class TestLogger:
    """Test cases for logger utilities."""
    
    @pytest.mark.unit
    def test_get_logger(self):
        """Test getting logger."""
        logger = get_logger('test_module')
        assert logger is not None
        assert logger.name == 'test_module'
    
    @pytest.mark.unit
    def test_get_firewall_logger(self):
        """Test getting firewall logger."""
        logger = get_firewall_logger('test_module', 'test_firewall')
        assert logger is not None
        assert 'test_module' in logger.name
    
    @pytest.mark.unit
    def test_update_logger_firewall_context(self):
        """Test updating logger firewall context."""
        logger = get_logger('test_module')
        update_logger_firewall_context(logger, 'test_firewall')
        assert logger is not None


class TestStatsConfig:
    """Test cases for stats configuration."""
    
    @pytest.mark.unit
    def test_stats_collection_config_init(self):
        """Test StatsCollectionConfig initialization."""
        from config.settings import settings
        config = StatsCollectionConfig(settings)
        assert config is not None
    
    @pytest.mark.unit
    def test_stats_collection_config_defaults(self):
        """Test StatsCollectionConfig default values."""
        from config.settings import settings
        config = StatsCollectionConfig(settings)
        assert hasattr(config, 'settings')
        assert hasattr(config, 'stats_config')
    
    @pytest.mark.unit
    def test_stats_collection_config_custom_values(self):
        """Test StatsCollectionConfig with custom values."""
        from config.settings import settings
        config = StatsCollectionConfig(settings)
        assert config is not None
        # Test that we can check if modules are enabled
        assert isinstance(config.is_module_enabled('system'), bool)
