"""Tests for system statistics module."""

import pytest
from unittest.mock import Mock, patch
from src.stats.system import SystemStats


class TestSystemStats:
    """Test cases for SystemStats class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.system_stats = SystemStats(self.mock_client)
    
    def test_convert_uptime_to_seconds_with_days(self):
        """Test uptime conversion with days."""
        uptime_str = "18 days, 22:03:09"
        expected_seconds = (18 * 24 * 3600) + (22 * 3600) + (3 * 60) + 9  # 1634589
        result = self.system_stats._convert_uptime_to_seconds(uptime_str)
        assert result == expected_seconds
    
    def test_convert_uptime_to_seconds_without_days(self):
        """Test uptime conversion without days."""
        uptime_str = "22:03:09"
        expected_seconds = (22 * 3600) + (3 * 60) + 9  # 79389
        result = self.system_stats._convert_uptime_to_seconds(uptime_str)
        assert result == expected_seconds
    
    def test_convert_uptime_to_seconds_single_day(self):
        """Test uptime conversion with single day."""
        uptime_str = "1 day, 22:03:09"
        expected_seconds = (1 * 24 * 3600) + (22 * 3600) + (3 * 60) + 9  # 169389
        result = self.system_stats._convert_uptime_to_seconds(uptime_str)
        assert result == expected_seconds
    
    def test_convert_uptime_to_seconds_empty_string(self):
        """Test uptime conversion with empty string."""
        result = self.system_stats._convert_uptime_to_seconds("")
        assert result == 0
    
    def test_convert_uptime_to_seconds_none(self):
        """Test uptime conversion with None."""
        result = self.system_stats._convert_uptime_to_seconds(None)
        assert result == 0
    
    def test_convert_uptime_to_seconds_invalid_format(self):
        """Test uptime conversion with invalid format."""
        result = self.system_stats._convert_uptime_to_seconds("invalid format")
        assert result == 0
    
    @patch('src.stats.system.logger')
    def test_convert_uptime_to_seconds_logs_warning_on_invalid_format(self, mock_logger):
        """Test that warning is logged for invalid uptime format."""
        self.system_stats._convert_uptime_to_seconds("invalid format")
        mock_logger.warning.assert_called_once()
    
    def test_get_system_data_adds_uptime_seconds(self):
        """Test that _uptime_seconds is added to system info."""
        # Mock the client response
        mock_response = {
            'result': {
                'system': {
                    'uptime': '18 days, 22:03:09',
                    'hostname': 'test-firewall'
                }
            }
        }
        
        self.mock_client.execute_operational_command.return_value = mock_response
        self.mock_client.multi_firewall_mode = False
        self.mock_client.firewall_name = 'test-firewall'
        self.mock_client.host = '192.168.1.1'
        
        # Mock the execute_on_all_firewalls method to return the expected result
        def mock_execute_on_all_firewalls(func):
            return func(self.mock_client)
        
        self.mock_client.execute_on_all_firewalls = mock_execute_on_all_firewalls
        
        # Mock the stats config
        with patch.object(self.system_stats.stats_config, 'is_collection_enabled', return_value=True):
            result = self.system_stats.get_system_data()
        
        # Verify that _uptime_seconds was added
        system_info = result['system_info']
        assert '_uptime_seconds' in system_info['system']
        assert system_info['system']['_uptime_seconds'] == 1634589  # 18 days, 22:03:09 in seconds
        assert system_info['system']['uptime'] == '18 days, 22:03:09'  # Original preserved
