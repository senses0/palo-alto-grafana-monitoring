"""Pytest tests for configuration management."""

import pytest
import os
import yaml
from pathlib import Path
from unittest.mock import patch, mock_open

from tests.conftest import TestConfig


class TestTestConfig:
    """Test cases for TestConfig class."""

    @pytest.mark.unit
    def test_use_real_firewall_env_true(self):
        """Test use_real_firewall when environment variable is set to true."""
        with patch.dict(os.environ, {'PA_TEST_REAL_FIREWALL': 'true'}):
            assert TestConfig.use_real_firewall() is True

    @pytest.mark.unit
    def test_use_real_firewall_env_false(self):
        """Test use_real_firewall when environment variable is set to false."""
        with patch.dict(os.environ, {'PA_TEST_REAL_FIREWALL': 'false'}):
            with patch.object(TestConfig, 'load_config_file', return_value=None):
                assert TestConfig.use_real_firewall() is False

    @pytest.mark.unit
    def test_use_real_firewall_env_not_set(self):
        """Test use_real_firewall when environment variable is not set."""
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(TestConfig, 'load_config_file', return_value=None):
                assert TestConfig.use_real_firewall() is False

    @pytest.mark.unit
    def test_use_real_firewall_config_file_true(self):
        """Test use_real_firewall when config file has use_real_firewall: true."""
        mock_config = {'use_real_firewall': True}
        with patch.object(TestConfig, 'load_config_file', return_value=mock_config):
            with patch.dict(os.environ, {}, clear=True):
                assert TestConfig.use_real_firewall() is True

    @pytest.mark.unit
    def test_use_real_firewall_config_file_false(self):
        """Test use_real_firewall when config file has use_real_firewall: false."""
        mock_config = {'use_real_firewall': False}
        with patch.object(TestConfig, 'load_config_file', return_value=mock_config):
            with patch.dict(os.environ, {}, clear=True):
                assert TestConfig.use_real_firewall() is False

    @pytest.mark.unit
    def test_get_mock_firewall_config(self):
        """Test get_mock_firewall_config returns expected configuration."""
        config = TestConfig.get_mock_firewall_config()
        
        expected_keys = ['host', 'port', 'api_key', 'verify_ssl', 'timeout', 'firewall_name', 'description', 'location']
        assert all(key in config for key in expected_keys)
        assert config['host'] == '192.168.1.1'
        assert config['port'] == 443
        assert config['api_key'] == 'test_api_key'
        assert config['verify_ssl'] is False
        assert config['timeout'] == 30
        assert config['firewall_name'] == 'test-fw'

    @pytest.mark.unit
    def test_get_real_firewall_config_env_vars(self):
        """Test get_real_firewall_config with environment variables."""
        env_vars = {
            'PA_TEST_FIREWALL_HOST': '192.168.1.100',
            'PA_TEST_FIREWALL_PORT': '8443',
            'PA_TEST_FIREWALL_API_KEY': 'test_real_key',
            'PA_TEST_FIREWALL_VERIFY_SSL': 'true',
            'PA_TEST_FIREWALL_TIMEOUT': '60',
            'PA_TEST_FIREWALL_NAME': 'real-fw'
        }
        
        with patch.dict(os.environ, env_vars):
            with patch.object(TestConfig, 'use_real_firewall', return_value=True):
                config = TestConfig.get_real_firewall_config()
                
                assert config['host'] == '192.168.1.100'
                assert config['port'] == 8443
                assert config['api_key'] == 'test_real_key'
                assert config['verify_ssl'] is True
                assert config['timeout'] == 60
                assert config['firewall_name'] == 'real-fw'

    @pytest.mark.unit
    def test_get_real_firewall_config_missing_required(self):
        """Test get_real_firewall_config raises error when required env vars are missing."""
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(TestConfig, 'load_config_file', return_value=None):
                with pytest.raises(ValueError, match="Real firewall testing requires"):
                    TestConfig.get_real_firewall_config()

    @pytest.mark.unit
    def test_get_real_firewall_config_from_file(self):
        """Test get_real_firewall_config with config file."""
        mock_config = {
            'firewall': {
                'host': '192.168.1.200',
                'port': 9443,
                'api_key': 'file_key',
                'verify_ssl': False,
                'timeout': 45,
                'firewall_name': 'file-fw'
            }
        }
        
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(TestConfig, 'load_config_file', return_value=mock_config):
                config = TestConfig.get_real_firewall_config()
                
                assert config['host'] == '192.168.1.200'
                assert config['port'] == 9443
                assert config['api_key'] == 'file_key'
                assert config['verify_ssl'] is False
                assert config['timeout'] == 45
                assert config['firewall_name'] == 'file-fw'

    @pytest.mark.unit
    def test_get_firewall_config_real_firewall(self):
        """Test get_firewall_config when real firewall is enabled."""
        mock_real_config = {'host': '192.168.1.100', 'api_key': 'real_key'}
        with patch.object(TestConfig, 'use_real_firewall', return_value=True):
            with patch.object(TestConfig, 'get_real_firewall_config', return_value=mock_real_config):
                config = TestConfig.get_firewall_config()
                assert config == mock_real_config

    @pytest.mark.unit
    def test_get_firewall_config_mock_firewall(self):
        """Test get_firewall_config when real firewall is disabled."""
        mock_mock_config = {'host': '192.168.1.1', 'api_key': 'test_api_key'}
        with patch.object(TestConfig, 'use_real_firewall', return_value=False):
            with patch.object(TestConfig, 'get_mock_firewall_config', return_value=mock_mock_config):
                config = TestConfig.get_firewall_config()
                assert config == mock_mock_config

    @pytest.mark.unit
    def test_load_config_file_exists(self):
        """Test load_config_file when config file exists."""
        mock_yaml_content = {'use_real_firewall': True, 'firewall': {'host': 'test'}}
        mock_file_content = yaml.dump(mock_yaml_content)
        
        with patch('builtins.open', mock_open(read_data=mock_file_content)):
            with patch('pathlib.Path.exists', return_value=True):
                config = TestConfig.load_config_file()
                assert config == mock_yaml_content

    @pytest.mark.unit
    def test_load_config_file_not_exists(self):
        """Test load_config_file when config file does not exist."""
        with patch('pathlib.Path.exists', return_value=False):
            config = TestConfig.load_config_file()
            assert config is None

    @pytest.mark.unit
    def test_load_config_file_yaml_error(self):
        """Test load_config_file when YAML parsing fails."""
        with patch('builtins.open', mock_open(read_data='invalid yaml')):
            with patch('pathlib.Path.exists', return_value=True):
                with patch('yaml.safe_load', side_effect=yaml.YAMLError("Invalid YAML")):
                    config = TestConfig.load_config_file()
                    assert config is None

    @pytest.mark.unit
    def test_get_firewall_config_from_file_with_firewall(self):
        """Test get_firewall_config_from_file when firewall config exists."""
        mock_config = {
            'firewall': {
                'host': '192.168.1.100',
                'api_key': 'test_key'
            }
        }
        with patch.object(TestConfig, 'load_config_file', return_value=mock_config):
            config = TestConfig.get_firewall_config_from_file()
            assert config == mock_config['firewall']

    @pytest.mark.unit
    def test_get_firewall_config_from_file_without_firewall(self):
        """Test get_firewall_config_from_file when firewall config does not exist."""
        mock_config = {'other_config': 'value'}
        with patch.object(TestConfig, 'load_config_file', return_value=mock_config):
            config = TestConfig.get_firewall_config_from_file()
            assert config is None

    @pytest.mark.unit
    def test_get_firewall_config_from_file_no_config(self):
        """Test get_firewall_config_from_file when no config file exists."""
        with patch.object(TestConfig, 'load_config_file', return_value=None):
            config = TestConfig.get_firewall_config_from_file()
            assert config is None


@pytest.mark.unit
def test_firewall_config_fixture(mock_firewall_config):
    """Test that the mock_firewall_config fixture works correctly."""
    assert mock_firewall_config['host'] == '192.168.1.1'
    assert mock_firewall_config['api_key'] == 'test_api_key'
    assert mock_firewall_config['verify_ssl'] is False


@pytest.mark.unit
def test_real_firewall_config_fixture(real_firewall_config):
    """Test that the real_firewall_config fixture works correctly."""
    # This will be None if real firewall config is not available
    # which is expected behavior
    if real_firewall_config is not None:
        assert 'host' in real_firewall_config
        assert 'api_key' in real_firewall_config


@pytest.mark.unit
def test_firewall_config_fixture_default(mock_firewall_config):
    """Test that the firewall_config fixture defaults to mock when real is not available."""
    # This should always return the mock config since we're not setting up real firewall
    assert mock_firewall_config['host'] == '192.168.1.1'
    assert mock_firewall_config['api_key'] == 'test_api_key'
