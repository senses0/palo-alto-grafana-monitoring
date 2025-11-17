"""Simplified pytest fixtures for Palo Alto Grafana Monitoring tests."""

import pytest
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock


def pytest_configure(config):
    """Register custom pytest marks."""
    config.addinivalue_line(
        "markers", "unit: Unit tests"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests"
    )
    config.addinivalue_line(
        "markers", "real_firewall: Tests that require real firewall"
    )
    config.addinivalue_line(
        "markers", "slow: Slow running tests"
    )
    config.addinivalue_line(
        "markers", "mock: Mock tests"
    )

# Add the project root to the Python path
import sys
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.palo_alto_client.client import PaloAltoClient
from src.palo_alto_client.auth import PaloAltoAuth
from src.palo_alto_client.exceptions import *


class TestConfig:
    """Simplified configuration for test environment."""
    
    @staticmethod
    def use_real_firewall() -> bool:
        """Check if real firewall should be used for testing."""
        # Check environment variable first
        env_value = os.getenv('PA_TEST_REAL_FIREWALL', '').lower()
        if env_value in ('true', '1', 'yes'):
            return True
        elif env_value in ('false', '0', 'no'):
            return False
        
        # Check config file
        config = TestConfig.load_config_file()
        if config and 'use_real_firewall' in config:
            return config['use_real_firewall']
        
        return False
    
    @staticmethod
    def get_mock_firewall_config() -> Dict[str, Any]:
        """Get mock firewall configuration for testing."""
        return {
            'host': '192.168.1.1',
            'port': 443,
            'api_key': 'test_api_key',
            'verify_ssl': False,
            'timeout': 30,
            'firewall_name': 'test-fw',
            'description': 'Test Firewall',
            'location': 'Test Environment'
        }
    
    @staticmethod
    def get_real_firewall_config() -> Dict[str, Any]:
        """Get real firewall configuration from environment variables or config file."""
        # First try environment variables
        host = os.getenv('PA_TEST_FIREWALL_HOST')
        port = int(os.getenv('PA_TEST_FIREWALL_PORT', '443'))
        api_key = os.getenv('PA_TEST_FIREWALL_API_KEY')
        verify_ssl = os.getenv('PA_TEST_FIREWALL_VERIFY_SSL', 'false').lower() == 'true'
        timeout = int(os.getenv('PA_TEST_FIREWALL_TIMEOUT', '30'))
        firewall_name = os.getenv('PA_TEST_FIREWALL_NAME', 'real-fw')
        
        # If environment variables are not available, try config file
        if not host or not api_key:
            config = TestConfig.load_config_file()
            if config and 'firewall' in config:
                firewall_config = config['firewall']
                host = firewall_config.get('host')
                port = firewall_config.get('port', 443)
                api_key = firewall_config.get('api_key')
                verify_ssl = firewall_config.get('verify_ssl', False)
                timeout = firewall_config.get('timeout', 30)
                firewall_name = firewall_config.get('firewall_name', 'real-fw')
        
        if not host or not api_key:
            raise ValueError("Real firewall testing requires PA_TEST_FIREWALL_HOST and PA_TEST_FIREWALL_API_KEY environment variables or firewall configuration in tests/firewall_config.yaml")
        
        return {
            'host': host,
            'port': port,
            'api_key': api_key,
            'verify_ssl': verify_ssl,
            'timeout': timeout,
            'firewall_name': firewall_name,
            'description': 'Real Test Firewall',
            'location': 'Test Environment'
        }
    
    @staticmethod
    def get_firewall_config() -> Dict[str, Any]:
        """Get firewall configuration based on use_real_firewall setting."""
        if TestConfig.use_real_firewall():
            return TestConfig.get_real_firewall_config()
        else:
            return TestConfig.get_mock_firewall_config()
    
    @staticmethod
    def get_firewall_config_from_file() -> Optional[Dict[str, Any]]:
        """Get firewall configuration from config file."""
        config = TestConfig.load_config_file()
        if config and 'firewall' in config:
            return config['firewall']
        return None
    
    @staticmethod
    def load_config_file() -> Optional[Dict[str, Any]]:
        """Load configuration from YAML file."""
        config_paths = [
            Path('tests/firewall_config.yaml'),
            Path('tests/firewall_config_local.yaml')
        ]
        
        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        return yaml.safe_load(f)
                except Exception as e:
                    print(f"Warning: Could not load config file {config_path}: {e}")
        
        return None


@pytest.fixture
def mock_client():
    """Fixture providing a mocked PaloAltoClient instance."""
    mock_client = Mock()
    mock_client.firewall_name = 'test-fw'
    mock_client.host = '192.168.1.1'
    mock_client.port = 443
    mock_client.api_key = 'test_api_key'
    mock_client.verify_ssl = False
    mock_client.timeout = 30
    mock_client.base_url = 'https://192.168.1.1:443'
    mock_client.multi_firewall_mode = False
    mock_client.firewalls = {'test-fw': mock_client}
    
    # Mock methods
    mock_client.get_firewall_names.return_value = ['test-fw']
    mock_client.get_firewall_by_name.return_value = mock_client
    mock_client.execute_operational_command.return_value = {'result': {'test': 'data'}}
    mock_client._make_request.return_value = Mock(text='<response status="success"><result>test</result></response>')
    
    return mock_client


@pytest.fixture
def mock_firewall_config():
    """Fixture providing mock firewall configuration."""
    return TestConfig.get_mock_firewall_config()


@pytest.fixture
def real_firewall_config():
    """Fixture providing real firewall configuration."""
    try:
        return TestConfig.get_real_firewall_config()
    except ValueError:
        # Return None if real firewall configuration is not available
        # This allows tests to handle the case gracefully
        return None


@pytest.fixture
def firewall_config():
    """Fixture providing firewall configuration."""
    return TestConfig.get_firewall_config()


@pytest.fixture
def client(firewall_config):
    """Fixture providing a PaloAltoClient instance."""
    config = firewall_config
    
    # Create a simple client for testing that doesn't rely on settings
    class TestPaloAltoClient:
        def __init__(self, host, port, api_key, verify_ssl, timeout, firewall_name):
            self.host = host
            self.port = port
            self.api_key = api_key
            self.verify_ssl = verify_ssl
            self.timeout = timeout
            self.firewall_name = firewall_name
            self.base_url = f"https://{host}:{port}"
            self.auth = PaloAltoAuth(host, port, verify_ssl, timeout, firewall_name)
            self.auth.set_api_key(api_key)
            self.firewalls = {firewall_name: self}
            self.multi_firewall_mode = False
            self.description = 'Test Firewall'
            self.location = 'Test Environment'
        
        def test_connection(self):
            """Test connection to firewall."""
            return self.auth.test_authentication()
        
        def get_system_info(self):
            """Get system information."""
            # This would normally make an API call, but for testing we'll return mock data
            return {
                'hostname': self.firewall_name,
                'model': 'PA-220',
                'sw_version': '10.1.0'
            }
        
        def get_interface_stats(self):
            """Get interface statistics."""
            # This would normally make an API call, but for testing we'll return mock data
            return [
                {
                    'name': 'ethernet1/1',
                    'state': 'up'
                }
            ]
        
        def get_firewall_names(self):
            """Get firewall names."""
            return list(self.firewalls.keys())
        
        def get_firewall_by_name(self, name):
            """Get firewall by name."""
            return self.firewalls.get(name)
        
        def get_firewall_summary(self):
            """Get firewall summary."""
            return {
                'total_firewalls': 1,
                'firewalls': {
                    self.firewall_name: {
                        'host': self.host,
                        'port': self.port,
                        'description': self.description,
                        'location': self.location,
                        'verify_ssl': self.verify_ssl,
                        'timeout': self.timeout
                    }
                }
            }
        
        def validate_firewall_config(self):
            """Validate firewall configuration."""
            return {
                self.firewall_name: {
                    'valid': True,
                    'errors': []
                }
            }
        
        def _make_request(self, method, endpoint, **kwargs):
            """Mock request method."""
            return Mock(text='<response status="success"><result>test</result></response>')
        
        def execute_operational_command(self, command):
            """Execute operational command."""
            return {'result': {'test': 'data'}}
    
    return TestPaloAltoClient(
        host=config['host'],
        port=config['port'],
        api_key=config['api_key'],
        verify_ssl=config['verify_ssl'],
        timeout=config['timeout'],
        firewall_name=config['firewall_name']
    )


@pytest.fixture
def auth(firewall_config):
    """Fixture providing a PaloAltoAuth instance."""
    config = firewall_config
    auth = PaloAltoAuth(
        host=config['host'],
        port=config['port'],
        verify_ssl=config['verify_ssl'],
        timeout=config['timeout'],
        firewall_name=config['firewall_name']
    )
    auth.set_api_key(config['api_key'])
    return auth


@pytest.fixture
def sample_system_data():
    """Fixture providing sample system data for testing."""
    return {
        'system': {
            'hostname': 'test-fw',
            'ip_address': '192.168.1.1',
            'model': 'PA-220',
            'serial': '012345678901',
            'sw_version': '10.1.0',
            'uptime': '5 days, 2 hours, 30 minutes',
            'cpu_usage': 15.5,
            'memory_usage': 45.2,
            'disk_usage': 30.1
        },
        'timestamp': '2024-01-01T12:00:00Z'
    }


@pytest.fixture
def sample_interface_data():
    """Fixture providing sample interface data for testing."""
    return {
        'interfaces': [
            {
                'name': 'ethernet1/1',
                'state': 'up',
                'ip_address': '192.168.1.1/24',
                'speed': '1000',
                'duplex': 'full',
                'rx_bytes': 1024000,
                'tx_bytes': 2048000,
                'rx_packets': 1000,
                'tx_packets': 2000,
                'rx_errors': 0,
                'tx_errors': 0
            },
            {
                'name': 'ethernet1/2',
                'state': 'down',
                'ip_address': '10.0.0.1/24',
                'speed': '1000',
                'duplex': 'full',
                'rx_bytes': 0,
                'tx_bytes': 0,
                'rx_packets': 0,
                'tx_packets': 0,
                'rx_errors': 0,
                'tx_errors': 0
            }
        ],
        'timestamp': '2024-01-01T12:00:00Z'
    }


@pytest.fixture
def sample_bgp_data():
    """Fixture providing sample BGP data for testing."""
    return {
        'bgp': {
            'as_number': '65000',
            'router_id': '192.168.1.1',
            'peers': [
                {
                    'remote_as': '65001',
                    'remote_ip': '192.168.1.2',
                    'state': 'Established',
                    'uptime': '2 days, 5 hours',
                    'prefixes_received': 100,
                    'prefixes_sent': 50,
                    'messages_received': 1000,
                    'messages_sent': 500
                }
            ]
        },
        'timestamp': '2024-01-01T12:00:00Z'
    }


@pytest.fixture
def sample_threat_data():
    """Fixture providing sample threat data for testing."""
    return {
        'threats': {
            'total_threats': 150,
            'threats_today': 25,
            'threats_this_week': 75,
            'threats_this_month': 150,
            'threat_types': {
                'virus': 50,
                'spyware': 30,
                'vulnerability': 40,
                'wildfire': 30
            },
            'severity_distribution': {
                'critical': 10,
                'high': 25,
                'medium': 60,
                'low': 55
            }
        },
        'timestamp': '2024-01-01T12:00:00Z'
    }
