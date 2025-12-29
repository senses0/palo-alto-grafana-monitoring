"""Pytest tests for Settings class and firewall enabled parameter."""

import pytest
import os
import yaml
from pathlib import Path
from unittest.mock import patch, mock_open
import tempfile

from config.settings import Settings


class TestSettingsEnabledParameter:
    """Test cases for the firewall enabled parameter functionality."""

    @pytest.mark.unit
    def test_enabled_defaults_to_true(self):
        """Test that enabled defaults to True when not specified."""
        config_yaml = """
firewalls:
  test-fw:
    host: "192.168.1.1"
    port: 443
    api_key: "test_key"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                firewalls = settings.get_firewalls()
                
                assert 'test-fw' in firewalls
                assert firewalls['test-fw'].get('enabled') is True
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_enabled_explicit_true(self):
        """Test firewall with enabled explicitly set to true."""
        config_yaml = """
firewalls:
  test-fw:
    enabled: true
    host: "192.168.1.1"
    port: 443
    api_key: "test_key"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                assert settings.is_firewall_enabled('test-fw') is True
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_enabled_explicit_false(self):
        """Test firewall with enabled explicitly set to false."""
        config_yaml = """
firewalls:
  test-fw:
    enabled: false
    host: "192.168.1.1"
    port: 443
    api_key: "test_key"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                assert settings.is_firewall_enabled('test-fw') is False
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_get_enabled_firewalls(self):
        """Test get_enabled_firewalls returns only enabled firewalls."""
        config_yaml = """
firewalls:
  enabled-fw:
    enabled: true
    host: "192.168.1.1"
    port: 443
    api_key: "test_key"
  disabled-fw:
    enabled: false
    host: "192.168.1.2"
    port: 443
    api_key: "test_key2"
  default-fw:
    host: "192.168.1.3"
    port: 443
    api_key: "test_key3"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                enabled_firewalls = settings.get_enabled_firewalls()
                
                assert 'enabled-fw' in enabled_firewalls
                assert 'default-fw' in enabled_firewalls  # Defaults to enabled
                assert 'disabled-fw' not in enabled_firewalls
                assert len(enabled_firewalls) == 2
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_get_disabled_firewalls(self):
        """Test get_disabled_firewalls returns only disabled firewalls."""
        config_yaml = """
firewalls:
  enabled-fw:
    enabled: true
    host: "192.168.1.1"
    port: 443
    api_key: "test_key"
  disabled-fw:
    enabled: false
    host: "192.168.1.2"
    port: 443
    api_key: "test_key2"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                disabled_firewalls = settings.get_disabled_firewalls()
                
                assert 'disabled-fw' in disabled_firewalls
                assert 'enabled-fw' not in disabled_firewalls
                assert len(disabled_firewalls) == 1
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_get_enabled_firewall_names(self):
        """Test get_enabled_firewall_names returns list of enabled firewall names."""
        config_yaml = """
firewalls:
  enabled-fw1:
    enabled: true
    host: "192.168.1.1"
    api_key: "test_key"
  disabled-fw:
    enabled: false
    host: "192.168.1.2"
    api_key: "test_key2"
  enabled-fw2:
    enabled: true
    host: "192.168.1.3"
    api_key: "test_key3"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                enabled_names = settings.get_enabled_firewall_names()
                
                assert 'enabled-fw1' in enabled_names
                assert 'enabled-fw2' in enabled_names
                assert 'disabled-fw' not in enabled_names
                assert len(enabled_names) == 2
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_is_firewall_enabled_nonexistent(self):
        """Test is_firewall_enabled returns False for non-existent firewall."""
        config_yaml = """
firewalls:
  test-fw:
    host: "192.168.1.1"
    api_key: "test_key"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                assert settings.is_firewall_enabled('nonexistent-fw') is False
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_all_firewalls_disabled(self):
        """Test that get_enabled_firewalls returns empty when all are disabled."""
        config_yaml = """
firewalls:
  disabled-fw1:
    enabled: false
    host: "192.168.1.1"
    api_key: "test_key"
  disabled-fw2:
    enabled: false
    host: "192.168.1.2"
    api_key: "test_key2"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                enabled_firewalls = settings.get_enabled_firewalls()
                
                assert len(enabled_firewalls) == 0
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_get_firewalls_includes_all(self):
        """Test that get_firewalls includes both enabled and disabled firewalls."""
        config_yaml = """
firewalls:
  enabled-fw:
    enabled: true
    host: "192.168.1.1"
    api_key: "test_key"
  disabled-fw:
    enabled: false
    host: "192.168.1.2"
    api_key: "test_key2"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                all_firewalls = settings.get_firewalls()
                
                assert 'enabled-fw' in all_firewalls
                assert 'disabled-fw' in all_firewalls
                assert len(all_firewalls) == 2
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_legacy_format_defaults_to_enabled(self):
        """Test that legacy single firewall format defaults to enabled."""
        config_yaml = """
firewall:
  host: "192.168.1.1"
  port: 443
  api_key: "test_key"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                firewalls = settings.get_firewalls()
                
                # Legacy format should create a 'default' firewall entry
                assert 'default' in firewalls
                assert firewalls['default'].get('enabled') is True
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_enabled_string_true_values(self):
        """Test that various string representations of true work for enabled."""
        test_values = ['true', 'True', 'TRUE', '1', 'yes', 'Yes', 'YES', 'on', 'On', 'ON']
        
        for true_value in test_values:
            config_yaml = f"""
firewalls:
  test-fw:
    enabled: "{true_value}"
    host: "192.168.1.1"
    api_key: "test_key"
"""
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(config_yaml)
                f.flush()
                
                try:
                    settings = Settings(config_file=f.name)
                    # The enabled value will be the string, but is_firewall_enabled 
                    # uses _parse_bool which handles string "true", "1", "yes", "on"
                    assert settings.is_firewall_enabled('test-fw') is True, \
                        f"Failed for enabled value: {true_value}"
                finally:
                    os.unlink(f.name)

    @pytest.mark.unit
    def test_enabled_string_false_values(self):
        """Test that various string representations of false work for enabled."""
        test_values = ['false', 'False', 'FALSE', '0', 'no', 'No', 'NO', 'off', 'Off', 'OFF']
        
        for false_value in test_values:
            config_yaml = f"""
firewalls:
  test-fw:
    enabled: "{false_value}"
    host: "192.168.1.1"
    api_key: "test_key"
"""
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(config_yaml)
                f.flush()
                
                try:
                    settings = Settings(config_file=f.name)
                    # The enabled value will be the string, but is_firewall_enabled
                    # uses _parse_bool which handles string "false", "0", "no", "off"
                    assert settings.is_firewall_enabled('test-fw') is False, \
                        f"Failed for enabled value: {false_value}"
                finally:
                    os.unlink(f.name)


class TestSettingsBasicFunctionality:
    """Test cases for basic Settings class functionality."""

    @pytest.mark.unit
    def test_get_firewall_by_name(self):
        """Test get_firewall returns correct firewall configuration."""
        config_yaml = """
firewalls:
  primary-fw:
    host: "192.168.1.1"
    api_key: "primary_key"
  secondary-fw:
    host: "192.168.1.2"
    api_key: "secondary_key"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                
                primary = settings.get_firewall('primary-fw')
                assert primary['host'] == '192.168.1.1'
                assert primary['api_key'] == 'primary_key'
                
                secondary = settings.get_firewall('secondary-fw')
                assert secondary['host'] == '192.168.1.2'
                assert secondary['api_key'] == 'secondary_key'
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_get_firewall_names(self):
        """Test get_firewall_names returns all firewall names."""
        config_yaml = """
firewalls:
  fw1:
    host: "192.168.1.1"
    api_key: "key1"
  fw2:
    host: "192.168.1.2"
    api_key: "key2"
  fw3:
    host: "192.168.1.3"
    api_key: "key3"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                names = settings.get_firewall_names()
                
                assert len(names) == 3
                assert 'fw1' in names
                assert 'fw2' in names
                assert 'fw3' in names
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_routing_mode_defaults_to_auto(self):
        """Test that routing_mode defaults to 'auto' when not specified."""
        config_yaml = """
firewalls:
  test-fw:
    host: "192.168.1.1"
    api_key: "test_key"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                firewall = settings.get_firewall('test-fw')
                
                assert firewall.get('routing_mode') == 'auto'
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_default_firewall_selection(self):
        """Test that default_firewall setting is respected."""
        config_yaml = """
firewalls:
  primary-fw:
    host: "192.168.1.1"
    api_key: "primary_key"
  secondary-fw:
    host: "192.168.1.2"
    api_key: "secondary_key"
default_firewall: secondary-fw
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                
                # When no name specified, should return default
                default = settings.get_firewall()
                assert default['host'] == '192.168.1.2'
                assert default['api_key'] == 'secondary_key'
            finally:
                os.unlink(f.name)

    @pytest.mark.unit
    def test_get_method_dot_notation(self):
        """Test the get method with dot notation for nested values."""
        config_yaml = """
firewalls:
  test-fw:
    host: "192.168.1.1"
    api_key: "test_key"
logging:
  level: "DEBUG"
  file: "test.log"
query:
  max_retries: 5
  retry_delay: 10
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_yaml)
            f.flush()
            
            try:
                settings = Settings(config_file=f.name)
                
                assert settings.get('logging.level') == 'DEBUG'
                assert settings.get('logging.file') == 'test.log'
                assert settings.get('query.max_retries') == 5
                assert settings.get('query.retry_delay') == 10
                assert settings.get('nonexistent.key', 'default') == 'default'
            finally:
                os.unlink(f.name)

