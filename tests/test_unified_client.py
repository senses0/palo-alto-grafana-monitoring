#!/usr/bin/env python3
"""Test script for the unified multi-firewall client integration."""

import sys
import os
import pytest

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.palo_alto_client.client import PaloAltoClient
from src.stats.system import SystemStats
from src.stats.network_interfaces import InterfaceStats
from src.utils.logger import get_logger

logger = get_logger(__name__)

@pytest.mark.integration
def test_unified_client_multi_firewall_mode():
    """Test the unified client functionality in multi-firewall mode."""
    print("=== Testing Unified Multi-Firewall Client ===\n")
    
    # Test 1: Multi-firewall mode (default)
    print("1. Testing Multi-Firewall Mode (Default)")
    client = PaloAltoClient()
    
    # Get firewall summary
    summary = client.get_firewall_summary()
    assert 'total_firewalls' in summary, "Summary should contain total_firewalls"
    assert 'firewalls' in summary, "Summary should contain firewalls"
    
    print(f"   Configured firewalls: {summary['total_firewalls']}")
    for name, config in summary['firewalls'].items():
        print(f"   - {name}: {config.get('host', 'N/A')}")
    
    # Get firewall names
    firewall_names = client.get_firewall_names()
    assert isinstance(firewall_names, list), "Firewall names should be a list"
    print(f"   Available firewalls: {firewall_names}")
    
    # Validate configurations
    validation = client.validate_firewall_config()
    assert isinstance(validation, dict), "Validation should return a dictionary"
    print("   Configuration validation:")
    for name, result in validation.items():
        status = "✓ Valid" if result['valid'] else "✗ Invalid"
        print(f"     {name}: {status}")
    
    print()

@pytest.mark.integration
def test_unified_client_single_firewall_mode():
    """Test the unified client functionality in single firewall mode."""
    client = PaloAltoClient()
    firewall_names = client.get_firewall_names()
    
    if not firewall_names:
        pytest.skip("No firewalls configured for single firewall mode test")
    
    print("2. Testing Single Firewall Mode")
    target_firewall = firewall_names[0]
    print(f"   Targeting firewall: {target_firewall}")
    
    single_client = PaloAltoClient(firewall_name=target_firewall)
    single_summary = single_client.get_firewall_summary()
    assert single_summary['total_firewalls'] == 1, "Single firewall mode should have exactly 1 firewall"
    print(f"   Single firewall summary: {single_summary['total_firewalls']} firewall(s)")
    
    print()

@pytest.mark.integration
def test_stats_collectors_with_unified_client():
    """Test stats collectors with unified client."""
    client = PaloAltoClient()
    
    print("3. Testing Stats Collectors")
    
    # System stats
    system_stats = SystemStats(client)
    print("   Testing system stats...")
    try:
        sys_data = system_stats.get_system_data()
        assert isinstance(sys_data, dict), "System data should be a dictionary"
        print(f"   System data retrieved for {len(sys_data)} firewall(s)")
        
        for firewall_name, result in sys_data.items():
            if result['success']:
                print(f"     ✓ {firewall_name}: Success")
            else:
                print(f"     ✗ {firewall_name}: {result['error']}")
    except Exception as e:
        print(f"     Error getting system data: {e}")
        pytest.fail(f"System stats test failed: {e}")
    
    # Interface stats
    interface_stats = InterfaceStats(client)
    print("   Testing interface stats...")
    try:
        if_data = interface_stats.get_interface_data()
        assert isinstance(if_data, dict), "Interface data should be a dictionary"
        print(f"   Interface data retrieved for {len(if_data)} firewall(s)")
        
        for firewall_name, result in if_data.items():
            if result['success']:
                print(f"     ✓ {firewall_name}: Success")
            else:
                print(f"     ✗ {firewall_name}: {result['error']}")
    except Exception as e:
        print(f"     Error getting interface data: {e}")
        pytest.fail(f"Interface stats test failed: {e}")
    
    print()

@pytest.mark.integration
def test_unified_client_approach():
    """Test unified client approach consistency."""
    client = PaloAltoClient()
    
    print("4. Testing Unified Client Approach")
    print("   All methods now use execute_on_all_firewalls() for consistency")
    
    system_stats = SystemStats(client)
    try:
        # Test that the unified approach works for all firewalls
        unified_sys_data = system_stats.get_system_data()
        assert isinstance(unified_sys_data, dict), "Unified approach data should be a dictionary"
        print(f"   Unified approach data retrieved for {len(unified_sys_data)} firewall(s)")
        
        for firewall_name, result in unified_sys_data.items():
            if result['success']:
                print(f"     ✓ {firewall_name}: Success")
            else:
                print(f"     ✗ {firewall_name}: {result['error']}")
    except Exception as e:
        print(f"     Error with unified approach: {e}")
        pytest.fail(f"Unified approach test failed: {e}")
    
    print()
    print("=== Test Completed Successfully ===")

