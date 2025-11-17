#!/usr/bin/env python3
"""Test script to verify data structure improvements."""

import sys
import os
import json
from typing import Dict, Any

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.palo_alto_client.client import PaloAltoClient
from src.stats.vpn_tunnels import VpnTunnelStats
from src.stats.system import SystemStats
from src.stats.network_interfaces import InterfaceStats
from src.stats.global_counters import GlobalCounters
from src.stats.global_protect import GlobalProtectStats
from src.stats.routing import RoutingStats

def analyze_data_structure(data: Dict[str, Any], path: str = "") -> None:
    """Analyze the data structure and print nesting information."""
    if not isinstance(data, dict):
        return
    
    for key, value in data.items():
        current_path = f"{path}.{key}" if path else key
        
        if isinstance(value, dict):
            # Check if this looks like a firewall response structure
            if 'success' in value and 'data' in value and 'error' in value:
                print(f"  🔍 Found firewall response structure at: {current_path}")
                if isinstance(value['data'], dict) and 'success' in value['data']:
                    print(f"  ⚠️  WARNING: Nested firewall response structure detected at: {current_path}.data")
                else:
                    print(f"  ✅ Clean data structure at: {current_path}.data")
            
            # Recursively analyze nested dictionaries
            analyze_data_structure(value, current_path)
        else:
            print(f"  📄 Leaf node at: {current_path} = {type(value).__name__}")

def test_vpn_data_structure():
    """Test VPN data structure."""
    print("\n" + "="*60)
    print("Testing VPN Data Structure")
    print("="*60)
    
    client = PaloAltoClient()
    vpn_stats = VpnTunnelStats(client)
    
    print("Getting VPN data...")
    vpn_data = vpn_stats.get_vpn_data()
    
    print("\nData structure analysis:")
    analyze_data_structure(vpn_data)
    
    # Use assertions instead of returning True/False
    assert isinstance(vpn_data, dict), "VPN data should be a dictionary"
    
    # Check for the specific issue mentioned - use dynamic firewall name
    # In multi-firewall mode, the data structure has firewall names as keys
    if client.multi_firewall_mode:
        # Check all firewall data in multi-firewall mode
        for firewall_name, firewall_data in vpn_data.items():
            if isinstance(firewall_data, dict) and 'data' in firewall_data:
                vpn_flows = firewall_data['data'].get('vpn_flows', {})
                if isinstance(vpn_flows, dict):
                    assert firewall_name not in vpn_flows, f"Nested firewall name '{firewall_name}' should not be in vpn_flows"
                    print(f"\n✅ FIXED: No nested firewall name '{firewall_name}' in vpn_flows")
                else:
                    print(f"\n✅ vpn_flows is not a dictionary as expected for '{firewall_name}'")
            else:
                print(f"\n✅ Firewall data structure is clean for '{firewall_name}'")
    else:
        # Single firewall mode - use the client's firewall name
        firewall_name = client.firewall_name
        if firewall_name and firewall_name in vpn_data:
            firewall_data = vpn_data[firewall_name]
            if isinstance(firewall_data, dict) and 'data' in firewall_data:
                vpn_flows = firewall_data['data'].get('vpn_flows', {})
                if isinstance(vpn_flows, dict):
                    assert firewall_name not in vpn_flows, f"Nested firewall name '{firewall_name}' should not be in vpn_flows"
                    print(f"\n✅ FIXED: No nested firewall name '{firewall_name}' in vpn_flows")
                else:
                    print(f"\n✅ vpn_flows is not a dictionary as expected")
            else:
                print(f"\n✅ Firewall data structure is clean for '{firewall_name}'")
        else:
            print(f"\n✅ No firewall-specific data found for '{firewall_name}'")

def test_system_data_structure():
    """Test system data structure."""
    print("\n" + "="*60)
    print("Testing System Data Structure")
    print("="*60)
    
    client = PaloAltoClient()
    system_stats = SystemStats(client)
    
    print("Getting system data...")
    system_data = system_stats.get_system_data()
    
    print("\nData structure analysis:")
    analyze_data_structure(system_data)
    
    # Use assertions instead of returning True/False
    assert isinstance(system_data, dict), "System data should be a dictionary"

def test_interface_data_structure():
    """Test interface data structure."""
    print("\n" + "="*60)
    print("Testing Interface Data Structure")
    print("="*60)
    
    client = PaloAltoClient()
    interface_stats = InterfaceStats(client)
    
    print("Getting interface data...")
    interface_data = interface_stats.get_interface_data()
    
    print("\nData structure analysis:")
    analyze_data_structure(interface_data)
    
    # Use assertions instead of returning True/False
    assert isinstance(interface_data, dict), "Interface data should be a dictionary"

def test_global_counters_data_structure():
    """Test global counters data structure."""
    print("\n" + "="*60)
    print("Testing Global Counters Data Structure")
    print("="*60)
    
    client = PaloAltoClient()
    counter_stats = GlobalCounters(client)
    
    print("Getting global counters data...")
    counter_data = counter_stats.get_counter_data()
    
    print("\nData structure analysis:")
    analyze_data_structure(counter_data)
    
    # Use assertions instead of returning True/False
    assert isinstance(counter_data, dict), "Global counters data should be a dictionary"

def test_global_protect_data_structure():
    """Test global protect data structure."""
    print("\n" + "="*60)
    print("Testing Global Protect Data Structure")
    print("="*60)
    
    client = PaloAltoClient()
    gp_stats = GlobalProtectStats(client)
    
    print("Getting global protect data...")
    gp_data = gp_stats.get_global_protect_data()
    
    print("\nData structure analysis:")
    analyze_data_structure(gp_data)
    
    # Use assertions instead of returning True/False
    assert isinstance(gp_data, dict), "Global protect data should be a dictionary"

def test_routing_data_structure():
    """Test  routing data structure."""
    print("\n" + "="*60)
    print("Testing  Routing Data Structure")
    print("="*60)
    
    client = PaloAltoClient()
    routing_stats = RoutingStats(client)
    
    print("Getting routing data...")
    routing_data = routing_stats.get_routing_data()
    
    print("\nData structure analysis:")
    analyze_data_structure(routing_data)
    
    # Use assertions instead of returning True/False
    assert isinstance(routing_data, dict), "Routing data should be a dictionary"

def main():
    """Main test function."""
    print("Palo Alto Data Structure Fix Verification")
    print("=" * 60)
    
    # Test all modules
    tests = [
        test_vpn_data_structure,
        test_system_data_structure,
        test_interface_data_structure,
        test_global_counters_data_structure,
        test_global_protect_data_structure,
        test_routing_data_structure
    ]
    
    results = []
    for test in tests:
        try:
            test()  # Call the test function without expecting a return value
            results.append(True)
        except Exception as e:
            print(f"Test failed with exception: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✅ All tests passed! Data structure improvements successful.")
    else:
        print("❌ Some tests failed. Please review the output above.")
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    exit(main())
