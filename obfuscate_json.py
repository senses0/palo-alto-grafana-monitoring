#!/usr/bin/env python3
"""
Obfuscate sensitive data in statistics JSON files for external sharing.

This script applies consistent mapping obfuscation to sensitive data like
hostnames, IP addresses, serial numbers, VPN tunnel names, etc. The same
input value will always produce the same obfuscated output within a run,
preserving data relationships for debugging.

Usage:
    python obfuscate_json.py input.json output.json
    python obfuscate_json.py input.json output.json --level paranoid
    python obfuscate_json.py input.json output.json --level minimal --save-mapping mapping.json
"""

import argparse
import ipaddress
import json
import re
import signal
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Set


# Handle broken pipe gracefully (e.g., when piping to head)
signal.signal(signal.SIGPIPE, signal.SIG_DFL)


class ObfuscationMapper:
    """Maintains consistent mappings for obfuscated values."""

    # RFC 5737 documentation IP ranges for replacements
    DOC_IPV4_RANGES = [
        ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
        ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ]

    # RFC 3849 documentation IPv6 prefix
    DOC_IPV6_PREFIX = "2001:db8::"

    def __init__(self):
        self.mappings: Dict[str, Dict[str, str]] = {
            "hostname": {},
            "public_ip": {},
            "private_ip": {},
            "serial": {},
            "mac": {},
            "vpn_tunnel": {},
            "ike_gateway": {},
            "bgp_peer": {},
            "peer_group": {},
            "route_filter": {},
            "vlan_name": {},
            "logical_router": {},
            "asn": {},
            "gp_gateway": {},
            "gp_portal": {},
            "generic_name": {},
        }
        self.counters: Dict[str, int] = {k: 0 for k in self.mappings.keys()}
        self._public_ip_index = 0

    def get_mapping(self, category: str, original: str) -> str:
        """Get or create a consistent mapping for a value."""
        if original in self.mappings[category]:
            return self.mappings[category][original]

        obfuscated = self._generate_obfuscated(category, original)
        self.mappings[category][original] = obfuscated
        return obfuscated

    def _generate_obfuscated(self, category: str, original: str) -> str:
        """Generate an obfuscated value based on category."""
        self.counters[category] += 1
        count = self.counters[category]

        generators = {
            "hostname": lambda: f"firewall-{count:02d}",
            "public_ip": lambda: self._generate_doc_ip(count),
            "private_ip": lambda: f"10.{(count // 256) % 256}.{count % 256}.{(count * 7) % 256}",
            "serial": lambda: f"100000{count:05d}",
            "mac": lambda: f"00:00:5e:00:01:{count:02x}",
            "vpn_tunnel": lambda: f"vpn-tunnel-{count:02d}",
            "ike_gateway": lambda: f"ike-gateway-{count:02d}",
            "bgp_peer": lambda: f"bgp-peer-{count:02d}",
            "peer_group": lambda: f"peer-group-{count:02d}",
            "route_filter": lambda: f"route-filter-{count:02d}",
            "vlan_name": lambda: f"vlan-{count:02d}",
            "logical_router": lambda: f"vr-{count:02d}",
            "asn": lambda: f"{64512 + count}",  # Private ASN range
            "gp_gateway": lambda: f"gp-gateway-{count:02d}",
            "gp_portal": lambda: f"gp-portal-{count:02d}",
            "generic_name": lambda: f"name-{count:03d}",
        }

        return generators.get(category, lambda: f"obfuscated-{count}")()

    def _generate_doc_ip(self, index: int) -> str:
        """Generate a documentation IP address."""
        # Cycle through the three documentation ranges
        range_idx = (index - 1) // 254
        host_idx = ((index - 1) % 254) + 1

        if range_idx < len(self.DOC_IPV4_RANGES):
            network = self.DOC_IPV4_RANGES[range_idx]
            return str(network.network_address + host_idx)
        else:
            # Fallback for many IPs
            return f"198.18.{(index // 256) % 256}.{index % 256}"

    def export_mappings(self) -> Dict[str, Dict[str, str]]:
        """Export all mappings for reference."""
        return {k: v for k, v in self.mappings.items() if v}


class JSONObfuscator:
    """Obfuscates sensitive data in Palo Alto firewall JSON exports."""

    # Patterns for identifying data types
    PUBLIC_IP_PATTERN = re.compile(
        r"^(?!10\.)(?!172\.(?:1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)(?!169\.254\.)(?!127\.)"
        r"(?!0\.)(?!255\.)"
        r"(\d{1,3}\.){3}\d{1,3}$"
    )
    PRIVATE_IP_PATTERN = re.compile(
        r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"169\.254\.\d{1,3}\.\d{1,3})$"
    )
    MAC_PATTERN = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
    SERIAL_PATTERN = re.compile(r"^\d{10,12}$")
    IP_IN_STRING_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    # Keys that indicate sensitive hostname/name fields
    HOSTNAME_KEYS = {
        "hostname", "devicename", "advHostName", "rcvHostName",
    }

    # Keys that indicate VPN tunnel names
    VPN_TUNNEL_KEYS = {"name"}  # Context-dependent, checked in vpn_tunnels
    VPN_TUNNEL_PARENT_KEYS = {"vpn_tunnels", "ipsec_sa", "active_tunnels", "IPSec"}

    # Keys that indicate IKE gateway names
    IKE_GATEWAY_KEYS = {"name", "gw", "gateway"}
    IKE_GATEWAY_PARENT_KEYS = {"ike_gateways", "vpn_gateways"}

    # Keys that indicate GlobalProtect gateway names
    GP_GATEWAY_PARENT_KEYS = {"gateway_summary", "Gateway"}

    # Keys that indicate GlobalProtect portal names
    GP_PORTAL_PARENT_KEYS = {"portal_summary"}

    # Keys that indicate BGP peer names
    BGP_PEER_KEYS = {"peer-name", "peerName"}
    BGP_PEER_STATUS_KEY = "bgp_peer_status"

    # Keys that indicate peer group names
    PEER_GROUP_KEYS = {"peer-group-name", "peerGroup", "peerGroupMember"}

    # Keys for route filters
    ROUTE_FILTER_KEYS = {
        "incomingUpdatePrefixFilterList", "outgoingUpdatePrefixFilterList"
    }

    # Keys for logical routers
    LOGICAL_ROUTER_PARENT_KEYS = {"bgp_summary", "routing_table", "bgp_routes", "static_routes"}

    # Keys for VLAN names (in fwd field like "vlan:VL-Name")
    VLAN_FWD_KEY = "fwd"

    # Keys containing IPs
    IP_KEYS = {
        "ip-address", "public-ip-address", "default-gateway", "mgmt-ip",
        "ha1-ipaddr", "peer-ip", "local-ip", "hostLocal", "hostForeign",
        "nexthop", "updateSource", "router-id", "remoteRouterId", "localRouterId",
        "ip", "addr", "peer-id", "local-id", "destination", "monitordst-0",
    }

    # Keys containing MAC addresses
    MAC_KEYS = {
        "mac-address", "base_mac", "ha1-macaddr", "ha2-macaddr", "mac"
    }

    # Keys containing serial numbers
    SERIAL_KEYS = {"serial", "serial-num"}

    # Keys containing ASN
    ASN_KEYS = {"local-as", "remote-as", "localAs", "remoteAs"}

    # Top-level section names that should NOT be obfuscated
    TOP_LEVEL_SECTIONS = {
        "system", "interfaces", "routing", "counters", "global_protect", "vpn"
    }

    def __init__(self, level: str = "standard"):
        """
        Initialize the obfuscator.

        Args:
            level: Obfuscation level - 'minimal', 'standard', or 'paranoid'
        """
        self.level = level
        self.mapper = ObfuscationMapper()
        self._context_stack: list = []
        self._current_parent_key: Optional[str] = None

    def obfuscate(self, data: Any) -> Any:
        """Obfuscate sensitive data in the JSON structure."""
        return self._process(data)

    def _process(self, obj: Any, key: Optional[str] = None) -> Any:
        """Recursively process JSON data."""
        if isinstance(obj, dict):
            return self._process_dict(obj)
        elif isinstance(obj, list):
            return [self._process(item, key) for item in obj]
        elif isinstance(obj, str):
            return self._process_string(obj, key)
        elif isinstance(obj, (int, float)):
            return self._process_number(obj, key)
        else:
            return obj

    def _process_dict(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Process a dictionary, handling special cases for keys."""
        result = {}

        for key, value in obj.items():
            # Track context for nested processing
            old_parent = self._current_parent_key

            # Check if this key itself needs obfuscation BEFORE pushing to stack
            # This way _context_stack contains ancestors, not including current key
            new_key = self._maybe_obfuscate_key(key)

            # Now push the key onto the stack for processing children
            self._context_stack.append(key)

            # Check if we're entering a context that affects child processing
            if key in self.LOGICAL_ROUTER_PARENT_KEYS:
                self._current_parent_key = "logical_router"
            elif key in self.VPN_TUNNEL_PARENT_KEYS:
                self._current_parent_key = "vpn_tunnel"
            elif key in self.IKE_GATEWAY_PARENT_KEYS:
                self._current_parent_key = "ike_gateway"
            elif key == self.BGP_PEER_STATUS_KEY:
                self._current_parent_key = "bgp_peer_status"
            elif key in self.GP_GATEWAY_PARENT_KEYS:
                self._current_parent_key = "gp_gateway"
            elif key in self.GP_PORTAL_PARENT_KEYS:
                self._current_parent_key = "gp_portal"

            # Process the value
            result[new_key] = self._process(value, key)

            self._context_stack.pop()
            self._current_parent_key = old_parent

        return result

    def _maybe_obfuscate_key(self, key: str) -> str:
        """Check if a dictionary key itself should be obfuscated."""
        # Note: _context_stack contains parent keys, NOT including the current key
        # When called, self._context_stack[-1] is the parent of the current key
        
        stack_depth = len(self._context_stack)
        
        # Skip obfuscating top-level section names (depth 0, no parents)
        if stack_depth == 0 and key in self.TOP_LEVEL_SECTIONS:
            return key

        # Firewall hostname keys (direct children of top-level sections)
        # At this point, context_stack = ["system"] or similar, so depth = 1
        if stack_depth == 1 and self._context_stack[0] in self.TOP_LEVEL_SECTIONS:
            return self.mapper.get_mapping("hostname", key)

        # BGP peer status uses peer names as keys
        # The immediate children of bgp_peer_status are peer names
        if stack_depth > 0 and self._context_stack[-1] == self.BGP_PEER_STATUS_KEY:
            return self.mapper.get_mapping("bgp_peer", key)

        # Logical router names used as keys (e.g., "LR-LAN", "LR-WAN")
        if stack_depth > 0 and self._context_stack[-1] in self.LOGICAL_ROUTER_PARENT_KEYS:
            if self.level in ("standard", "paranoid"):
                return self.mapper.get_mapping("logical_router", key)

        return key

    def _process_string(self, value: str, key: Optional[str] = None) -> str:
        """Process a string value for potential obfuscation."""
        if not value or value in ("unknown", "n/a", "N/A", "null", "none", "None"):
            return value

        # Hostname fields
        if key in self.HOSTNAME_KEYS:
            return self.mapper.get_mapping("hostname", value)

        # Serial number fields
        if key in self.SERIAL_KEYS:
            return self.mapper.get_mapping("serial", str(value))

        # MAC address fields
        if key in self.MAC_KEYS or self.MAC_PATTERN.match(value):
            if self.level in ("standard", "paranoid"):
                return self.mapper.get_mapping("mac", value)

        # IP address fields
        if key in self.IP_KEYS:
            return self._obfuscate_ip_value(value)

        # Peer group names
        if key in self.PEER_GROUP_KEYS:
            return self.mapper.get_mapping("peer_group", value)

        # Route filter names
        if key in self.ROUTE_FILTER_KEYS:
            if self.level in ("standard", "paranoid"):
                return self.mapper.get_mapping("route_filter", value)

        # BGP peer name
        if key in self.BGP_PEER_KEYS:
            return self.mapper.get_mapping("bgp_peer", value)

        # VPN tunnel names (context-dependent)
        if key == "name" and self._current_parent_key == "vpn_tunnel":
            return self.mapper.get_mapping("vpn_tunnel", value)

        # IKE gateway names
        if key in self.IKE_GATEWAY_KEYS and self._current_parent_key in ("ike_gateway", "vpn_tunnel"):
            return self.mapper.get_mapping("ike_gateway", value)
        if key == "name" and self._current_parent_key == "ike_gateway":
            return self.mapper.get_mapping("ike_gateway", value)

        # GlobalProtect gateway names
        if key == "name" and self._current_parent_key == "gp_gateway":
            return self.mapper.get_mapping("gp_gateway", value)

        # GlobalProtect portal names
        if key == "name" and self._current_parent_key == "gp_portal":
            return self.mapper.get_mapping("gp_portal", value)

        # VLAN names in fwd field (format: "vlan:VL-Name")
        if key == self.VLAN_FWD_KEY and value.startswith("vlan:"):
            if self.level in ("standard", "paranoid"):
                vlan_name = value[5:]  # Remove "vlan:" prefix
                obfuscated = self.mapper.get_mapping("vlan_name", vlan_name)
                return f"vlan:{obfuscated}"

        # Handle compound IP strings like "192.168.1.1/24" or "1.2.3.4(ipaddr:1.2.3.4)"
        if self.IP_IN_STRING_PATTERN.search(value):
            return self._obfuscate_compound_ip_string(value)

        return value

    def _process_number(self, value: Any, key: Optional[str] = None) -> Any:
        """Process numeric values for potential obfuscation."""
        # Serial numbers can be numeric
        if key in self.SERIAL_KEYS:
            return self.mapper.get_mapping("serial", str(value))

        # ASN values
        if key in self.ASN_KEYS:
            if self.level == "paranoid":
                return int(self.mapper.get_mapping("asn", str(value)))

        return value

    def _obfuscate_ip_value(self, value: str) -> str:
        """Obfuscate an IP address value."""
        # Handle CIDR notation
        if "/" in value:
            ip_part, cidr = value.rsplit("/", 1)
            obfuscated_ip = self._obfuscate_single_ip(ip_part)
            return f"{obfuscated_ip}/{cidr}"

        # Check if it's a simple IP first
        result = self._obfuscate_single_ip(value)
        if result != value:
            return result

        # If unchanged, try compound IP string handling (e.g., "1.2.3.4(ipaddr:1.2.3.4)")
        if self.IP_IN_STRING_PATTERN.search(value):
            return self._obfuscate_compound_ip_string(value)

        return value

    def _obfuscate_single_ip(self, ip: str) -> str:
        """Obfuscate a single IP address."""
        ip = ip.strip()

        # Skip non-IP values
        if not ip or ip in ("unknown", "N/A", "n/a"):
            return ip

        # Check if it's a valid IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return ip

        # Determine if public or private
        if self.PUBLIC_IP_PATTERN.match(ip):
            return self.mapper.get_mapping("public_ip", ip)
        elif self.PRIVATE_IP_PATTERN.match(ip):
            if self.level in ("standard", "paranoid"):
                return self.mapper.get_mapping("private_ip", ip)
        
        return ip

    def _obfuscate_compound_ip_string(self, value: str) -> str:
        """Handle strings containing IPs like '1.2.3.4(ipaddr:1.2.3.4)'."""
        def replace_ip(match):
            ip = match.group(1)
            return self._obfuscate_single_ip(ip)

        return self.IP_IN_STRING_PATTERN.sub(replace_ip, value)

    def get_mappings(self) -> Dict[str, Dict[str, str]]:
        """Get all obfuscation mappings."""
        return self.mapper.export_mappings()


def main():
    parser = argparse.ArgumentParser(
        description="Obfuscate sensitive data in Palo Alto firewall JSON exports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Obfuscation Levels:
  minimal   - Only public IPs, hostnames, serial numbers, VPN/BGP names
  standard  - Above + private IPs, MAC addresses, VLAN names, route filters (default)
  paranoid  - Above + ASN numbers, all identifiable names

Examples:
  %(prog)s input.json output.json
  %(prog)s input.json output.json --level paranoid
  %(prog)s input.json output.json --level minimal --save-mapping mapping.json
  %(prog)s input.json -  # Output to stdout
        """
    )

    parser.add_argument(
        "input_file",
        help="Input JSON file to obfuscate"
    )
    parser.add_argument(
        "output_file",
        help="Output JSON file (use '-' for stdout)"
    )
    parser.add_argument(
        "--level", "-l",
        choices=["minimal", "standard", "paranoid"],
        default="standard",
        help="Obfuscation level (default: standard)"
    )
    parser.add_argument(
        "--save-mapping", "-m",
        metavar="FILE",
        help="Save obfuscation mapping to a JSON file for reference"
    )
    parser.add_argument(
        "--indent", "-i",
        type=int,
        default=2,
        help="JSON indentation level (default: 2)"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress informational output"
    )

    args = parser.parse_args()

    # Validate input file
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: Input file '{args.input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    # Load input JSON
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"Obfuscating '{args.input_file}' with level '{args.level}'...", file=sys.stderr)

    # Perform obfuscation
    obfuscator = JSONObfuscator(level=args.level)
    obfuscated_data = obfuscator.obfuscate(data)

    # Write output
    if args.output_file == "-":
        json.dump(obfuscated_data, sys.stdout, indent=args.indent)
        sys.stdout.write("\n")
    else:
        output_path = Path(args.output_file)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(obfuscated_data, f, indent=args.indent)
        if not args.quiet:
            print(f"Obfuscated data written to '{args.output_file}'", file=sys.stderr)

    # Save mapping if requested
    if args.save_mapping:
        mappings = obfuscator.get_mappings()
        mapping_path = Path(args.save_mapping)
        with open(mapping_path, "w", encoding="utf-8") as f:
            json.dump(mappings, f, indent=2)
        if not args.quiet:
            print(f"Obfuscation mapping saved to '{args.save_mapping}'", file=sys.stderr)

    # Print summary
    if not args.quiet:
        mappings = obfuscator.get_mappings()
        total = sum(len(v) for v in mappings.values())
        print(f"\nObfuscation summary:", file=sys.stderr)
        for category, mapping in mappings.items():
            if mapping:
                print(f"  {category}: {len(mapping)} unique values", file=sys.stderr)
        print(f"  Total: {total} values obfuscated", file=sys.stderr)


if __name__ == "__main__":
    main()

