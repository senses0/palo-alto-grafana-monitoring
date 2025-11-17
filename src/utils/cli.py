#!/usr/bin/env python3
"""Command-line interface for Palo Alto stats (read-only)."""

import click
import json
import sys
from tabulate import tabulate
from datetime import datetime

from ..palo_alto_client.client import PaloAltoClient
from ..stats.network_interfaces import InterfaceStats
from ..stats.system import SystemStats
from ..stats.routing import RoutingStats
from ..utils.logger import get_logger

logger = get_logger(__name__)

@click.group()
@click.option('--firewall', help='Specific firewall name to target')
@click.option('--host', help='Firewall hostname or IP (for single firewall mode)')
@click.option('--api-key', help='API key for authentication (for single firewall mode)')
@click.option('--output', '-o', type=click.Choice(['json', 'table']), default='table', help='Output format')
@click.pass_context
def cli(ctx, firewall, host, api_key, output):
    """Palo Alto Networks statistics collection tool (read-only)."""
    ctx.ensure_object(dict)
    
    ctx.obj['output_format'] = output
    
    try:
        # Initialize client with unified multi-firewall support
        if firewall:
            # Single firewall mode
            ctx.obj['client'] = PaloAltoClient(firewall_name=firewall, host=host)
        else:
            # Multi-firewall mode (default)
            ctx.obj['client'] = PaloAltoClient(host=host)
        
        ctx.obj['interface'] = InterfaceStats(ctx.obj['client'])
        ctx.obj['system'] = SystemStats(ctx.obj['client'])
        ctx.obj['routing'] = RoutingStats(ctx.obj['client'])
    except Exception as e:
        click.echo(f"Error initializing client: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def system_info(ctx):
    """Get system information from all firewalls."""
    try:
        info = ctx.obj['system'].get_system_data()
        
        if ctx.obj['output_format'] == 'json':
            click.echo(json.dumps(info, indent=2))
        else:
            # Display results for each firewall
            for firewall_name, result in info.items():
                if result['success']:
                    click.echo(f"\n=== {firewall_name} ===")
                    system = result['data'].get('system_info', {}).get('system', {})
                    if system:
                        table_data = [
                            ['Hostname', system.get('hostname', 'N/A')],
                            ['Model', system.get('model', 'N/A')],
                            ['Serial', system.get('serial', 'N/A')],
                            ['Version', system.get('sw-version', 'N/A')],
                            ['Uptime', system.get('uptime', 'N/A')]
                        ]
                        click.echo(tabulate(table_data, headers=['Property', 'Value'], tablefmt='grid'))
                    else:
                        click.echo("No system information available")
                else:
                    click.echo(f"\n=== {firewall_name} ===")
                    click.echo(f"Error: {result['error']}")
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def interface_stats(ctx):
    """Get interface statistics and counters from all firewalls."""
    try:
        stats = ctx.obj['interface'].get_interface_data()
        
        if ctx.obj['output_format'] == 'json':
            click.echo(json.dumps(stats, indent=2))
        else:
            # Display results for each firewall
            for firewall_name, result in stats.items():
                if result['success']:
                    click.echo(f"\n=== {firewall_name} ===")
                    data = result['data']
                    
                    # Display session info
                    session_info = data.get('session_info', {})
                    if session_info:
                        click.echo("Session Information:")
                        session_data = [
                            ['Active Sessions', session_info.get('num-active', 'N/A')],
                            ['Maximum Sessions', session_info.get('num-max', 'N/A')],
                            ['Utilization %', session_info.get('pct-utilization', 'N/A')]
                        ]
                        click.echo(tabulate(session_data, headers=['Metric', 'Value'], tablefmt='grid'))
                        click.echo()
                    
                    # Display interface counters summary
                    interface_counters = data.get('interface_counters', {})
                    if 'ifnet' in interface_counters:
                        click.echo("Interface Counters (Top 5):")
                        interfaces = interface_counters['ifnet'].get('entry', [])
                        if isinstance(interfaces, dict):
                            interfaces = [interfaces]
                        
                        if_data = []
                        for interface in interfaces[:5]:
                            if_data.append([
                                interface.get('name', 'Unknown'),
                                interface.get('ibytes', 'N/A'),
                                interface.get('obytes', 'N/A'),
                                interface.get('ipackets', 'N/A'),
                                interface.get('opackets', 'N/A')
                            ])
                        
                        if if_data:
                            click.echo(tabulate(if_data, headers=['Interface', 'RX Bytes', 'TX Bytes', 'RX Packets', 'TX Packets'], tablefmt='grid'))
                else:
                    click.echo(f"\n=== {firewall_name} ===")
                    click.echo(f"Error: {result['error']}")
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def resource_usage(ctx):
    """Get resource usage from all firewalls."""
    try:
        resources = ctx.obj['system'].get_resource_usage()
        
        if ctx.obj['output_format'] == 'json':
            click.echo(json.dumps(resources, indent=2))
        else:
            # Display results for each firewall
            for firewall_name, result in resources.items():
                if result['success']:
                    click.echo(f"\n=== {firewall_name} ===")
                    data = result['data']
                    
                    if data:
                        # Display CPU and memory information
                        cpu_user = data.get('cpu_user', 'N/A')
                        cpu_system = data.get('cpu_system', 'N/A')
                        cpu_idle = data.get('cpu_idle', 'N/A')
                        memory_usage = data.get('memory_usage_percent', 'N/A')
                        load_1min = data.get('load_average_1min', 'N/A')
                        load_5min = data.get('load_average_5min', 'N/A')
                        load_15min = data.get('load_average_15min', 'N/A')
                        
                        table_data = [
                            ['CPU User %', cpu_user],
                            ['CPU System %', cpu_system],
                            ['CPU Idle %', cpu_idle],
                            ['Memory Usage %', memory_usage],
                            ['Load Average (1/5/15 min)', f"{load_1min}/{load_5min}/{load_15min}"]
                        ]
                        click.echo(tabulate(table_data, headers=['Metric', 'Value'], tablefmt='grid'))
                    else:
                        click.echo("No resource usage data available")
                else:
                    click.echo(f"\n=== {firewall_name} ===")
                    click.echo(f"Error: {result['error']}")
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def firewall_summary(ctx):
    """Get summary of all configured firewalls."""
    try:
        summary = ctx.obj['client'].get_firewall_summary()
        
        if ctx.obj['output_format'] == 'json':
            click.echo(json.dumps(summary, indent=2))
        else:
            click.echo(f"Total Firewalls: {summary['total_firewalls']}")
            click.echo()
            
            for name, config in summary['firewalls'].items():
                click.echo(f"=== {name} ===")
                table_data = [
                    ['Host', config.get('host', 'N/A')],
                    ['Port', config.get('port', 'N/A')],
                    ['Description', config.get('description', 'N/A')],
                    ['Location', config.get('location', 'N/A')],
                    ['SSL Verify', config.get('verify_ssl', 'N/A')],
                    ['Timeout', config.get('timeout', 'N/A')]
                ]
                click.echo(tabulate(table_data, headers=['Property', 'Value'], tablefmt='grid'))
                click.echo()
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def validate_config(ctx):
    """Validate all firewall configurations."""
    try:
        validation = ctx.obj['client'].validate_firewall_config()
        
        if ctx.obj['output_format'] == 'json':
            click.echo(json.dumps(validation, indent=2))
        else:
            for firewall_name, result in validation.items():
                click.echo(f"=== {firewall_name} ===")
                if result['valid']:
                    click.echo("✅ Configuration is valid")
                else:
                    click.echo("❌ Configuration has errors:")
                    for error in result['errors']:
                        click.echo(f"  - {error}")
                click.echo()
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def routing_info(ctx):
    """Get routing information from all firewalls."""
    try:
        results = ctx.obj['routing'].get_routing_data()
        
        if ctx.obj['output_format'] == 'json':
            click.echo(json.dumps(results, indent=2))
        else:
            # Display results for each firewall
            for firewall_name, data in results.items():
                routing_mode = data.get('routing_mode', 'Unknown')
                click.echo(f"\n=== {firewall_name} (Routing Mode: {routing_mode}) ===")
                
                # Show available collections
                collections = [k for k, v in data.items() if k not in ['routing_mode', 'timestamp'] and v]
                if collections:
                    click.echo(f"Available collections: {', '.join(collections)}")
                    
                    # Show BGP peer status if available
                    if 'bgp_peer_status' in data and data['bgp_peer_status']:
                        click.echo("\n--- BGP Peer Status ---")
                        formatted_status = ctx.obj['routing'].format_bgp_peer_status_for_display(data['bgp_peer_status'])
                        click.echo(formatted_status)
                else:
                    click.echo("No routing data available")
    except Exception as e:
        click.echo(f"Error getting routing info: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()