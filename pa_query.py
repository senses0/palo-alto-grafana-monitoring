#!/usr/bin/env python3
"""
Palo Alto Networks Statistics Collection Tool
Standalone script for monitoring firewall statistics (read-only)
"""

import sys
import os
import json
import click
from pathlib import Path

# Add src directory to Python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.palo_alto_client.client import PaloAltoClient
from src.stats.system import SystemStats
from src.stats.network_interfaces import InterfaceStats
from src.stats.routing import RoutingStats
from src.stats.global_counters import GlobalCounters
from src.stats.global_protect import GlobalProtectStats
from src.stats.vpn_tunnels import VpnTunnelStats
from src.utils.logger import get_logger
from src.utils.table_formatters import (
    format_system_info_rich,
    format_interface_stats_rich,
    format_routing_info_rich,
    format_global_counters_rich,
    format_global_protect_rich,
    format_vpn_tunnels_rich,
    format_firewall_summary_rich,
    format_validation_rich
)

logger = get_logger(__name__)

def output_result(data, ctx, format_func=None):
    """Output data to stdout or file based on context."""
    output_file = ctx.obj.get('output_file')
    output_format = ctx.obj.get('output_format', 'json')
    
    if output_format == 'json':
        output_data = json.dumps(data, indent=2)
    else:
        # For table format, use the provided format function or default
        if format_func:
            output_data = format_func(data)
        else:
            output_data = str(data)
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(output_data)
            click.echo(f"Output written to: {output_file}")
        except Exception as e:
            click.echo(f"Error writing to file {output_file}: {e}", err=True)
            sys.exit(1)
    else:
        click.echo(output_data)

@click.group()
@click.option('--config', default='config/config.yaml', help='Configuration file path')
@click.option('--output', '-o', type=click.Choice(['json', 'table']), default='json', help='Output format')
@click.option('--output-file', '-f', type=click.Path(dir_okay=False, writable=True), help='Output file path (writes to file instead of stdout)')
@click.option('--firewall', help='Specific firewall name to target')
@click.option('--host', help='Firewall hostname or IP (for single firewall mode)')
@click.option('--api-key', help='API key for authentication (for single firewall mode)')
@click.pass_context
def cli(ctx, config, output, output_file, firewall, host, api_key):
    """Palo Alto Networks statistics collection tool (read-only)."""
    ctx.ensure_object(dict)
    ctx.obj['output_format'] = output
    ctx.obj['output_file'] = output_file
    
    try:
        # Initialize client
        if firewall:
            ctx.obj['client'] = PaloAltoClient(firewall_name=firewall, host=host)
        else:
            ctx.obj['client'] = PaloAltoClient(host=host)
        
        # Initialize stats collectors
        ctx.obj['system'] = SystemStats(ctx.obj['client'])
        ctx.obj['interface'] = InterfaceStats(ctx.obj['client'])
        ctx.obj['routing'] = RoutingStats(ctx.obj['client'])
        ctx.obj['counters'] = GlobalCounters(ctx.obj['client'])
        ctx.obj['global_protect'] = GlobalProtectStats(ctx.obj['client'])
        ctx.obj['vpn'] = VpnTunnelStats(ctx.obj['client'])
        
    except Exception as e:
        click.echo(f"Error initializing client: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def system_info(ctx):
    """Get system information from all firewalls."""
    try:
        info = ctx.obj['system'].get_system_data()
        
        # Wrap in module name for consistency with all-stats
        wrapped_data = {'system': info}
        
        def format_system_info(data):
            """Format system info for table output."""
            return format_system_info_rich(data)
        
        output_result(wrapped_data, ctx, format_system_info)
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def interface_stats(ctx):
    """Get interface statistics from all firewalls."""
    try:
        stats = ctx.obj['interface'].get_interface_data()
        
        # Wrap in module name for consistency with all-stats
        wrapped_data = {'interfaces': stats}
        
        def format_interface_stats(data):
            """Format interface stats for table output."""
            return format_interface_stats_rich(data)
        
        output_result(wrapped_data, ctx, format_interface_stats)
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def routing_info(ctx):
    """Get routing information from all firewalls."""
    try:
        results = ctx.obj['routing'].get_routing_data()
        
        # Wrap in module name for consistency with all-stats
        wrapped_data = {'routing': results}
        
        def format_routing_info(data):
            """Format routing info for table output."""
            return format_routing_info_rich(data)
        
        output_result(wrapped_data, ctx, format_routing_info)
    
    except Exception as e:
        click.echo(f"Error getting routing info: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def global_counters(ctx):
    """Get global counter statistics from all firewalls."""
    try:
        counters = ctx.obj['counters'].get_counter_data()
        
        # Wrap in module name for consistency with all-stats
        wrapped_data = {'counters': counters}
        
        def format_global_counters(data):
            """Format global counters for table output."""
            return format_global_counters_rich(data)
        
        output_result(wrapped_data, ctx, format_global_counters)
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def global_protect(ctx):
    """Get GlobalProtect statistics from all firewalls."""
    try:
        gp_stats = ctx.obj['global_protect'].get_global_protect_data()
        
        # Wrap in module name for consistency with all-stats
        wrapped_data = {'global_protect': gp_stats}
        
        def format_global_protect(data):
            """Format GlobalProtect stats for table output."""
            return format_global_protect_rich(data)
        
        output_result(wrapped_data, ctx, format_global_protect)
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def vpn_tunnels(ctx):
    """Get VPN tunnel statistics from all firewalls."""
    try:
        vpn_stats = ctx.obj['vpn'].get_vpn_data()
        
        # Wrap in module name for consistency with all-stats
        wrapped_data = {'vpn': vpn_stats}
        
        def format_vpn_tunnels(data):
            """Format VPN tunnel stats for table output."""
            return format_vpn_tunnels_rich(data)
        
        output_result(wrapped_data, ctx, format_vpn_tunnels)
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def all_stats(ctx):
    """Get all available statistics from all firewalls."""
    try:
        all_data = {}
        
        # Collect all stats
        all_data['system'] = ctx.obj['system'].get_system_data()
        all_data['interfaces'] = ctx.obj['interface'].get_interface_data()
        all_data['routing'] = ctx.obj['routing'].get_routing_data()
        all_data['counters'] = ctx.obj['counters'].get_counter_data()
        all_data['global_protect'] = ctx.obj['global_protect'].get_global_protect_data()
        all_data['vpn'] = ctx.obj['vpn'].get_vpn_data()
        
        def format_all_stats(data):
            """Format all stats for table output."""
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich import box
            
            console_local = Console()
            output = []
            
            # Summary panel
            summary_table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            summary_table.add_column("Module", style="yellow")
            summary_table.add_column("Status", style="white")
            
            for module_name, module_data in data.items():
                success_count = sum(1 for fw_result in module_data.values() if fw_result.get('success', False))
                total_count = len(module_data)
                status_style = "green" if success_count == total_count else "yellow" if success_count > 0 else "red"
                summary_table.add_row(
                    module_name.replace('_', ' ').title(),
                    f"[{status_style}]{success_count}/{total_count} firewalls[/{status_style}]"
                )
            
            header = Panel(
                "[bold white]All Statistics Collection Summary[/bold white]\n\n"
                "Use individual commands for detailed tables or --output json for complete data",
                style="bold blue",
                border_style="blue"
            )
            
            with console_local.capture() as capture:
                console_local.print(header)
                console_local.print(summary_table)
            
            return capture.get()
        
        output_result(all_data, ctx, format_all_stats)
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def firewall_summary(ctx):
    """Get summary of all configured firewalls."""
    try:
        summary = ctx.obj['client'].get_firewall_summary()
        
        def format_firewall_summary(data):
            """Format firewall summary for table output."""
            return format_firewall_summary_rich(data)
        
        output_result(summary, ctx, format_firewall_summary)
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.pass_context
def validate_config(ctx):
    """Validate all firewall configurations."""
    try:
        validation = ctx.obj['client'].validate_firewall_config()
        
        def format_validation(data):
            """Format validation results for table output."""
            return format_validation_rich(data)
        
        output_result(validation, ctx, format_validation)
    
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()
