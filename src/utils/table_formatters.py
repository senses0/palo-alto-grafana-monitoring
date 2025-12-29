#!/usr/bin/env python3
"""
Rich table formatters for Palo Alto firewall statistics output.
Provides beautiful, colorful tabular output for CLI commands.
"""

from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from collections import defaultdict

console = Console()


def format_system_info_rich(data: Dict[str, Any]) -> str:
    """Format system info data with Rich tables."""
    output = []
    
    # Unwrap for table display
    system_data = data.get('system', data)
    
    for firewall_name, result in system_data.items():
        # Firewall header
        header = Panel(
            f"[bold white]{firewall_name}[/bold white]",
            style="bold cyan",
            border_style="cyan"
        )
        output.append(header)
        
        if not result.get('success'):
            error_panel = Panel(
                f"[bold red]Error:[/bold red] {result.get('error', 'Unknown error')}",
                border_style="red"
            )
            output.append(error_panel)
            continue
        
        data_dict = result.get('data', {})
        
        # System Information Table
        if 'system_info' in data_dict and 'system' in data_dict['system_info']:
            system = data_dict['system_info']['system']
            
            table = Table(
                title="[bold magenta]System Information[/bold magenta]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Property", style="yellow", no_wrap=True)
            table.add_column("Value", style="green")
            
            table.add_row("Hostname", str(system.get('hostname', 'N/A')))
            table.add_row("IP Address", str(system.get('ip-address', 'N/A')))
            table.add_row("Model", str(system.get('model', 'N/A')))
            table.add_row("Serial", str(system.get('serial', 'N/A')))
            table.add_row("SW Version", str(system.get('sw-version', 'N/A')))
            table.add_row("Family", str(system.get('family', 'N/A')))
            table.add_row("Operational Mode", str(system.get('operational-mode', 'N/A')))
            table.add_row("Uptime", str(system.get('uptime', 'N/A')))
            
            output.append(table)
        
        # Resource Usage Table
        if 'resource_usage' in data_dict:
            resources = data_dict['resource_usage']
            
            table = Table(
                title="[bold blue]Resource Usage[/bold blue]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Metric", style="yellow", no_wrap=True)
            table.add_column("Value", style="white")
            
            # CPU
            cpu_total = 100 - resources.get('cpu_idle', 0)
            cpu_style = "green" if cpu_total < 70 else "yellow" if cpu_total < 90 else "red"
            table.add_row(
                "CPU Usage",
                f"[{cpu_style}]{cpu_total:.1f}%[/{cpu_style}] (User: {resources.get('cpu_user', 0):.1f}%, System: {resources.get('cpu_system', 0):.1f}%, Idle: {resources.get('cpu_idle', 0):.1f}%)"
            )
            
            # Memory
            mem_percent = resources.get('memory_usage_percent', 0)
            mem_style = "green" if mem_percent < 70 else "yellow" if mem_percent < 90 else "red"
            table.add_row(
                "Memory",
                f"[{mem_style}]{mem_percent:.1f}%[/{mem_style}] ({resources.get('memory_used_mib', 0):.0f} / {resources.get('memory_total_mib', 0):.0f} MiB)"
            )
            
            # Swap
            swap_percent = resources.get('swap_usage_percent', 0)
            swap_style = "green" if swap_percent < 30 else "yellow" if swap_percent < 70 else "red"
            table.add_row(
                "Swap",
                f"[{swap_style}]{swap_percent:.1f}%[/{swap_style}] ({resources.get('swap_used_mib', 0):.0f} / {resources.get('swap_total_mib', 0):.0f} MiB)"
            )
            
            # Load Average
            load_1 = resources.get('load_average_1min', 0)
            table.add_row(
                "Load Average",
                f"{load_1:.2f} / {resources.get('load_average_5min', 0):.2f} / {resources.get('load_average_15min', 0):.2f}"
            )
            
            output.append(table)
    
    # Render to string
    with console.capture() as capture:
        for item in output:
            console.print(item)
            console.print()
    
    return capture.get()


def format_interface_stats_rich(data: Dict[str, Any]) -> str:
    """Format interface statistics with Rich tables."""
    output = []
    
    # Unwrap for table display
    interface_data = data.get('interfaces', data)
    
    for firewall_name, result in interface_data.items():
        # Firewall header
        header = Panel(
            f"[bold white]{firewall_name}[/bold white]",
            style="bold yellow",
            border_style="yellow"
        )
        output.append(header)
        
        if not result.get('success'):
            error_panel = Panel(
                f"[bold red]Error:[/bold red] {result.get('error', 'Unknown error')}",
                border_style="red"
            )
            output.append(error_panel)
            continue
        
        data_dict = result.get('data', {})
        
        # Hardware Interfaces Table
        if 'interface_info' in data_dict and 'hw' in data_dict['interface_info']:
            hw_info = data_dict['interface_info']['hw']
            if 'entry' in hw_info:
                entries = hw_info['entry'] if isinstance(hw_info['entry'], list) else [hw_info['entry']]
                
                table = Table(
                    title="[bold yellow]Hardware Interfaces[/bold yellow]",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                table.add_column("Interface", style="cyan", no_wrap=True)
                table.add_column("State", style="white")
                table.add_column("Speed", style="magenta")
                table.add_column("Duplex", style="blue")
                table.add_column("MAC", style="dim")
                
                for iface in entries:
                    state = iface.get('state', 'unknown')
                    state_style = "green" if state == "up" else "red" if state == "down" else "yellow"
                    
                    table.add_row(
                        iface.get('name', 'N/A'),
                        f"[{state_style}]{state.upper()}[/{state_style}]",
                        f"{iface.get('speed', 'N/A')}",
                        iface.get('duplex', 'N/A'),
                        iface.get('mac', 'N/A')
                    )
                
                output.append(table)
        
        # Logical Interfaces Table
        if 'interface_info' in data_dict and 'ifnet' in data_dict['interface_info']:
            ifnet_info = data_dict['interface_info']['ifnet']
            if 'entry' in ifnet_info:
                entries = ifnet_info['entry'] if isinstance(ifnet_info['entry'], list) else [ifnet_info['entry']]
                
                table = Table(
                    title="[bold green]Logical Interfaces (Layer 3)[/bold green]",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                table.add_column("Interface", style="cyan", no_wrap=True)
                table.add_column("Zone", style="blue")
                table.add_column("IP Address", style="green")
                table.add_column("VRF/Routing", style="yellow")
                
                for iface in entries:
                    table.add_row(
                        iface.get('name', 'N/A'),
                        iface.get('zone', 'N/A'),
                        iface.get('ip', 'N/A'),
                        iface.get('fwd', 'N/A')
                    )
                
                output.append(table)
        
        # Interface Counters Table
        if 'interface_counters' in data_dict and 'hw' in data_dict['interface_counters']:
            hw_counters = data_dict['interface_counters']['hw']
            if 'entry' in hw_counters:
                entries = hw_counters['entry'] if isinstance(hw_counters['entry'], list) else [hw_counters['entry']]
                
                table = Table(
                    title="[bold cyan]Interface Traffic Counters[/bold cyan]",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                table.add_column("Interface", style="cyan", no_wrap=True)
                table.add_column("RX Bytes", style="green", justify="right")
                table.add_column("TX Bytes", style="blue", justify="right")
                table.add_column("RX Packets", style="green", justify="right")
                table.add_column("TX Packets", style="blue", justify="right")
                table.add_column("Errors", style="red", justify="right")
                
                for iface in entries:
                    port = iface.get('port', {})
                    rx_errors = port.get('rx-error', 0)
                    tx_errors = port.get('tx-error', 0)
                    total_errors = rx_errors + tx_errors
                    error_style = "green" if total_errors == 0 else "yellow" if total_errors < 100 else "red"
                    
                    table.add_row(
                        iface.get('name', 'N/A'),
                        f"{port.get('rx-bytes', 0):,}",
                        f"{port.get('tx-bytes', 0):,}",
                        f"{port.get('rx-unicast', 0):,}",
                        f"{port.get('tx-unicast', 0):,}",
                        f"[{error_style}]{total_errors:,}[/{error_style}]"
                    )
                
                output.append(table)
    
    # Render to string
    with console.capture() as capture:
        for item in output:
            console.print(item)
            console.print()
    
    return capture.get()


def format_routing_info_rich(data: Dict[str, Any]) -> str:
    """Format routing information with Rich tables."""
    output = []
    
    # Unwrap for table display
    routing_data = data.get('routing', data)
    
    for firewall_name, result in routing_data.items():
        # Firewall header
        header = Panel(
            f"[bold white]{firewall_name}[/bold white]",
            style="bold red",
            border_style="red"
        )
        output.append(header)
        
        if not result.get('success'):
            error_panel = Panel(
                f"[bold red]Error:[/bold red] {result.get('error', 'Unknown error')}",
                border_style="red"
            )
            output.append(error_panel)
            continue
        
        # Unwrap the data structure
        firewall_data = result.get('data', {})
        routing_mode = firewall_data.get('routing_mode', 'Unknown')
        
        # Update header with routing mode info
        info_table = Table(
            title="[bold yellow]Routing Overview[/bold yellow]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
        )
        info_table.add_column("Property", style="yellow")
        info_table.add_column("Value", style="white")
        info_table.add_row("Routing Mode", routing_mode)
        output.append(info_table)
        
        # BGP Summary (per VRF configuration)
        if 'bgp_summary' in firewall_data and firewall_data['bgp_summary']:
            bgp_summary_raw = firewall_data['bgp_summary']
            
            # Handle both normalized (VRF-keyed dict) and raw legacy format
            bgp_summary = {}
            if 'entry' in bgp_summary_raw and isinstance(bgp_summary_raw.get('entry'), dict):
                # Raw legacy format - single entry with @virtual-router attribute
                entry = bgp_summary_raw['entry']
                vrf_name = entry.get('@virtual-router', 'default')
                # Remove @ attributes
                normalized_entry = {k: v for k, v in entry.items() if not k.startswith('@')}
                bgp_summary = {vrf_name: normalized_entry}
            else:
                # Already normalized format
                bgp_summary = bgp_summary_raw
            
            summary_table = Table(
                title="[bold red]BGP Configuration Summary[/bold red]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            summary_table.add_column("VRF", style="cyan", no_wrap=True)
            summary_table.add_column("Router ID", style="blue")
            summary_table.add_column("Local AS", style="yellow")
            summary_table.add_column("Graceful Restart", style="green")
            summary_table.add_column("Status", style="white")
            
            for vrf_name, vrf_config in bgp_summary.items():
                if isinstance(vrf_config, dict):
                    enabled = vrf_config.get('enabled', 'no')
                    status_style = "green" if enabled == 'yes' else "red"
                    
                    summary_table.add_row(
                        vrf_name,
                        vrf_config.get('router-id', 'N/A'),
                        str(vrf_config.get('local-as', 'N/A')),
                        str(vrf_config.get('graceful-restart', 'N/A')),
                        f"[{status_style}]{enabled.upper()}[/{status_style}]"
                    )
            
            output.append(summary_table)
        
        # BGP Peer Status
        if 'bgp_peer_status' in firewall_data and firewall_data['bgp_peer_status']:
            bgp_peers_raw = firewall_data['bgp_peer_status']
            
            # Handle both normalized (peer-name-keyed dict) and raw legacy format
            bgp_peers = {}
            if 'entry' in bgp_peers_raw and isinstance(bgp_peers_raw.get('entry'), list):
                # Raw legacy format - convert to normalized format
                entries = bgp_peers_raw['entry']
                for entry in entries:
                    if isinstance(entry, dict):
                        peer_name = entry.get('@peer', entry.get('peer-name', 'unknown'))
                        # Map legacy field names to normalized names
                        normalized_entry = {}
                        for k, v in entry.items():
                            if k.startswith('@'):
                                continue
                            elif k == 'status':
                                normalized_entry['state'] = v
                            elif k == 'status-duration':
                                normalized_entry['status-time'] = v
                            elif k == 'peer-address':
                                normalized_entry['peer-ip'] = v
                            else:
                                normalized_entry[k] = v
                        
                        # Preserve prefix-counter for legacy mode
                        normalized_entry['prefix-counter'] = entry.get('prefix-counter')
                        bgp_peers[peer_name] = normalized_entry
            else:
                # Already normalized format
                bgp_peers = bgp_peers_raw
            
            # Summary statistics
            total_peers = len(bgp_peers)
            established = sum(1 for p in bgp_peers.values() if isinstance(p, dict) and p.get('state') == 'Established')
            down = total_peers - established
            
            summary_table = Table(
                title="[bold red]BGP Peer Summary[/bold red]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            summary_table.add_column("Metric", style="yellow")
            summary_table.add_column("Value", style="white", justify="right")
            
            summary_table.add_row("Total Peers", str(total_peers))
            summary_table.add_row(
                "Established",
                f"[green]{established}[/green]"
            )
            summary_table.add_row(
                "Down",
                f"[red]{down}[/red]" if down > 0 else "[green]0[/green]"
            )
            
            output.append(summary_table)
            
            # Detailed peer table
            peer_table = Table(
                title="[bold red]BGP Peer Details[/bold red]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            peer_table.add_column("Peer Name", style="cyan", no_wrap=True)
            peer_table.add_column("State", style="white")
            peer_table.add_column("Peer IP", style="blue")
            peer_table.add_column("Remote AS", style="yellow")
            peer_table.add_column("Uptime", style="magenta")
            peer_table.add_column("Prefixes ⬇/⬆", style="white", justify="right")
            
            for peer_name, peer_info in bgp_peers.items():
                if not isinstance(peer_info, dict):
                    continue
                
                state = peer_info.get('state', 'Unknown')
                # Color code based on BGP state
                if state == 'Established':
                    state_style = "green"
                elif state in ['Connect', 'Active', 'OpenSent', 'OpenConfirm']:
                    state_style = "yellow"  # Transitional states
                else:
                    state_style = "red"  # Idle or other problematic states
                
                # Get uptime
                uptime = "N/A"
                detail = peer_info.get('detail', {})
                if detail and 'bgpTimerUpString' in detail:
                    uptime = detail['bgpTimerUpString']
                elif 'status-time' in peer_info:
                    # Format status time in a readable way
                    seconds = int(peer_info['status-time'])
                    if seconds >= 86400:  # More than a day
                        days = seconds // 86400
                        hours = (seconds % 86400) // 3600
                        uptime = f"{days}d {hours}h"
                    elif seconds >= 3600:  # More than an hour
                        hours = seconds // 3600
                        minutes = (seconds % 3600) // 60
                        uptime = f"{hours}h {minutes}m"
                    elif seconds >= 60:  # More than a minute
                        minutes = seconds // 60
                        secs = seconds % 60
                        uptime = f"{minutes}m {secs}s"
                    else:
                        uptime = f"{seconds}s"
                
                # Get prefix counts
                prefixes_in = 0
                prefixes_out = 0
                
                # Handle both legacy and advanced routing modes
                if routing_mode == 'legacy':
                    # Legacy mode: prefix-counter.entry structure
                    prefix_counter = peer_info.get('prefix-counter')
                    if prefix_counter and isinstance(prefix_counter, dict):
                        entry = prefix_counter.get('entry', {})
                        if entry:
                            prefixes_in = entry.get('incoming-accepted', 0)
                            prefixes_out = entry.get('outgoing-advertised', 0)
                else:
                    # Advanced mode: detail.addressFamilyInfo structure
                    if detail:
                        af_info = detail.get('addressFamilyInfo', {})
                        ipv4_info = af_info.get('ipv4Unicast', {})
                        if ipv4_info:
                            prefixes_in = ipv4_info.get('acceptedPrefixCounter', 0)
                            prefixes_out = ipv4_info.get('sentPrefixCounter', 0)
                
                peer_table.add_row(
                    peer_name,
                    f"[{state_style}]{state}[/{state_style}]",
                    peer_info.get('peer-ip', 'N/A'),
                    str(peer_info.get('remote-as', 'N/A')),
                    uptime,
                    f"[green]{prefixes_in:,}[/green] / [blue]{prefixes_out:,}[/blue]"
                )
            
            output.append(peer_table)
        
        # Routing Table Summary
        if 'routing_table' in firewall_data and firewall_data['routing_table']:
            route_table = firewall_data['routing_table']
            
            # Handle both normalized (VRF-keyed) and raw legacy format
            vrf_data = []
            
            # Check if this is raw legacy format with 'entry' field
            if 'entry' in route_table and isinstance(route_table.get('entry'), list):
                # Raw legacy format - group by VRF
                vrf_groups = defaultdict(list)
                for route in route_table['entry']:
                    if isinstance(route, dict):
                        vrf_name = route.get('virtual-router', 'default')
                        vrf_groups[vrf_name].append(route)
                
                # Count protocols for each VRF
                for vrf_name, routes in vrf_groups.items():
                    protocol_counts = defaultdict(int)
                    for route in routes:
                        # Determine protocol from flags
                        flags = route.get('flags', '')
                        if 'B' in flags:
                            protocol = 'bgp'
                        elif 'S' in flags:
                            protocol = 'static'
                        elif 'C' in flags:
                            protocol = 'connected'
                        else:
                            protocol = 'other'
                        protocol_counts[protocol] += 1
                    
                    total = len(routes)
                    vrf_data.append((vrf_name, protocol_counts, total))
            else:
                # Normalized format (VRF-keyed)
                for vrf_name, vrf_routes in route_table.items():
                    # Skip metadata fields
                    if vrf_name in ['flags'] or not isinstance(vrf_routes, dict):
                        continue
                    
                    protocol_counts = defaultdict(int)
                    total = 0
                    
                    for prefix, route_list in vrf_routes.items():
                        if isinstance(route_list, list):
                            for route in route_list:
                                # Try to get protocol field first (advanced mode)
                                protocol = route.get('protocol')
                                
                                # If no protocol field, derive from flags (legacy mode)
                                if not protocol:
                                    flags = route.get('flags', '')
                                    if 'B' in flags:
                                        protocol = 'bgp'
                                    elif 'S' in flags:
                                        protocol = 'static'
                                    elif 'C' in flags:
                                        protocol = 'connected'
                                    else:
                                        protocol = 'other'
                                
                                protocol_counts[protocol] += 1
                                total += 1
                    
                    vrf_data.append((vrf_name, protocol_counts, total))
            
            table = Table(
                title="[bold green]Routing Table Summary[/bold green]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("VRF", style="cyan", no_wrap=True)
            table.add_column("Total Routes", style="yellow", justify="right")
            table.add_column("BGP", style="blue", justify="right")
            table.add_column("Static", style="green", justify="right")
            table.add_column("Connected", style="magenta", justify="right")
            table.add_column("Other", style="dim", justify="right")
            
            for vrf_name, protocol_counts, total in vrf_data:
                table.add_row(
                    vrf_name,
                    f"{total:,}",
                    f"{protocol_counts.get('bgp', 0):,}",
                    f"{protocol_counts.get('static', 0):,}",
                    f"{protocol_counts.get('connected', 0):,}",
                    f"{sum(v for k, v in protocol_counts.items() if k not in ['bgp', 'static', 'connected']):,}"
                )
            
            output.append(table)
        
        # Path Monitor Status
        if 'bgp_path_monitor' in firewall_data and firewall_data['bgp_path_monitor'] and 'entry' in firewall_data['bgp_path_monitor']:
            entries = firewall_data['bgp_path_monitor']['entry']
            if entries:
                table = Table(
                    title="[bold magenta]BGP Path Monitor Status[/bold magenta]",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                table.add_column("Destination", style="cyan")
                table.add_column("Next Hop", style="blue")
                table.add_column("Interface", style="yellow")
                table.add_column("Status", style="white")
                table.add_column("Monitors", style="dim")
                
                for entry in entries:
                    status = entry.get('pathmonitor-status', 'Unknown')
                    status_style = "green" if status == 'Up' else "red"
                    
                    # Collect monitor info
                    monitors = []
                    for i in range(10):
                        if f'monitordst-{i}' in entry:
                            mon_status = entry.get(f'monitorstatus-{i}', 'Unknown')
                            mon_style = "green" if mon_status == 'Success' else "red"
                            monitors.append(f"[{mon_style}]●[/{mon_style}]")
                    
                    monitor_str = " ".join(monitors) if monitors else "N/A"
                    
                    table.add_row(
                        entry.get('destination', 'N/A'),
                        entry.get('nexthop', 'N/A'),
                        entry.get('interface', 'N/A'),
                        f"[{status_style}]{status}[/{status_style}]",
                        monitor_str
                    )
                
                output.append(table)
    
    # Render to string
    with console.capture() as capture:
        for item in output:
            console.print(item)
            console.print()
    
    return capture.get()


def format_global_counters_rich(data: Dict[str, Any]) -> str:
    """Format global counters with Rich tables."""
    output = []
    
    # Unwrap for table display
    counter_data = data.get('counters', data)
    
    for firewall_name, result in counter_data.items():
        # Firewall header
        header = Panel(
            f"[bold white]{firewall_name}[/bold white]",
            style="bold magenta",
            border_style="magenta"
        )
        output.append(header)
        
        if not result.get('success'):
            error_panel = Panel(
                f"[bold red]Error:[/bold red] {result.get('error', 'Unknown error')}",
                border_style="red"
            )
            output.append(error_panel)
            continue
        
        data_dict = result.get('data', {})
        
        # Session Info
        if 'session_info' in data_dict:
            session_info = data_dict['session_info']
            
            table = Table(
                title="[bold cyan]Session Statistics[/bold cyan]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Metric", style="yellow", no_wrap=True)
            table.add_column("Value", style="white", justify="right")
            
            table.add_row("Active Sessions", f"{session_info.get('num-active', 0):,}")
            table.add_row("Max Sessions", f"{session_info.get('num-max', 0):,}")
            table.add_row("TCP Sessions", f"{session_info.get('num-tcp', 0):,}")
            table.add_row("UDP Sessions", f"{session_info.get('num-udp', 0):,}")
            table.add_row("ICMP Sessions", f"{session_info.get('num-icmp', 0):,}")
            table.add_row("─" * 20, "")
            table.add_row("Connections/sec", f"{session_info.get('cps', 0):,}")
            table.add_row("Packets/sec", f"{session_info.get('pps', 0):,}")
            table.add_row("Kbits/sec", f"{session_info.get('kbps', 0):,}")
            
            output.append(table)
        
        # Global Counters by Category
        if 'global_counters' in data_dict and data_dict['global_counters'] and 'global' in data_dict['global_counters']:
            global_data = data_dict['global_counters']['global']
            if 'counters' in global_data and 'entry' in global_data['counters']:
                entries = global_data['counters']['entry']
                if not isinstance(entries, list):
                    entries = [entries]
                
                # Group by category
                categories = defaultdict(list)
                for entry in entries:
                    category = entry.get('category', 'other')
                    categories[category].append(entry)
                
                # Create table for each significant category (limit to top categories)
                for category in sorted(categories.keys())[:5]:  # Show top 5 categories
                    category_entries = categories[category][:10]  # Show top 10 per category
                    
                    table = Table(
                        title=f"[bold magenta]{category.upper()} Counters (Top {len(category_entries)})[/bold magenta]",
                        box=box.ROUNDED,
                        show_header=True,
                        header_style="bold cyan"
                    )
                    table.add_column("Counter", style="cyan", no_wrap=True)
                    table.add_column("Value", style="white", justify="right")
                    table.add_column("Rate/sec", style="blue", justify="right")
                    table.add_column("Severity", style="yellow")
                    
                    for entry in category_entries:
                        severity = entry.get('severity', 'info')
                        sev_style = {
                            'info': 'green',
                            'warn': 'yellow',
                            'error': 'red',
                            'drop': 'red'
                        }.get(severity, 'white')
                        
                        value = entry.get('value', 0)
                        value_style = "green" if value == 0 or severity == 'info' else "yellow" if value < 1000 else "red"
                        
                        table.add_row(
                            entry.get('name', 'Unknown')[:40],
                            f"[{value_style}]{value:,}[/{value_style}]",
                            f"{entry.get('rate', 0):,}",
                            f"[{sev_style}]{severity}[/{sev_style}]"
                        )
                    
                    output.append(table)
    
    # Render to string
    with console.capture() as capture:
        for item in output:
            console.print(item)
            console.print()
    
    return capture.get()


def format_global_protect_rich(data: Dict[str, Any]) -> str:
    """Format GlobalProtect statistics with Rich tables."""
    output = []
    
    # Unwrap for table display
    gp_data = data.get('global_protect', data)
    
    for firewall_name, result in gp_data.items():
        # Firewall header
        header = Panel(
            f"[bold white]{firewall_name}[/bold white]",
            style="bold blue",
            border_style="blue"
        )
        output.append(header)
        
        if not result.get('success'):
            error_panel = Panel(
                f"[bold red]Error:[/bold red] {result.get('error', 'Unknown error')}",
                border_style="red"
            )
            output.append(error_panel)
            continue
        
        data_dict = result.get('data', {})
        
        # Gateway Summary
        if 'gateway_summary' in data_dict and data_dict['gateway_summary'] and 'entry' in data_dict['gateway_summary']:
            entries = data_dict['gateway_summary']['entry']
            if not isinstance(entries, list):
                entries = [entries]
            
            table = Table(
                title="[bold blue]GlobalProtect Gateway Statistics[/bold blue]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Gateway", style="cyan", no_wrap=True)
            table.add_column("Current Users", style="green", justify="right")
            table.add_column("Previous Users", style="yellow", justify="right")
            table.add_column("Max Tunnels", style="blue", justify="right")
            table.add_column("Successful Connections", style="magenta", justify="right")
            
            for gw in entries:
                table.add_row(
                    gw.get('name', 'N/A'),
                    f"{gw.get('CurrentUsers', 0):,}",
                    f"{gw.get('PreviousUsers', 0):,}",
                    f"{gw.get('gateway_max_concurrent_tunnel', 0):,}",
                    f"{gw.get('gateway_successful_ip_sec_connections', 0):,}"
                )
            
            output.append(table)
        
        # Portal Summary
        if 'portal_summary' in data_dict and data_dict['portal_summary'] and 'entry' in data_dict['portal_summary']:
            entries = data_dict['portal_summary']['entry']
            if not isinstance(entries, list):
                entries = [entries]
            
            table = Table(
                title="[bold blue]GlobalProtect Portal Statistics[/bold blue]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Portal", style="cyan", no_wrap=True)
            table.add_column("Successful Connections", style="green", justify="right")
            
            for portal in entries:
                table.add_row(
                    portal.get('name', 'N/A'),
                    f"{portal.get('successful_connections', 0):,}"
                )
            
            output.append(table)
    
    # Render to string
    with console.capture() as capture:
        for item in output:
            console.print(item)
            console.print()
    
    return capture.get()


def format_vpn_tunnels_rich(data: Dict[str, Any]) -> str:
    """Format VPN tunnel statistics with Rich tables."""
    output = []
    
    # Unwrap for table display
    vpn_data = data.get('vpn', data)
    
    for firewall_name, result in vpn_data.items():
        # Firewall header
        header = Panel(
            f"[bold white]{firewall_name}[/bold white]",
            style="bold green",
            border_style="green"
        )
        output.append(header)
        
        if not result.get('success'):
            error_panel = Panel(
                f"[bold red]Error:[/bold red] {result.get('error', 'Unknown error')}",
                border_style="red"
            )
            output.append(error_panel)
            continue
        
        data_dict = result.get('data', {})
        
        # VPN Flow Summary
        if 'vpn_flows' in data_dict:
            flows = data_dict['vpn_flows']
            
            table = Table(
                title="[bold green]VPN Flow Summary[/bold green]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Flow Type", style="yellow", no_wrap=True)
            table.add_column("Count", style="white", justify="right")
            
            table.add_row("IPsec Flows", f"{flows.get('num_ipsec', 0):,}")
            table.add_row("SSL VPN Flows", f"{flows.get('num_sslvpn', 0):,}")
            table.add_row("Total Flows", f"[bold]{flows.get('total', 0):,}[/bold]")
            
            output.append(table)
        
        # Active IPsec Tunnels (from vpn_flows.IPSec.entry)
        if 'vpn_flows' in data_dict and data_dict['vpn_flows'].get('IPSec'):
            ipsec_data = data_dict['vpn_flows']['IPSec']
            
            # Handle both dict with 'entry' key and list directly
            if isinstance(ipsec_data, dict) and 'entry' in ipsec_data:
                tunnel_entries = ipsec_data['entry']
                # Ensure it's a list
                if not isinstance(tunnel_entries, list):
                    tunnel_entries = [tunnel_entries]
            else:
                tunnel_entries = []
            
            if tunnel_entries:
                table = Table(
                    title="[bold green]Active VPN Tunnels[/bold green]",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                table.add_column("Tunnel Name", style="cyan", no_wrap=True)
                table.add_column("State", style="white", justify="center")
                table.add_column("Local IP", style="blue")
                table.add_column("Peer IP", style="magenta")
                table.add_column("Inner IF", style="yellow")
                table.add_column("Outer IF", style="green")
                
                for tunnel in tunnel_entries:
                    if not isinstance(tunnel, dict):
                        continue
                    
                    state = tunnel.get('state', 'unknown')
                    state_style = "green" if state == 'active' else "red"
                    
                    table.add_row(
                        tunnel.get('name', 'N/A'),
                        f"[{state_style}]{state.upper()}[/{state_style}]",
                        tunnel.get('localip', 'N/A'),
                        tunnel.get('peerip', 'N/A'),
                        tunnel.get('inner-if', 'N/A'),
                        tunnel.get('outer-if', 'N/A')
                    )
                
                output.append(table)
        
        # VPN Gateway Summary (from vpn_gateways.entries.entry)
        if 'vpn_gateways' in data_dict and data_dict['vpn_gateways']:
            gateways_data = data_dict['vpn_gateways']
            
            # Extract gateway entries from nested structure
            gateway_entries = []
            if isinstance(gateways_data, dict):
                if 'entries' in gateways_data and gateways_data['entries']:
                    entries = gateways_data['entries']
                    if isinstance(entries, dict) and 'entry' in entries:
                        gateway_entries = entries['entry']
                        # Ensure it's a list
                        if not isinstance(gateway_entries, list):
                            gateway_entries = [gateway_entries]
            
            if gateway_entries:
                table = Table(
                    title="[bold green]VPN Gateways[/bold green]",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                table.add_column("Gateway", style="cyan", no_wrap=True)
                table.add_column("Peer Address", style="blue")
                table.add_column("Local Address", style="green")
                table.add_column("Encryption", style="yellow")
                table.add_column("Auth", style="magenta")
                
                for gw in gateway_entries:
                    if not isinstance(gw, dict):
                        continue
                    
                    # Prefer v2 (IKEv2) over v1
                    ike_version = gw.get('v2') if gw.get('v2') else gw.get('v1')
                    
                    # Extract peer and local IPs from ID strings
                    peer_id = ike_version.get('peer-id', 'N/A') if ike_version else 'N/A'
                    local_id = ike_version.get('local-id', 'N/A') if ike_version else 'N/A'
                    
                    # Parse peer IP from format "ip(ipaddr:x.x.x.x)"
                    peer_ip = peer_id.split('ipaddr:')[-1].rstrip(')') if 'ipaddr:' in peer_id else peer_id
                    local_ip = local_id.split('ipaddr:')[-1].rstrip(')') if 'ipaddr:' in local_id else local_id
                    
                    encryption = ike_version.get('enc', 'N/A') if ike_version else 'N/A'
                    auth = ike_version.get('auth', 'N/A') if ike_version else 'N/A'
                    
                    table.add_row(
                        gw.get('name', 'N/A'),
                        peer_ip,
                        local_ip,
                        encryption,
                        auth
                    )
                
                output.append(table)
            elif gateways_data.get('ngw', 0) == 0:
                # Show a message when there are no gateways
                info_table = Table(
                    title="[bold green]VPN Gateways[/bold green]",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                info_table.add_column("Gateway", style="cyan")
                info_table.add_column("Peer Address", style="blue")
                info_table.add_column("Local Address", style="green")
                info_table.add_column("Tunnels", style="yellow")
                info_table.add_row("entries", "N/A", "N/A", "0")
                output.append(info_table)
        
        # IPsec Security Associations (from ipsec_sa.entries.entry)
        if 'ipsec_sa' in data_dict and data_dict['ipsec_sa']:
            sa_data = data_dict['ipsec_sa']
            
            # Extract SA entries from nested structure
            sa_entries = []
            if isinstance(sa_data, dict):
                if 'entries' in sa_data and sa_data['entries']:
                    entries = sa_data['entries']
                    if isinstance(entries, dict) and 'entry' in entries:
                        sa_entries = entries['entry']
                        # Ensure it's a list
                        if not isinstance(sa_entries, list):
                            sa_entries = [sa_entries]
            
            if sa_entries:
                table = Table(
                    title="[bold green]IPsec Security Associations[/bold green]",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                table.add_column("Tunnel Name", style="cyan", no_wrap=True)
                table.add_column("Gateway", style="blue")
                table.add_column("Peer IP", style="magenta")
                table.add_column("Encryption", style="yellow")
                table.add_column("Lifetime", style="green", justify="right")
                table.add_column("Remaining", style="white", justify="right")
                
                for sa in sa_entries:
                    if not isinstance(sa, dict):
                        continue
                    
                    # Calculate time remaining in human-readable format
                    remain = sa.get('remain', 0)
                    if remain:
                        remain_mins = remain // 60
                        remain_secs = remain % 60
                        remain_str = f"{remain_mins}m {remain_secs}s"
                        # Color code based on remaining time
                        if remain < 300:  # Less than 5 minutes
                            remain_str = f"[red]{remain_str}[/red]"
                        elif remain < 900:  # Less than 15 minutes
                            remain_str = f"[yellow]{remain_str}[/yellow]"
                        else:
                            remain_str = f"[green]{remain_str}[/green]"
                    else:
                        remain_str = "N/A"
                    
                    life = sa.get('life', 0)
                    life_str = f"{life}s" if life else "N/A"
                    
                    table.add_row(
                        sa.get('name', 'N/A'),
                        sa.get('gateway', 'N/A'),
                        sa.get('remote', 'N/A'),
                        sa.get('enc', 'N/A'),
                        life_str,
                        remain_str
                    )
                
                output.append(table)
    
    # Render to string
    with console.capture() as capture:
        for item in output:
            console.print(item)
            console.print()
    
    return capture.get()


def format_firewall_summary_rich(data: Dict[str, Any]) -> str:
    """Format firewall summary with Rich tables."""
    output = []
    
    # Summary header with enabled/disabled counts
    total = data.get('total_firewalls', 0)
    enabled = data.get('enabled_firewalls', total)  # Default to total for backward compatibility
    disabled = data.get('disabled_firewalls', 0)
    
    header_text = f"[bold white]Configured Firewalls: {total}[/bold white]"
    if disabled > 0:
        header_text += f"  [green]({enabled} enabled[/green], [red]{disabled} disabled)[/red]"
    
    header = Panel(
        header_text,
        style="bold blue",
        border_style="blue"
    )
    output.append(header)
    
    # Firewall table
    table = Table(
        title="[bold blue]Firewall Configuration Summary[/bold blue]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Enabled", style="white", justify="center")
    table.add_column("Host", style="blue")
    table.add_column("Port", style="yellow", justify="right")
    table.add_column("Location", style="green")
    table.add_column("SSL Verify", style="magenta")
    table.add_column("Timeout", style="dim", justify="right")
    
    for name, config in data.get('firewalls', {}).items():
        ssl_verify = config.get('verify_ssl', True)
        ssl_style = "green" if ssl_verify else "yellow"
        
        # Handle enabled status with visual indicator
        is_enabled = config.get('enabled', True)
        if is_enabled:
            enabled_display = "[bold green]✓[/bold green]"
        else:
            enabled_display = "[bold red]✗[/bold red]"
        
        table.add_row(
            name,
            enabled_display,
            config.get('host', 'N/A'),
            str(config.get('port', 'N/A')),
            config.get('location', 'N/A'),
            f"[{ssl_style}]{ssl_verify}[/{ssl_style}]",
            f"{config.get('timeout', 'N/A')}s"
        )
    
    output.append(table)
    
    # Render to string
    with console.capture() as capture:
        for item in output:
            console.print(item)
            console.print()
    
    return capture.get()


def format_validation_rich(data: Dict[str, Any]) -> str:
    """Format validation results with Rich tables."""
    output = []
    
    for firewall_name, result in data.items():
        is_valid = result.get('valid', False)
        
        # Status style
        status_style = "green" if is_valid else "red"
        status_symbol = "✅" if is_valid else "❌"
        
        panel = Panel(
            f"{status_symbol} [bold {status_style}]{firewall_name}: {'VALID' if is_valid else 'INVALID'}[/bold {status_style}]",
            border_style=status_style
        )
        output.append(panel)
        
        if not is_valid and 'errors' in result:
            table = Table(
                title="[bold red]Validation Errors[/bold red]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Error", style="red")
            
            for error in result['errors']:
                table.add_row(error)
            
            output.append(table)
    
    # Render to string
    with console.capture() as capture:
        for item in output:
            console.print(item)
            console.print()
    
    return capture.get()

