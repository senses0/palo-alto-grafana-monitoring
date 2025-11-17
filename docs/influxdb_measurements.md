# InfluxDB Measurements Reference

**Generated from Schema Version:** 1.6.0  
**Total Measurements:** 42  
**Categories:** System, Environmental, Interfaces, Routing, Counters, GlobalProtect, VPN

This document provides a comprehensive reference for all InfluxDB measurements created by the `influxdb_converter.py` tool. Each measurement is documented with its tags (dimensions for filtering) and fields (metrics to monitor).

## Table of Contents

- [System Measurements (13)](#system-measurements)
  - [palo_alto_system_identity](#palo_alto_system_identity)
  - [palo_alto_system_uptime](#palo_alto_system_uptime)
  - [palo_alto_content_versions](#palo_alto_content_versions)
  - [palo_alto_mac_count](#palo_alto_mac_count)
  - [palo_alto_cpu_usage](#palo_alto_cpu_usage)
  - [palo_alto_memory_usage](#palo_alto_memory_usage)
  - [palo_alto_swap_usage](#palo_alto_swap_usage)
  - [palo_alto_load_average](#palo_alto_load_average)
  - [palo_alto_task_stats](#palo_alto_task_stats)
  - [palo_alto_disk_usage](#palo_alto_disk_usage)
  - [palo_alto_ha_status](#palo_alto_ha_status)
  - [palo_alto_cpu_dataplane_tasks](#palo_alto_cpu_dataplane_tasks)
  - [palo_alto_cpu_dataplane_cores](#palo_alto_cpu_dataplane_cores)
- [Environmental Measurements (4)](#environmental-measurements)
  - [palo_alto_env_thermal](#palo_alto_env_thermal)
  - [palo_alto_env_fan](#palo_alto_env_fan)
  - [palo_alto_env_power](#palo_alto_env_power)
  - [palo_alto_env_power_supply](#palo_alto_env_power_supply)
- [Interface Measurements (4)](#interface-measurements)
  - [palo_alto_interface_info](#palo_alto_interface_info)
  - [palo_alto_interface_logical](#palo_alto_interface_logical)
  - [palo_alto_interface_counters_hw](#palo_alto_interface_counters_hw)
  - [palo_alto_interface_counters_logical](#palo_alto_interface_counters_logical)
- [Routing Measurements (4)](#routing-measurements)
  - [palo_alto_bgp_summary](#palo_alto_bgp_summary)
  - [palo_alto_bgp_peer](#palo_alto_bgp_peer)
  - [palo_alto_bgp_path_monitor](#palo_alto_bgp_path_monitor)
  - [palo_alto_routing_table_counts](#palo_alto_routing_table_counts)
- [Counter Measurements (10)](#counter-measurements)
  - [palo_alto_counters_flow](#palo_alto_counters_flow)
  - [palo_alto_counters_session](#palo_alto_counters_session)
  - [palo_alto_counters_packet](#palo_alto_counters_packet)
  - [palo_alto_counters_appid](#palo_alto_counters_appid)
  - [palo_alto_counters_tcp](#palo_alto_counters_tcp)
  - [palo_alto_counters_ctd](#palo_alto_counters_ctd)
  - [palo_alto_counters_log](#palo_alto_counters_log)
  - [palo_alto_counters_proxy](#palo_alto_counters_proxy)
  - [palo_alto_counters_ssl](#palo_alto_counters_ssl)
  - [palo_alto_counters_http2](#palo_alto_counters_http2)
- [GlobalProtect Measurements (2)](#globalprotect-measurements)
  - [palo_alto_gp_gateway](#palo_alto_gp_gateway)
  - [palo_alto_gp_portal](#palo_alto_gp_portal)
- [VPN Measurements (5)](#vpn-measurements)
  - [palo_alto_vpn_flows](#palo_alto_vpn_flows)
  - [palo_alto_ipsec_flow](#palo_alto_ipsec_flow)
  - [palo_alto_vpn_tunnel](#palo_alto_vpn_tunnel)
  - [palo_alto_vpn_gateway](#palo_alto_vpn_gateway)
  - [palo_alto_ipsec_sa](#palo_alto_ipsec_sa)

---

## System Measurements

System measurements provide insight into firewall health, performance, and resource utilization.

### palo_alto_system_identity

**Category:** System  
**Description:** System identification and static configuration information  
**Update Frequency:** Rarely (on system change)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname (primary identifier) |
| `model` | string | PA-VM | Device model |
| `family` | string | vm | Device family |
| `serial` | string | 732CC0C852AD594 | Serial number |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `sw_version` | string | - | 11.1.6-h3 | Software version |
| `vm_cores` | integer | cores | 4 | Number of VM cores |
| `vm_mem_mb` | float | MiB | 14014.75 | VM memory |
| `operational_mode` | string | - | normal | Operational mode |
| `advanced_routing` | string | - | on | Advanced routing status |
| `multi_vsys` | string | - | off | Multi-vsys capability status |
| `ip_address` | string | - | 192.168.15.5 | Management IP address |
| `mac_address` | string | - | 00:22:48:f3:cf:3e | Management MAC address |
| `ipv6_address` | string | - | unknown | Management IPv6 address |
| `is_dhcp` | boolean | - | true | Using DHCP for IPv4 |
| `is_dhcp6` | boolean | - | false | Using DHCP for IPv6 |

#### Notes
- Static system information that rarely changes
- Use for inventory management and compatibility tracking
- Network configuration fields (IP, MAC) help with asset tracking

---

### palo_alto_system_uptime

**Category:** System  
**Description:** System uptime metrics  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `uptime_seconds` | integer | seconds | 2616376 | Uptime in seconds |
| `uptime_days` | float | days | 30.28 | Uptime in days |

#### Notes
- Monitor for unexpected reboots
- Useful for maintenance scheduling and SLA tracking

---

### palo_alto_content_versions

**Category:** System  
**Description:** Content and security package versions  
**Update Frequency:** Frequently (with content updates - typically daily/weekly)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `app_version` | string | - | 8790-8462 | Application and threat content version |
| `av_version` | integer | - | 0 | Anti-virus content version (0 = not installed) |
| `threat_version` | integer | - | 0 | Threat prevention content version (0 = not installed) |
| `wf_private_version` | integer | - | 0 | WildFire private cloud version |
| `wildfire_version` | integer | - | 0 | WildFire content version |
| `wildfire_rt` | string | - | Disabled | WildFire real-time status |
| `url_filtering_version` | integer | - | 20251014 | URL filtering database version |
| `url_db` | string | - | paloaltonetworks | URL database source |
| `logdb_version` | string | - | 11.1.2 | Log database version |
| `device_dictionary_version` | string | - | 196-656 | Device dictionary version |
| `global_protect_client_package_version` | string | - | 6.3.2 | GlobalProtect client package version |

#### Notes
- Critical for security compliance monitoring
- Alert on outdated content versions
- Version 0 typically indicates the feature is not licensed or not installed
- Use for tracking content update compliance across firewall fleet
- Recommended to monitor daily and alert on versions older than 7 days

---

### palo_alto_mac_count

**Category:** System  
**Description:** MAC address allocation count  
**Update Frequency:** Rarely (on system change)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `model` | string | PA-VM | Device model |
| `family` | string | vm | Device family |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `mac_count` | integer | addresses | 256 | Number of MAC addresses allocated to the device |

#### Notes
- MAC address allocation for the firewall
- Hardware firewalls report as `mac_count`, VM firewalls as `vm-mac-count`
- Useful for capacity planning and licensing tracking
- Typically 254-256 addresses for PA-3000 series hardware
- VM firewalls may have different allocations based on license tier

---

### palo_alto_cpu_usage

**Category:** System  
**Description:** CPU utilization breakdown by type  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `cpu_user` | float | % | 9.2 | User CPU time |
| `cpu_system` | float | % | 4.6 | System CPU time |
| `cpu_nice` | float | % | 0.0 | Nice CPU time |
| `cpu_idle` | float | % | 81.5 | Idle CPU time |
| `cpu_iowait` | float | % | 0.0 | IO wait time |
| `cpu_hardware_interrupt` | float | % | 3.1 | Hardware interrupt time |
| `cpu_software_interrupt` | float | % | 1.5 | Software interrupt time |
| `cpu_steal` | float | % | 0.0 | Steal time (virtualization) |
| `cpu_total_used` | float | % | 18.5 | Total CPU used (100 - idle) |

#### Notes
- All CPU values are percentages (0-100)
- `cpu_total_used` is a computed field for easier graphing
- Alert on sustained high CPU usage (>80%)

---

### palo_alto_memory_usage

**Category:** System  
**Description:** Memory utilization metrics  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `memory_total_mib` | float | MiB | 14014.8 | Total memory |
| `memory_free_mib` | float | MiB | 783.3 | Free memory |
| `memory_used_mib` | float | MiB | 4289.2 | Used memory |
| `memory_buff_cache_mib` | float | MiB | 8942.3 | Buffer/cache memory |
| `memory_available_mib` | float | MiB | 7074.5 | Available memory |
| `memory_usage_percent` | float | % | 30.6 | Memory usage percentage |

#### Notes
- Memory values in MiB, percentage is 0-100
- Alert on memory usage >85%
- `memory_available_mib` is the best indicator of available memory

---

### palo_alto_swap_usage

**Category:** System  
**Description:** Swap space utilization  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `swap_total_mib` | float | MiB | 4000.0 | Total swap |
| `swap_free_mib` | float | MiB | 3999.2 | Free swap |
| `swap_used_mib` | float | MiB | 0.8 | Used swap |
| `swap_usage_percent` | float | % | 0.02 | Swap usage percentage |

#### Notes
- Active swap usage may indicate memory pressure
- Alert if swap usage exceeds 25%

---

### palo_alto_load_average

**Category:** System  
**Description:** System load averages  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `load_1min` | float | - | 0.83 | 1 minute load average |
| `load_5min` | float | - | 0.93 | 5 minute load average |
| `load_15min` | float | - | 0.99 | 15 minute load average |

#### Notes
- Load average represents the number of processes waiting for CPU
- Compare to number of CPU cores for context
- Alert if load consistently exceeds CPU core count

---

### palo_alto_task_stats

**Category:** System  
**Description:** Process and task statistics  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `tasks_total` | integer | - | 249 | Total tasks |
| `tasks_running` | integer | - | 2 | Running tasks |
| `tasks_sleeping` | integer | - | 246 | Sleeping tasks |
| `tasks_stopped` | integer | - | 0 | Stopped tasks |
| `tasks_zombie` | integer | - | 1 | Zombie tasks |

#### Notes
- Monitor for unusual spikes in task counts
- Alert on persistent zombie processes

---

### palo_alto_disk_usage

**Category:** System  
**Description:** Disk usage per mount point  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per mount point)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `mount_point` | string | / | Mount point path |
| `device` | string | /dev/root | Device name |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `use_percent` | integer | % | 46 | Disk usage percentage |
| `size_gb` | float | GB | 12.0 | Total size in GB |
| `used_gb` | float | GB | 5.2 | Used space in GB |
| `available_gb` | float | GB | 6.1 | Available space in GB |

#### Notes
- Multiple data points per collection (one per mount point)
- Alert on usage >85% for critical mounts
- Size values are converted from strings (e.g., "12G") to numeric GB

---

### palo_alto_ha_status

**Category:** System  
**Description:** High Availability configuration and status  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | MO-P-FW02 | Device hostname |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `enabled` | string | - | yes | HA enabled status (yes/no) |
| **Core HA State** | | | | |
| `ha_mode` | string | - | Active-Passive | HA mode (Active-Passive, Active-Active) |
| `local_state` | string | - | passive | Local firewall state (active, passive, suspended, initial) |
| `local_state_duration` | integer | seconds | 13216095 | Time in current state |
| `peer_state` | string | - | active | Peer firewall state |
| `peer_state_duration` | integer | seconds | 13216110 | Peer time in current state |
| **Synchronization Status** | | | | |
| `state_sync` | string | - | Complete | Config sync status (Complete, Incomplete, In Progress) |
| `state_sync_type` | string | - | ethernet | Sync connection type (ethernet, ip) |
| `running_sync` | string | - | synchronized | Running config sync status |
| `running_sync_enabled` | string | - | yes | Running config sync enabled (yes/no) |
| **Connection Health** | | | | |
| `peer_conn_status` | string | - | up | Overall peer connection status (up, down) |
| `peer_conn_ha1_status` | string | - | up | HA1 control link status (up, down) |
| `peer_conn_ha2_status` | string | - | up | HA2 data link status (up, down) |
| **Failover & Stability** | | | | |
| `local_priority` | integer | - | 100 | Local priority value (0-255, higher = preferred active) |
| `peer_priority` | integer | - | 100 | Peer priority value |
| `preempt_flap_cnt` | integer | - | 0 | Preemptive failover count (indicates instability) |
| `nonfunc_flap_cnt` | integer | - | 0 | Non-functional device failover count |
| `max_flaps` | integer | - | 3 | Maximum flaps threshold configured |
| **Version Compatibility** | | | | |
| `dlp_compat` | string | - | Match | DLP version compatibility (Match, Mismatch) |
| `nd_compat` | string | - | Match | Network Discovery version compatibility |
| `oc_compat` | string | - | Match | OpenConfig version compatibility |
| `build_compat` | string | - | Match | Software build compatibility |
| `url_compat` | string | - | Mismatch | URL filtering database compatibility |
| `app_compat` | string | - | Match | App/threat content compatibility |
| `iot_compat` | string | - | Match | IoT content compatibility |
| `av_compat` | string | - | Match | Antivirus content compatibility |
| `threat_compat` | string | - | Match | Threat content compatibility |
| `vpnclient_compat` | string | - | Match | VPN client compatibility |
| `gpclient_compat` | string | - | Match | GlobalProtect client compatibility |

#### Notes
- Limited data when HA is disabled (only `enabled` field present)
- Comprehensive metrics available when HA is enabled (29 total fields)
- **Critical alerting scenarios:**
  - Alert when `local_state` or `peer_state` changes (failover event)
  - Alert when `peer_conn_status` != "up" (peer connectivity lost)
  - Alert when `peer_conn_ha1_status` or `peer_conn_ha2_status` != "up" (HA link failure)
  - Alert when `state_sync` != "Complete" (config out of sync)
  - Alert when `running_sync` != "synchronized" (running config mismatch)
  - Alert when any `*_compat` field = "Mismatch" (version incompatibility)
  - Alert when `preempt_flap_cnt` or `nonfunc_flap_cnt` increases (failover instability)
- Priority conflicts: Alert when both devices have same priority (ambiguous active selection)
- Compatibility mismatches can prevent proper failover - critical to monitor
- State duration fields help identify recent failovers
- Flap counters indicate HA instability - investigate if non-zero

---

### palo_alto_cpu_dataplane_tasks

**Category:** System  
**Description:** Dataplane task CPU utilization and resource utilization  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1 per dataplane processor

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `dp_id` | string | dp0 | Dataplane processor ID |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| **Task CPU Utilization (17 fields)** | | | | |
| `task_flow_lookup` | float | % | 0.0 | Flow lookup task CPU |
| `task_flow_fastpath` | float | % | 0.0 | Flow fastpath task CPU |
| `task_flow_slowpath` | float | % | 0.0 | Flow slowpath task CPU |
| `task_flow_forwarding` | float | % | 0.0 | Flow forwarding task CPU |
| `task_flow_mgmt` | float | % | 0.0 | Flow management task CPU |
| `task_flow_ctrl` | float | % | 0.0 | Flow control task CPU |
| `task_nac_result` | float | % | 0.0 | NAC result task CPU |
| `task_flow_np` | float | % | 0.0 | Flow network processor task CPU |
| `task_dfa_result` | float | % | 0.0 | DFA result task CPU |
| `task_module_internal` | float | % | 0.0 | Module internal task CPU |
| `task_aho_result` | float | % | 0.0 | Aho-Corasick result task CPU |
| `task_zip_result` | float | % | 0.0 | Compression result task CPU |
| `task_pktlog_forwarding` | float | % | 0.0 | Packet log forwarding task CPU |
| `task_send_out` | float | % | 0.0 | Send out task CPU |
| `task_flow_host` | float | % | 0.0 | Flow host task CPU |
| `task_send_host` | float | % | 0.0 | Send host task CPU |
| `task_fpga_result` | float | % | 0.0 | FPGA result task CPU |
| **Resource Utilization (4 fields)** | | | | |
| `resource_session_avg` | float | % | 2.5 | Session resource utilization (60s avg) |
| `resource_packet_buffer_avg` | float | % | 0.0 | Packet buffer utilization (60s avg) |
| `resource_packet_descriptor_avg` | float | % | 0.0 | Packet descriptor utilization (60s avg) |
| `resource_sw_tags_descriptor_avg` | float | % | 3.2 | SW tags descriptor utilization (60s avg) |
| **Core Information (1 field)** | | | | |
| `cpu_cores` | integer | cores | 4 | Number of dataplane CPU cores |

#### Notes
- Task CPU percentages are instantaneous values (current second)
- Resource utilization values are averaged over 60 seconds
- Provides detailed visibility into dataplane packet processing tasks
- Monitor for task-specific bottlenecks or resource exhaustion
- Alert on high task CPU (>80%) or resource exhaustion (>85%)
- Combined with per-core metrics provides comprehensive dataplane performance picture

---

### palo_alto_cpu_dataplane_cores

**Category:** System  
**Description:** Per-core dataplane CPU utilization  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per dataplane core)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `dp_id` | string | dp0 | Dataplane processor ID |
| `core_id` | string | 0 | Core ID |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `cpu_utilization_avg` | float | % | 0.25 | Average CPU utilization over 60 seconds |

#### Notes
- One data point per dataplane core (typically 2-16 cores depending on model)
- CPU utilization is averaged over 60 seconds for stability
- Useful for detecting core imbalance or hot cores
- Alert on individual core >90% (near saturation)
- Alert on core imbalance >50% between hottest and coolest cores
- VM firewalls typically have fewer cores (2-8) than hardware appliances (8-32)
- Use aggregation queries to find hottest core or calculate overall average


---

## Environmental Measurements

Environmental measurements monitor hardware health sensors on physical Palo Alto firewalls. These measurements are **only available on hardware appliances** and will not be present on VM firewalls.

### palo_alto_env_thermal

**Category:** Environmental  
**Description:** Thermal sensor temperature readings  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** 3-10 (varies by hardware model)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | MO-P-FW02 | Device hostname |
| `slot` | integer | 1 | Hardware slot number |
| `description` | string | CPU Die temperature sensor | Sensor description/location |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `temperature_c` | float | °C | 46.6 | Current temperature |
| `min_temp_c` | float | °C | 0.0 | Minimum threshold |
| `max_temp_c` | float | °C | 95.0 | Maximum threshold |
| `alarm` | integer | - | 0 | Alarm status (0=normal, 1=alarm) |

#### Notes
- Hardware firewalls only - not available on VM firewalls
- Monitor for temperature approaching max threshold
- Alert on alarm=1 or temperature >90% of max threshold
- Typical sensors: CPU die, chipsets, ambient
- Number of sensors varies by firewall model

---

### palo_alto_env_fan

**Category:** Environmental  
**Description:** Fan speed measurements  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** 2-8 (varies by hardware model)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | MO-P-FW02 | Device hostname |
| `slot` | integer | 1 | Hardware slot number |
| `description` | string | Fan #1 RPM | Fan description/location |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `rpm` | integer | RPM | 5217 | Current fan speed |
| `min_rpm` | integer | RPM | 2500 | Minimum threshold |
| `alarm` | integer | - | 0 | Alarm status (0=normal, 1=alarm) |

#### Notes
- Hardware firewalls only - not available on VM firewalls
- Monitor for RPM falling below minimum threshold
- Alert on alarm=1 or RPM below minimum
- Fan failures can lead to overheating
- Number of fans varies by firewall model

---

### palo_alto_env_power

**Category:** Environmental  
**Description:** Voltage sensor readings  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** 20-40 (varies by hardware model)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | MO-P-FW02 | Device hostname |
| `slot` | integer | 1 | Hardware slot number |
| `description` | string | VDD_PVNN_PCH (LTC) | Voltage sensor description |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `volts` | float | V | 0.8757 | Current voltage |
| `min_volts` | float | V | 0.65 | Minimum threshold |
| `max_volts` | float | V | 1.35 | Maximum threshold |
| `alarm` | integer | - | 0 | Alarm status (0=normal, 1=alarm) |

#### Notes
- Hardware firewalls only - not available on VM firewalls
- Monitor for voltage outside min/max range
- Alert on alarm=1 or voltage out of range
- Includes CPU, memory, PHY, and system voltages
- Critical for detecting power supply issues
- Number of sensors varies significantly by hardware model

---

### palo_alto_env_power_supply

**Category:** Environmental  
**Description:** Power supply status and presence  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1-2 (varies by hardware model)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | MO-P-FW02 | Device hostname |
| `slot` | integer | 1 | Hardware slot number |
| `description` | string | Power Supply #1 | Power supply description |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `inserted` | integer | - | 1 | Power supply inserted/present (0=no, 1=yes) |
| `min_required` | integer | - | 1 | Minimum required status (0=no, 1=yes) |
| `alarm` | integer | - | 0 | Alarm status (0=normal, 1=alarm) |

#### Notes
- Hardware firewalls only - not available on VM firewalls
- Monitor for power supply removal or failure
- Alert on alarm=1 or inserted=0
- Critical for redundant power monitoring
- Most firewalls have 1-2 power supplies

---

## Interface Measurements

Interface measurements track physical and logical interface configuration, status, and traffic statistics.

### palo_alto_interface_info

**Category:** Interfaces  
**Description:** Interface hardware information and status  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per physical interface)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `interface` | string | ethernet1/1 | Interface name |
| `type` | string | 0 | Interface type |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `state` | string | - | up | Interface state (up/down) |
| `speed` | integer | Mbps | 40000 | Interface speed |
| `duplex` | string | - | full | Duplex mode |
| `mac` | string | - | 00:22:48:d3:8c:f0 | MAC address |
| `mode` | string | - | (autoneg) | Interface mode |
| `fec` | string | - | auto | FEC status |

#### Notes
- One data point per physical interface
- Monitor for interface state changes
- Track speed/duplex mismatches

---

### palo_alto_interface_logical

**Category:** Interfaces  
**Description:** Interface logical configuration (zones, IPs, routing)  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per logical interface)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `interface` | string | ethernet1/1 | Interface name |
| `zone` | string | Trust | Security zone |
| `vsys` | string | 1 | Virtual system |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `ip` | string | - | 172.23.1.5/24 | IP address/mask |
| `fwd` | string | - | lr:DEV-LAN-LR | Forwarding (routing) info |
| `tag` | integer | - | 0 | VLAN tag |

#### Notes
- Logical interface configuration
- Useful for inventory and configuration tracking

---

### palo_alto_interface_counters_hw

**Category:** Interfaces  
**Description:** Interface hardware/port traffic counters (physical layer)  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per physical interface)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `interface` | string | ethernet1/1 | Interface name |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `rx_bytes` | integer | bytes | 43137212 | Received bytes (port level) |
| `rx_unicast` | integer | packets | 614896 | Received unicast packets |
| `rx_multicast` | integer | packets | 0 | Received multicast packets |
| `rx_broadcast` | integer | packets | 0 | Received broadcast packets |
| `rx_error` | integer | packets | 0 | Receive errors |
| `rx_discards` | integer | packets | 0 | Receive discards |
| `tx_bytes` | integer | bytes | 79935304 | Transmitted bytes (port level) |
| `tx_unicast` | integer | packets | 1119808 | Transmitted unicast packets |
| `tx_multicast` | integer | packets | 0 | Transmitted multicast packets |
| `tx_broadcast` | integer | packets | 0 | Transmitted broadcast packets |
| `tx_error` | integer | packets | 0 | Transmit errors |
| `tx_discards` | integer | packets | 0 | Transmit discards |
| `link_down_count` | integer | - | 0 | Link down count |
| `ibytes` | integer | bytes | 80245248 | Input bytes |
| `obytes` | integer | bytes | 58738520 | Output bytes |
| `ipackets` | integer | packets | 1128430 | Input packets |
| `opackets` | integer | packets | 822451 | Output packets |
| `ierrors` | integer | packets | 0 | Input errors |
| `idrops` | integer | packets | 0 | Input drops |

#### Notes
- Physical port statistics for network performance monitoring
- Counter values are cumulative (use derivative function in Grafana)
- One data point per physical interface
- Monitor errors and discards for network hardware issues
- Calculate bandwidth utilization from byte counters

---

### palo_alto_interface_counters_logical

**Category:** Interfaces  
**Description:** Interface logical/firewall-level counters (security processing)  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per logical interface, including subinterfaces)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `interface` | string | ethernet1/1 | Interface name (or subinterface like tunnel.10) |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `ibytes` | integer | bytes | 80245248 | Input bytes (firewall level) |
| `obytes` | integer | bytes | 58738520 | Output bytes (firewall level) |
| `ipackets` | integer | packets | 1128430 | Input packets |
| `opackets` | integer | packets | 822451 | Output packets |
| `ierrors` | integer | packets | 0 | Input errors |
| `idrops` | integer | packets | 1 | Input drops |
| `flowstate` | integer | packets | 0 | Flow state drops |
| `ifwderrors` | integer | packets | 0 | Forwarding errors |
| `noroute` | integer | packets | 1 | No route drops |
| `noarp` | integer | packets | 1 | No ARP entry drops |
| `noneigh` | integer | packets | 0 | No neighbor drops |
| `neighpend` | integer | packets | 0 | Neighbor pending drops |
| `nomac` | integer | packets | 0 | No MAC drops |
| `zonechange` | integer | packets | 0 | Zone change drops |
| `land` | integer | packets | 0 | LAND attack drops |
| `pod` | integer | packets | 0 | Ping of death drops |
| `teardrop` | integer | packets | 0 | Teardrop attack drops |
| `ipspoof` | integer | packets | 0 | IP spoofing drops |
| `macspoof` | integer | packets | 0 | MAC spoofing drops |
| `icmp_frag` | integer | packets | 0 | ICMP fragment drops |
| `l2_encap` | integer | packets | 0 | L2 encapsulation |
| `l2_decap` | integer | packets | 0 | L2 decapsulation |
| `tcp_conn` | integer | connections | 0 | TCP connections |
| `udp_conn` | integer | connections | 0 | UDP connections |
| `sctp_conn` | integer | connections | 0 | SCTP connections |
| `other_conn` | integer | connections | 0 | Other connections |

#### Notes
- Firewall/security processing statistics
- Includes logical interfaces and subinterfaces (e.g., tunnel.10)
- Counter values are cumulative (use derivative function in Grafana)
- Critical for troubleshooting security policy drops and routing issues
- Security drop counters (land, pod, teardrop, ipspoof, macspoof) help identify attack attempts
- Routing drops (noroute, noarp) help troubleshoot connectivity issues

---

## Routing Measurements

Routing measurements track BGP peer status, path monitoring, and route table statistics.

### palo_alto_bgp_summary

**Category:** Routing  
**Description:** BGP routing summary statistics per VRF  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** Multiple (one per VRF with BGP enabled)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `router_id` | string | 172.23.255.1 | BGP router ID |
| `local_as` | string | 64315 | Local AS number |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `total_peers` | integer | - | 8 | Total number of BGP peers configured |
| `peers_established` | integer | - | 7 | Number of peers in Established state |
| `peers_down` | integer | - | 1 | Number of peers down/not established |
| `total_prefixes` | integer | - | 2450 | Total prefixes received from all peers |

#### Notes
- One data point per VRF with BGP configured
- Provides high-level BGP health overview
- Alert when `peers_down` > 0 for immediate notification of peer issues
- Monitor `total_prefixes` for unexpected route table changes
- Use in conjunction with `palo_alto_bgp_peer` for detailed per-peer metrics

---

### palo_alto_bgp_peer

**Category:** Routing  
**Description:** BGP peer status and statistics  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per BGP peer)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `peer_name` | string | Azure-DevOps-RS01-1 | BGP peer name |
| `peer_ip` | string | 192.168.16.4 | Peer IP address |
| `peer_group` | string | Azure | Peer group name |
| `state` | string | Established | BGP session state |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `remote_as` | integer | - | 65515 | Remote AS number |
| `local_as` | integer | - | 64315 | Local AS number |
| `status_time` | float | seconds | 41264.0 | Time in current state |
| `state_up` | integer | boolean | 1 | Peer is up (1=up, 0=down) |
| `messages_sent` | integer | - | 71426 | Total messages sent |
| `messages_received` | integer | - | 81616 | Total messages received |
| `updates_sent` | integer | - | 10 | Update messages sent |
| `updates_received` | integer | - | 2 | Update messages received |
| `keepalives_sent` | integer | - | 71414 | Keepalives sent |
| `keepalives_received` | integer | - | 81608 | Keepalives received |
| `notifications_sent` | integer | - | 0 | Notifications sent |
| `notifications_received` | integer | - | 4 | Notifications received |

#### Notes
- One data point per BGP peer
- Critical for BGP monitoring and alerting
- `state_up` field makes it easy to alert on peer down
- Alert immediately on peer state != Established

---

### palo_alto_bgp_path_monitor

**Category:** Routing  
**Description:** BGP path monitoring status per destination  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per monitored path)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `destination` | string | 0.0.0.0/0 | Monitored destination prefix |
| `nexthop` | string | 172.23.255.1 | Next hop |
| `interface` | string | ethernet1/2 | Egress interface |
| `pathmonitor_status` | string | Up | Path monitor status (Up/Down) |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `metric` | integer | - | 10 | Route metric |
| `pathmonitor_condition` | string | - | Enabled(All) | Monitor condition (All/Any) |
| `path_up` | integer | boolean | 1 | Path is up (1=up, 0=down) |
| `monitor_0_destination` | string | - | 1.1.1.1 | Monitor destination 0 |
| `monitor_0_status` | string | - | Success | Monitor 0 status |
| `monitor_0_interval_count` | string | - | 3/5 | Monitor 0 success/total |
| `monitor_1_destination` | string | - | 8.8.8.8 | Monitor destination 1 |
| `monitor_1_status` | string | - | Success | Monitor 1 status |
| `monitor_1_interval_count` | string | - | 3/5 | Monitor 1 success/total |

#### Notes
- One data point per monitored path
- Critical for monitoring route failover capability
- `path_up` field makes it easy to alert on path down
- Multiple health check monitors per path (up to 10)

---

### palo_alto_routing_table_counts

**Category:** Routing  
**Description:** Route counts per protocol and VRF from routing table  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low to Medium  
**Data Points per Collection:** Multiple (one per VRF)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `vrf` | string | default | Virtual Router / VRF name |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `routes_bgp` | integer | routes | 2 | Number of BGP routes |
| `routes_static` | integer | routes | 3 | Number of static routes |
| `routes_connected` | integer | routes | 5 | Number of connected routes |
| `routes_local` | integer | routes | 4 | Number of local routes |
| `routes_total` | integer | routes | 10 | Total routes in VRF |

#### Notes
- One data point per VRF
- Primary source for route counts
- Monitor for unexpected route table growth
- Field names vary by protocols present (bgp, static, connected, local, ospf, etc.)
- **Protocol names are normalized**: lowercase with spaces replaced by underscores (e.g., "Local" → "local", "OSPF Intra" → "ospf_intra")

#### Fallback Measurements

When the `routing_table` collection is disabled in configuration, the converter creates alternative measurements from individual protocol collections:

- **`palo_alto_static_routes_count`** - Static route count aggregated across all VRFs
  - Tags: `hostname`
  - Fields: `static_routes` (integer)
  
- **`palo_alto_bgp_routes_count`** - BGP route count aggregated across all VRFs
  - Tags: `hostname`
  - Fields: `bgp_routes` (integer)

**Note**: These fallback measurements are only created when `routing_table` collection is disabled. They provide less granular data (no per-VRF breakdown) compared to `palo_alto_routing_table_counts`.

---

## Counter Measurements

Counter measurements track global statistics for flows, sessions, packets, applications, and protocols.

### palo_alto_counters_flow

**Category:** Counters  
**Description:** Global flow counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields 
> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category flow`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `flow_rcv_dot1q` | integer | - | 351325 | Tagged 802.1Q flow packets |
| `flow_rcv_dot1q_rate` | integer | /s | 0 | Tagged 802.1Q flow packets rate |
| `flow_ip_spoof` | integer | - | 30 | Spoofed IP address |
| `flow_ip_spoof_rate` | integer | /s | 0 | Spoofed IP address rate |
| `flow_mcast_fwd` | integer | - | 181 | Multicast packets forwarded |
| `flow_mcast_fwd_rate` | integer | /s | 0 | Multicast packets forwarded rate |

#### Notes
- Counter values are cumulative
- Rate values show current rate per second
- Use derivative function in Grafana for rate visualization

---

### palo_alto_counters_session

**Category:** Counters  
**Description:** Global session counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category session`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `session_allocated` | integer | - | 351223 | Number of sessions allocated |
| `session_allocated_rate` | integer | /s | 0 | Number of sessions allocated rate |
| `session_installed` | integer | - | 348197 | Number of sessions installed |
| `session_installed_rate` | integer | /s | 0 | Number of sessions installed rate |
| `session_freed` | integer | - | 345990 | Number of sessions freed |
| `session_freed_rate` | integer | /s | 0 | Number of sessions freed rate |

#### Notes
- Track session lifecycle (allocated, installed, freed)
- Monitor for session exhaustion

---

### palo_alto_counters_packet

**Category:** Counters  
**Description:** Global packet counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category packet`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `pkt_sent` | integer | - | 1126230 | Packets sent |
| `pkt_sent_rate` | integer | /s | 0 | Packets sent rate |
| `pkt_recv` | integer | - | 621316 | Packets received |
| `pkt_recv_rate` | integer | /s | 0 | Packets received rate |
| `pkt_drop` | integer | - | 15 | Packets dropped |
| `pkt_drop_rate` | integer | /s | 0 | Packets dropped rate |

#### Notes
- Comprehensive packet-level statistics
- Monitor drop rates for network issues

---

### palo_alto_counters_appid

**Category:** Counters  
**Description:** Global appid counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category appid`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `appid_proc` | integer | - | 177518 | Packets processed by App-ID |
| `appid_proc_rate` | integer | /s | 0 | Packets processed by App-ID rate |
| `appid_hs_match` | integer | - | 174558 | App-ID matches using lscan |
| `appid_hs_match_rate` | integer | /s | 0 | App-ID matches using lscan rate |

#### Notes
- Application identification statistics
- Track App-ID effectiveness

---

### palo_alto_counters_tcp

**Category:** Counters  
**Description:** Global TCP counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields 

> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category tcp`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `tcp_drop_packet` | integer | - | 3 | TCP packets dropped |
| `tcp_drop_packet_rate` | integer | /s | 0 | TCP packets dropped rate |
| `tcp_out_of_sync` | integer | - | 3 | TCP out of sync |
| `tcp_out_of_sync_rate` | integer | /s | 0 | TCP out of sync rate |

#### Notes
- TCP protocol statistics
- Monitor for TCP-related issues

---

### palo_alto_counters_ctd

**Category:** Counters  
**Description:** Global CTD (Content Decoder) counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields 

> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category ctd`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `ctd_sml_exit` | integer | - | 6 | Sessions with SML exit |
| `ctd_sml_exit_rate` | integer | /s | 0 | Sessions with SML exit rate |

#### Notes
- Content decoder statistics
- Advanced inspection metrics

---

### palo_alto_counters_log

**Category:** Counters  
**Description:** Global log counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields 

> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category log`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `log_traffic_cnt` | integer | - | 351209 | Number of traffic logs |
| `log_traffic_cnt_rate` | integer | /s | 0 | Number of traffic logs rate |
| `log_decrypt_cnt` | integer | - | 1052 | Number of decrypt logs |
| `log_decrypt_cnt_rate` | integer | /s | 0 | Number of decrypt logs rate |

#### Notes
- Logging subsystem statistics
- Monitor for log suppression

---

### palo_alto_counters_proxy

**Category:** Counters  
**Description:** Global proxy counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields 

> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category proxy`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `proxy_process` | integer | - | 184976 | Flows through proxy |
| `proxy_process_rate` | integer | /s | 0 | Flows through proxy rate |
| `proxy_tls13_offload` | integer | - | 172043 | TLS 1.3 offload proxy |
| `proxy_tls13_offload_rate` | integer | /s | 0 | TLS 1.3 offload proxy rate |

#### Notes
- SSL/TLS proxy statistics
- Monitor proxy performance

---

### palo_alto_counters_ssl

**Category:** Counters  
**Description:** Global SSL counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields 

> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category ssl`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `ssl_tls13_connection` | integer | - | 171357 | TLS 1.3 connections |
| `ssl_tls13_connection_rate` | integer | /s | 0 | TLS 1.3 connections rate |
| `ssl_unsupported_cipher` | integer | - | 169 | Unsupported cipher sessions |
| `ssl_unsupported_cipher_rate` | integer | /s | 0 | Unsupported cipher sessions rate |

#### Notes
- SSL/TLS protocol statistics
- Track cipher usage and errors

---

### palo_alto_counters_http2

**Category:** Counters  
**Description:** Global HTTP/2 counters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields 

> **Note:** _This is a sample list of fields. Actual number of fields vary from device to device. Run ``show counter global filter category http2`` on the device to see full list of captured fields_

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `http2_process` | integer | - | 12 | HTTP/2 connections processed |
| `http2_process_rate` | integer | /s | 0 | HTTP/2 connections processed rate |
| `http2_goaway_recv` | integer | - | 12 | HTTP/2 GOAWAY frames received |
| `http2_goaway_recv_rate` | integer | /s | 0 | HTTP/2 GOAWAY frames received rate |

#### Notes
- HTTP/2 protocol statistics
- Monitor modern web traffic

---

## GlobalProtect Measurements

GlobalProtect measurements track VPN gateway and portal statistics.

### palo_alto_gp_gateway

**Category:** GlobalProtect  
**Description:** GlobalProtect gateway statistics  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low to Medium  
**Data Points per Collection:** Multiple (one per gateway)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `gateway_name` | string | PanGP-Matrix-Gateway | Gateway name |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `current_users` | integer | - | 0 | Current connected users |
| `previous_users` | integer | - | 1 | Previous user count |
| `max_concurrent_tunnels` | integer | - | 1 | Max concurrent tunnels |
| `successful_ipsec_connections` | integer | - | 2 | Successful IPsec connections |
| `total_tunnel_count` | integer | - | 2616222 | Total tunnel count |

#### Notes
- One data point per GlobalProtect gateway
- Monitor for user connection trends
- Track tunnel capacity

---

### palo_alto_gp_portal

**Category:** GlobalProtect  
**Description:** GlobalProtect portal statistics  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** Multiple (one per portal)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |
| `portal_name` | string | Dev-PANGP-Portal | Portal name |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `successful_connections` | integer | - | 2 | Successful connections |

#### Notes
- One data point per GlobalProtect portal
- Monitor portal availability

---

## VPN Measurements

VPN measurements track IPsec and SSL VPN tunnel statistics.

### palo_alto_vpn_flows

**Category:** VPN  
**Description:** VPN flow summary statistics  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Low  
**Data Points per Collection:** 1

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-D-FW01 | Device hostname |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `num_ipsec` | integer | - | 0 | Number of IPsec flows |
| `num_sslvpn` | integer | - | 1 | Number of SSL VPN flows |
| `total_flows` | integer | - | 1 | Total VPN flows |

#### Notes
- Summary of all VPN flows
- Monitor for unexpected VPN activity
- Track VPN usage trends

---

### palo_alto_ipsec_flow

**Category:** VPN  
**Description:** Active IPsec flow operational state  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per active IPsec flow)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-P-NET-FW02 | Device hostname |
| `flow_name` | string | STS-MO-Test | Flow/tunnel name |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `flow_id` | integer | - | 1 | Flow ID |
| `gateway_id` | integer | - | 1 | Associated gateway ID |
| `inner_interface` | string | - | tunnel.12 | Inner (logical) interface |
| `outer_interface` | string | - | ethernet1/3 | Outer (physical) interface |
| `state` | string | - | active | Flow state (active/down) |
| `ipsec_mode` | string | - | tunnel | IPsec mode (tunnel/transport) |
| `local_ip` | string | - | 10.11.0.253 | Local endpoint IP address |
| `peer_ip` | string | - | 200.30.0.99 | Peer endpoint IP address |
| `monitoring` | string | - | off | Path monitoring status (on/off) |
| `owner` | integer | - | 1 | Owner ID |
| `state_up` | integer | boolean | 1 | Flow is active (1=active, 0=down) |

#### Notes
- One data point per active IPsec flow
- Captures operational state from `vpn_flows.IPSec.entry`
- Different from `palo_alto_vpn_tunnel` which shows configuration
- Use `state_up` field for simple up/down alerting
- Shows actual running interfaces (both inner tunnel and outer physical)
- Critical for real-time flow state monitoring

---

### palo_alto_vpn_tunnel

**Category:** VPN  
**Description:** Individual VPN tunnel configuration and status  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per VPN tunnel)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-P-NET-FW02 | Device hostname |
| `tunnel_name` | string | STS-MO-Test | Tunnel name |
| `gateway` | string | IGW-MO-TLSR | Associated gateway name |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `tunnel_id` | integer | - | 1 | Tunnel ID |
| `protocol` | string | - | ESP | IPsec protocol (ESP/AH) |
| `mode` | string | - | tunl | Tunnel mode |
| `dh_group` | string | - | no-pfs | Diffie-Hellman group for PFS |
| `encryption` | string | - | AES256 | Encryption algorithm |
| `hash` | string | - | SHA1 | Hash algorithm |
| `lifetime` | integer | seconds | 3600 | SA lifetime in seconds |
| `kb_limit` | integer | KB | 0 | KB limit (0 = unlimited) |

#### Notes
- One data point per configured VPN tunnel
- Tracks tunnel configuration parameters
- Use for inventory and configuration monitoring
- `dh_group` of "no-pfs" means Perfect Forward Secrecy is disabled

---

### palo_alto_vpn_gateway

**Category:** VPN  
**Description:** VPN gateway (IKE) configuration and parameters  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per VPN gateway)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-P-NET-FW02 | Device hostname |
| `gateway_name` | string | IGW-MO-TLSR | Gateway name |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `gateway_id` | integer | - | 1 | Gateway ID |
| `socket` | integer | - | 1024 | Socket number |
| `nat_t` | integer | - | 0 | NAT traversal (0=disabled, 1=enabled) |
| `peer_ip` | string | - | 200.30.0.99 | Peer gateway IP address |
| `local_ip` | string | - | 99.40.10.1 | Local gateway IP address |
| `ike_version` | integer | - | 2 | IKE version (1 or 2) |
| `authentication` | string | - | PSK | Authentication method |
| `dh_group` | string | - | DH14 | Diffie-Hellman group |
| `encryption` | string | - | AES256 | Encryption algorithm |
| `hash` | string | - | SHA256 | Hash algorithm |
| `prf` | string | - | SHA256 | Pseudo-Random Function (IKEv2 only) |
| `lifetime` | integer | seconds | 28800 | IKE SA lifetime in seconds |

#### Notes
- One data point per VPN gateway
- Contains IKE (Phase 1) parameters
- Prefers IKEv2 settings over IKEv1 when both are configured
- Monitor for weak cryptography (DH group, encryption)
- Typical lifetime is 8 hours (28800 seconds)

---

### palo_alto_ipsec_sa

**Category:** VPN  
**Description:** Active IPsec Security Associations with lifetime tracking  
**Update Frequency:** Frequently (every collection)  
**Cardinality:** Medium  
**Data Points per Collection:** Multiple (one per active IPsec SA)

#### Tags

| Tag | Type | Example | Description |
|-----|------|---------|-------------|
| `hostname` | string | VM-P-NET-FW02 | Device hostname |
| `tunnel_name` | string | STS-MO-Test | Tunnel name |
| `gateway` | string | IGW-MO-TLSR | Gateway name |

#### Fields

| Field | Type | Unit | Example | Description |
|-------|------|------|---------|-------------|
| `gateway_id` | integer | - | 1 | Gateway ID |
| `tunnel_id` | integer | - | 1 | Tunnel ID |
| `remote_ip` | string | - | 99.40.10.1 | Remote peer IP address |
| `protocol` | string | - | ESP | IPsec protocol |
| `encryption` | string | - | A256 | Encryption algorithm |
| `hash` | string | - | SHA1 | Hash algorithm |
| `inbound_spi` | integer | - | 4248218959 | Inbound SPI (Security Parameter Index) |
| `outbound_spi` | integer | - | 4208195665 | Outbound SPI |
| `lifetime_seconds` | integer | seconds | 3600 | SA lifetime |
| `remaining_seconds` | integer | seconds | 2344 | Time remaining until rekey |
| `remaining_percent` | float | % | 65.11 | Percentage of lifetime remaining |

#### Notes
- One data point per active IPsec SA (Phase 2)
- Critical for monitoring tunnel health and rekey timing
- Alert when `remaining_seconds` < 300 (5 minutes) to catch rekey issues
- `remaining_percent` makes it easy to set percentage-based alerts
- SPI values are unique identifiers for inbound/outbound traffic
- SPIs change with each rekey operation

---

## Appendix

### Data Types

- **integer**: Whole numbers (stored as integers in InfluxDB)
- **float**: Decimal numbers (stored as floats in InfluxDB)
- **string**: Text values (stored as strings in InfluxDB)
- **boolean**: True/false values (stored as booleans in InfluxDB)

### Using Rate Fields

Many counter measurements include both cumulative counters and rate fields (e.g., `pkt_sent` and `pkt_sent_rate`). The rate fields represent the current rate per second. For historical analysis in Grafana, use the `derivative()` function on cumulative counters.

### Cardinality Notes

- **Low**: Single data point per firewall
- **Medium**: Multiple data points per firewall (e.g., one per interface or BGP peer)
- **High**: Many data points per firewall (rare in this schema)

---

**Document Version:** 1.6.0  
**Last Updated:** 2025-11-17  
**Generated From:** influxdb_schema.json
