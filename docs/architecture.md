# Architecture Documentation

This document provides comprehensive architecture diagrams for the Palo Alto Grafana Monitoring project.

**Note:** For detailed InfluxDB measurement specifications, see `docs/influxdb_measurements.md`.

## Table of Contents
1. [System Architecture](#system-architecture)
2. [Component Architecture](#component-architecture)
3. [Data Flow](#data-flow)
4. [Deployment Architecture](#deployment-architecture)
5. [Module Interactions](#module-interactions)

---

## System Architecture

This diagram shows the high-level architecture of the monitoring solution, including external systems.

```mermaid
flowchart TB
    subgraph "Palo Alto Networks Infrastructure"
        FW1[Firewall 1<br/>PAN-OS]
        FW2[Firewall 2<br/>PAN-OS]
        FW3[Firewall N<br/>PAN-OS]
    end
    
    subgraph "Monitoring Application"
        PA[PA Query Tool<br/>pa_query.py]
        
        subgraph "Core Components"
            CLIENT[PaloAltoClient<br/>Multi-Firewall Support]
            
            subgraph "Statistics Collectors"
                SYS[SystemStats]
                NET[InterfaceStats]
                ROUTE[RoutingStats]
                GP[GlobalProtectStats]
                VPN[VpnTunnelStats]
                CTR[GlobalCounters]
            end
        end
        
        CONV[InfluxDB Converter<br/>influxdb_converter.py]
        ANALYZER[Data Analyzer<br/>data_analyzer.py]
    end
    
    subgraph "Time-Series Database"
        INFLUX[(InfluxDB)]
    end
    
    subgraph "Visualization Layer"
        GRAFANA[Grafana Dashboards]
    end
    
    subgraph "Configuration"
        CONFIG[config.yaml<br/>API Keys & Settings]
    end
    
    %% Connections
    CONFIG -.->|Configuration| CLIENT
    FW1 -->|REST API<br/>HTTPS| CLIENT
    FW2 -->|REST API<br/>HTTPS| CLIENT
    FW3 -->|REST API<br/>HTTPS| CLIENT
    
    CLIENT -->|Statistics| SYS
    CLIENT -->|Statistics| NET
    CLIENT -->|Statistics| ROUTE
    CLIENT -->|Statistics| GP
    CLIENT -->|Statistics| VPN
    CLIENT -->|Statistics| CTR
    
    SYS -->|JSON Data| PA
    NET -->|JSON Data| PA
    ROUTE -->|JSON Data| PA
    GP -->|JSON Data| PA
    VPN -->|JSON Data| PA
    CTR -->|JSON Data| PA
    
    PA -->|JSON Output| CONV
    PA -->|JSON Output| ANALYZER
    CONV -->|Line Protocol| INFLUX
    INFLUX -->|Query API| GRAFANA
    
    style FW1 fill:#ff9999
    style FW2 fill:#ff9999
    style FW3 fill:#ff9999
    style INFLUX fill:#9999ff
    style GRAFANA fill:#99ff99
    style CLIENT fill:#ffcc99
```

**Key Points:**
- **Read-Only Operations**: All firewall interactions are read-only via REST API
- **Multi-Firewall Support**: Concurrent data collection from multiple firewalls
- **Flexible Output**: JSON for programmatic use, Table for human readability
- **Time-Series Storage**: InfluxDB line protocol for efficient metrics storage

---

## Component Architecture

This diagram shows the internal structure of the Python application.

```mermaid
classDiagram
    class PaloAltoClient {
        +host: str
        +port: int
        +firewall_name: str
        +multi_firewall_mode: bool
        +firewalls: Dict
        +execute_operational_command(cmd)
        +execute_on_all_firewalls(operation)
        +execute_on_specific_firewalls(names, operation)
        +get_firewall_names()
        +validate_firewall_config()
    }
    
    class PaloAltoAuth {
        +host: str
        +api_key: str
        +set_api_key(key)
        +get_api_key()
        +test_authentication()
    }
    
    class SystemStats {
        +client: PaloAltoClient
        +stats_config: StatsCollectionConfig
        +get_system_data()
        +parse_top_output()
        +parse_disk_space_string()
    }
    
    class InterfaceStats {
        +client: PaloAltoClient
        +get_interface_data()
        +get_interface_counters()
    }
    
    class RoutingStats {
        +client: PaloAltoClient
        +get_routing_data()
        +get_bgp_summary()
        +get_bgp_peer_status()
        +get_routing_table()
    }
    
    class GlobalCounters {
        +client: PaloAltoClient
        +get_counter_data()
        +get_threat_counters()
    }
    
    class GlobalProtectStats {
        +client: PaloAltoClient
        +get_global_protect_data()
        +get_gateway_summary()
    }
    
    class VpnTunnelStats {
        +client: PaloAltoClient
        +get_vpn_data()
        +get_ipsec_tunnels()
    }
    
    class Settings {
        +config: Dict
        +get(key, default)
        +get_firewall(name)
        +get_firewalls()
        +reload()
    }
    
    class StatsCollectionConfig {
        +settings: Settings
        +is_collection_enabled(module, stat_type, firewall)
    }
    
    class InfluxDBConverter {
        +timestamp: int
        +system_converter: SystemConverter
        +interface_converter: InterfaceConverter
        +routing_converter: RoutingConverter
        +convert(stats_data)
        +get_stats()
    }
    
    class Logger {
        +get_logger(name)
        +update_logger_firewall_context(logger, name, host)
    }
    
    PaloAltoClient --> PaloAltoAuth : uses
    PaloAltoClient --> Logger : logs to
    PaloAltoClient --> Settings : reads config
    
    SystemStats --> PaloAltoClient : queries
    InterfaceStats --> PaloAltoClient : queries
    RoutingStats --> PaloAltoClient : queries
    GlobalCounters --> PaloAltoClient : queries
    GlobalProtectStats --> PaloAltoClient : queries
    VpnTunnelStats --> PaloAltoClient : queries
    
    SystemStats --> StatsCollectionConfig : checks enabled
    InterfaceStats --> StatsCollectionConfig : checks enabled
    RoutingStats --> StatsCollectionConfig : checks enabled
    
    StatsCollectionConfig --> Settings : reads from
    
    InfluxDBConverter ..> SystemStats : converts data from
    InfluxDBConverter ..> InterfaceStats : converts data from
    InfluxDBConverter ..> RoutingStats : converts data from
```

**Key Points:**
- **Client Pattern**: `PaloAltoClient` manages all firewall communications
- **Collector Pattern**: Each stats module is independent and focused
- **Configuration Management**: Centralized settings with per-firewall overrides
- **Converter Pattern**: Modular converters for each data category

---

## Data Flow

This diagram illustrates how data flows through the system from collection to visualization.

```mermaid
sequenceDiagram
    participant User
    participant CLI as pa_query.py CLI
    participant Client as PaloAltoClient
    participant FW1 as Firewall 1
    participant FW2 as Firewall 2
    participant Stats as Stats Collectors
    participant Conv as InfluxDB Converter
    participant DB as InfluxDB
    participant Grafana
    
    User->>CLI: Execute command<br/>(e.g., all-stats)
    CLI->>Client: Initialize client<br/>(multi-firewall mode)
    
    activate Client
    Client->>FW1: Authenticate<br/>(API Key)
    FW1-->>Client: Auth Success
    Client->>FW2: Authenticate<br/>(API Key)
    FW2-->>Client: Auth Success
    deactivate Client
    
    CLI->>Stats: Initialize collectors<br/>(System, Interface, etc.)
    
    loop For each stat type
        Stats->>Client: execute_on_all_firewalls(operation)
        
        par Parallel Collection
            Client->>FW1: Execute operational command
            FW1-->>Client: XML Response
            and
            Client->>FW2: Execute operational command
            FW2-->>Client: XML Response
        end
        
        Client->>Client: Parse XML to Dict
        Client-->>Stats: Return results<br/>{fw1: {success, data}, fw2: {...}}
    end
    
    Stats-->>CLI: Aggregated statistics<br/>(all firewalls, all modules)
    
    alt JSON Output
        CLI->>User: Display JSON
        User->>Conv: Pipe to converter
        Conv->>Conv: Transform to<br/>InfluxDB line protocol
        Conv->>DB: Write metrics
        DB->>Grafana: Query metrics
        Grafana->>User: Display dashboards
    else Table Output
        CLI->>User: Display formatted tables
    end
```

**Key Points:**
- **Parallel Collection**: Multiple firewalls queried simultaneously using ThreadPoolExecutor
- **Consistent Data Structure**: All modules return standardized format: `{firewall: {success, data, error}}`
- **Flexible Output**: Same data can be visualized as tables or sent to InfluxDB
- **Error Handling**: Individual firewall failures don't stop collection from others

---

## Deployment Architecture

This diagram shows a typical deployment scenario.

```mermaid
flowchart TB
    subgraph "Production Environment"
        subgraph "Firewall Cluster"
            FW1[Primary Firewall<br/>10.1.1.1:443]
            FW2[Secondary Firewall<br/>10.1.1.2:443]
        end
        
        subgraph "DMZ"
            FW3[DMZ Firewall<br/>10.2.1.1:443]
        end
    end
    
    subgraph "Monitoring Server"
        subgraph "Application Directory"
            APP["/opt/palo-alto-monitor/"]
            CONFIG[config/config.yaml<br/>API Keys: ENV vars]
            LOGS[logs/pa_stats.log<br/>Rotating logs]
        end
        
        subgraph "Python Environment"
            VENV[Virtual Environment<br/>Python 3.12+]
            DEPS[Dependencies<br/>requirements.txt]
        end
        
        subgraph "Scheduling"
            CRON[Cron Job<br/>*/5 * * * *]
            SCRIPT[Collection Script<br/>pa_query.py all-stats]
        end
    end
    
    subgraph "Data Storage Server"
        INFLUX[(InfluxDB<br/>Port 8086<br/>Database: palo_alto)]
    end
    
    subgraph "Visualization Server"
        GRAFANA[Grafana<br/>Port 3000<br/>Dashboards]
    end
    
    subgraph "Configuration Management"
        ENV[Environment Variables<br/>PA_FIREWALL_HOST<br/>PA_API_KEY]
        VAULT[Secrets Vault<br/>Optional: HashiCorp Vault]
    end
    
    %% Connections
    VAULT -.->|Secrets| ENV
    ENV -.->|Environment| CONFIG
    
    CRON -->|Every 5 min| SCRIPT
    SCRIPT -->|Uses| APP
    SCRIPT -->|Reads| CONFIG
    SCRIPT -->|Writes| LOGS
    SCRIPT -->|Uses| VENV
    
    SCRIPT -->|HTTPS API Calls| FW1
    SCRIPT -->|HTTPS API Calls| FW2
    SCRIPT -->|HTTPS API Calls| FW3
    
    SCRIPT -->|Line Protocol| INFLUX
    INFLUX -->|Queries| GRAFANA
    
    style FW1 fill:#ff9999
    style FW2 fill:#ff9999
    style FW3 fill:#ff9999
    style INFLUX fill:#9999ff
    style GRAFANA fill:#99ff99
    style VAULT fill:#ffff99
```

**Deployment Options:**

### Option 1: Cron-Based Collection
```bash
# /etc/cron.d/palo-alto-monitor
*/5 * * * * cd /path/to/palo-alto-grafana-monitoring && \
    source venv/bin/activate && \
    ./pa_query.py -o json all-stats | \
    ./influxdb_converter.py | \
    curl -XPOST 'http://influxdb:8086/write?db=Telegraf' \
    --data-binary @- >> logs/cron.log 2>&1

# Or pipe directly to InfluxDB
*/5 * * * * cd /path/to/palo-alto-grafana-monitoring && source venv/bin/activate && python pa_query.py -o json all-stats | python influxdb_converter.py | influx write --bucket Telegraf
```

### Option 2: Telegraf Exec Plugin

[Telegraf](https://www.influxdata.com/time-series-platform/telegraf/) provides a more robust solution with built-in buffering, retry logic, and direct InfluxDB integration.

Add this configuration to your Telegraf config file (Example: `/etc/telegraf/telegraf.d/inputs_palo_alto.conf`):

```toml
# Palo Alto Networks Firewall Monitoring
[[inputs.exec]]
  ## Command to run
  commands = [
    "/bin/bash -c 'cd /path/to/palo-alto-grafana-monitoring && /path/to/palo-alto-grafana-monitoring/.venv/bin/python pa_query.py -o json all-stats | /path/to/palo-alto-grafana-monitoring/.venv/bin/python influxdb_converter.py'"
  ]
  
  ## Timeout for the command to complete
  timeout = "60s"
  
  ## Data format to consume (influx = line protocol)
  data_format = "influx"
  
  ## Collection interval
  interval = "1m"

```

---

## Module Interactions

This diagram shows how different modules interact during a typical query operation.

```mermaid
flowchart LR
    subgraph "Entry Point"
        CLI[pa_query.py<br/>Click CLI]
    end
    
    subgraph "Configuration Layer"
        SETTINGS[Settings<br/>config/settings.py]
        CONFIG[config.yaml]
        ENV[Environment Variables]
    end
    
    subgraph "Client Layer"
        CLIENT[PaloAltoClient<br/>Multi-firewall support]
        AUTH[PaloAltoAuth<br/>API Key Auth]
        EXEC[Concurrent Executor<br/>ThreadPoolExecutor]
    end
    
    subgraph "Statistics Layer"
        SYS[SystemStats<br/>13 system + 4 environmental]
        IFACE[InterfaceStats<br/>4 measurements]
        ROUTE[RoutingStats<br/>4 measurements]
        COUNT[GlobalCounters<br/>10 categories]
        GP[GlobalProtectStats<br/>2 measurements]
        VPN[VpnTunnelStats<br/>5 measurements]
    end
    
    subgraph "Data Processing"
        PARSER[XML Parser<br/>xmltodict]
        VALIDATOR[Data Validator<br/>Type conversion]
        LOGGER[Logging<br/>Structured logs]
    end
    
    subgraph "Output Layer"
        JSON[JSON Output<br/>Machine-readable]
        TABLE[Table Output<br/>Human-readable]
        FILE[File Output<br/>Optional]
    end
    
    subgraph "Conversion Layer"
        CONV[InfluxDB Converter<br/>43 measurements]
        LINEPROTO[Line Protocol<br/>Time-series format]
    end
    
    %% Configuration flow
    ENV -->|Override| CONFIG
    CONFIG --> SETTINGS
    SETTINGS --> CLIENT
    
    %% Command flow
    CLI --> CLIENT
    CLIENT --> AUTH
    CLIENT --> EXEC
    
    %% Statistics collection
    EXEC --> SYS
    EXEC --> ENV
    EXEC --> IFACE
    EXEC --> ROUTE
    EXEC --> COUNT
    EXEC --> GP
    EXEC --> VPN
    
    %% Data processing
    SYS --> PARSER
    ENV --> PARSER
    IFACE --> PARSER
    ROUTE --> PARSER
    COUNT --> PARSER
    GP --> PARSER
    VPN --> PARSER
    
    PARSER --> VALIDATOR
    VALIDATOR --> LOGGER
    
    %% Output
    VALIDATOR --> JSON
    VALIDATOR --> TABLE
    JSON --> FILE
    TABLE --> FILE
    
    %% Conversion
    JSON --> CONV
    CONV --> LINEPROTO
    
    style CLI fill:#e1f5ff
    style CLIENT fill:#ffcc99
    style CONV fill:#c8e6c9
    style LINEPROTO fill:#c8e6c9
```

**Module Responsibilities:**

| Module | Responsibility | Key Features |
|--------|---------------|--------------|
| `pa_query.py` | CLI entry point | Click-based commands, output formatting |
| `PaloAltoClient` | Firewall communication | Multi-firewall, retry logic, connection pooling |
| `PaloAltoAuth` | Authentication | API key management, auth testing |
| `SystemStats` | System & environmental metrics | CPU, memory, disk, uptime, HA, environmental sensors |
| `InterfaceStats` | Network interfaces | Hardware info, logical config, counters |
| `RoutingStats` | Routing information | BGP, static routes, routing tables |
| `GlobalCounters` | Threat & traffic | Session, packet, threat counters |
| `GlobalProtectStats` | VPN users | Gateway and portal statistics |
| `VpnTunnelStats` | IPSec tunnels | Tunnel status and flows |
| `InfluxDB Converter` | Time-series format | 42 measurements, proper tagging |

---

## Statistics Coverage

The system collects **42 distinct measurements** across 6 categories (plus 2 optional routing fallback measurements):

### System Module (13 measurements)
- System Identity
- System Uptime
- Content Versions
- MAC Count
- CPU Usage
- Memory Usage
- Swap Usage
- Load Average
- Task Statistics
- Disk Usage (per mount point)
- HA Status
- CPU Dataplane Tasks
- CPU Dataplane Cores (per-core statistics)

### Environmental Module (4 measurements)
**Note:** Environmental data is collected by `SystemStats` but converted separately.
- Thermal Sensors (per sensor)
- Fan Speeds (per fan)
- Power/Voltage Sensors (per sensor)
- Power Supply Status (per PSU)

### Interface Module (4 measurements)
- Interface Hardware Info
- Interface Logical Config
- Hardware Interface Traffic Counters
- Logical Interface Traffic Counters

### Routing Module (4 measurements + 2 fallbacks)
- BGP Summary
- BGP Peer Status (per peer)
- BGP Path Monitor (per monitored path)
- Routing Table Counts (by VRF and protocol)
- *Fallback: Static Routes Count (when routing_table disabled)*
- *Fallback: BGP Routes Count (when routing_table disabled)*

### Global Counters (10 measurements by category)
- Flow counters
- Session statistics
- Packet counters
- AppID counters
- TCP counters
- CTD counters
- Log counters
- Proxy counters
- SSL counters
- HTTP2 counters

### GlobalProtect (2 measurements)
- Gateway Summary and Statistics (per gateway)
- Portal Summary and Statistics (per portal)

### VPN Tunnels (5 measurements)
- VPN Flows Summary
- IPsec Flow Operational State (per active flow)
- VPN Tunnels (per tunnel)
- VPN Gateways (per gateway)
- IPsec Security Associations (per SA)

---

## Network Communication

```mermaid
sequenceDiagram
    participant App as Monitoring App
    participant DNS
    participant FW as Firewall
    
    Note over App,FW: HTTPS (Port 443) - Read-Only API
    
    App->>DNS: Resolve firewall hostname
    DNS-->>App: IP Address
    
    App->>FW: HTTPS GET /api/<br/>?type=op&cmd=...&key=API_KEY
    
    alt Authentication Success
        FW->>FW: Validate API Key
        FW->>FW: Execute operational command
        FW->>FW: Generate XML response
        FW-->>App: 200 OK<br/>Content-Type: application/xml
        App->>App: Parse XML to Dict
    else Authentication Failure
        FW-->>App: 403 Forbidden<br/>Invalid API key
        App->>App: Log error, retry or fail
    else Network Error
        FW--xApp: Connection timeout
        App->>App: Retry with exponential backoff
    end
```

**Security Considerations:**
- **API Key Only**: No username/password authentication
- **HTTPS Required**: All communication encrypted
- **SSL Verification**: Configurable per firewall (disabled for self-signed certs)
- **Read-Only**: No configuration changes possible
- **Rate Limiting**: Built-in retry logic with exponential backoff

---

## Error Handling Strategy

```mermaid
flowchart TD
    START[API Request]
    
    START --> AUTH{Authentication<br/>Valid?}
    AUTH -->|No| AUTHFAIL[AuthenticationError]
    AUTH -->|Yes| CONNECT{Connection<br/>Successful?}
    
    CONNECT -->|No| RETRY{Retry<br/>Attempts<br/>Remaining?}
    RETRY -->|Yes| WAIT[Wait with<br/>Exponential Backoff]
    WAIT --> START
    RETRY -->|No| CONNFAIL[ConnectionError]
    
    CONNECT -->|Yes| RESPONSE{Response<br/>Valid?}
    RESPONSE -->|No| APIFAIL[APIError]
    RESPONSE -->|Yes| PARSE{XML Parse<br/>Success?}
    
    PARSE -->|No| PARSEFAIL[ParseError]
    PARSE -->|Yes| SUCCESS[Return Data]
    
    AUTHFAIL --> LOG[Log Error]
    CONNFAIL --> LOG
    APIFAIL --> LOG
    PARSEFAIL --> LOG
    
    LOG --> MULTI{Multi-Firewall<br/>Mode?}
    MULTI -->|Yes| CONTINUE[Continue with<br/>other firewalls]
    MULTI -->|No| FAIL[Raise Exception]
    
    SUCCESS --> END[Complete]
    CONTINUE --> END
    
    style SUCCESS fill:#90EE90
    style FAIL fill:#FFB6C6
    style CONTINUE fill:#FFE4B5
```

**Error Categories:**
- `AuthenticationError`: Invalid API key or authentication failure
- `ConnectionError`: Network issues, timeouts, unreachable host
- `APIError`: Firewall API returned error response
- `ParseError`: Invalid XML or unexpected response format
- `ConfigurationError`: Invalid configuration settings

---

## Performance Characteristics

### Concurrent Collection
- **ThreadPoolExecutor**: Default 5 workers (configurable)
- **Parallel Queries**: All firewalls queried simultaneously
- **Timeout Protection**: 30-second default per operation

### Data Volume (per 5-minute collection)
| Module | Measurements | Estimated Size |
|--------|--------------|----------------|
| System | 13 | ~3 KB |
| Environmental | 4 | ~1 KB |
| Interfaces | 4 per interface | ~2-6 KB |
| Routing | 4 + per peer | ~2-10 KB |
| Counters | 10 categories | ~5-15 KB |
| GlobalProtect | 2 | ~1 KB |
| VPN | 5 | ~1-2 KB |
| **Total per firewall** | **42** | **~15-40 KB** |


---

## Configuration Hierarchy

```mermaid
flowchart TD
    ENV[Environment Variables<br/>Highest Priority]
    YAML[config.yaml<br/>Medium Priority]
    DEFAULT[Code Defaults<br/>Lowest Priority]
    
    FINAL[Final Configuration]
    
    ENV --> MERGE[Merge Configs]
    YAML --> MERGE
    DEFAULT --> MERGE
    MERGE --> FINAL
    
    FINAL --> FW1[Firewall 1 Config]
    FINAL --> FW2[Firewall 2 Config]
    FINAL --> GLOBAL[Global Settings]
    
    style ENV fill:#ffffcc
    style YAML fill:#ccffcc
    style DEFAULT fill:#ccccff
    style FINAL fill:#ffcccc
```

**Configuration Precedence:**
1. Environment variables (e.g., `PA_API_KEY`)
2. YAML configuration file (`config/config.yaml`)
3. Code defaults

**Per-Firewall Overrides:**
- Host, port, timeout
- SSL verification
- API key
- Stats collection toggles

---

## Conclusion

This architecture provides:
- ✅ **Scalability**: Multi-firewall support with concurrent collection
- ✅ **Reliability**: Comprehensive error handling and retry logic
- ✅ **Flexibility**: Multiple output formats (JSON, Table, InfluxDB)
- ✅ **Modularity**: Independent stats collectors, easy to extend
- ✅ **Security**: Read-only API access, no configuration changes
- ✅ **Observability**: Structured logging, per-firewall context
- ✅ **Time-Series Ready**: Native InfluxDB line protocol conversion

For implementation details, see the code in:
- `src/palo_alto_client/` - Client implementation
- `src/stats/` - Statistics collectors
- `influxdb_converter.py` - InfluxDB conversion
- `pa_query.py` - CLI interface

