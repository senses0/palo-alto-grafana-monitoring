# Quick Reference Diagrams

Quick, at-a-glance diagrams for common scenarios and workflows.

## Quick Start Flow

```mermaid
flowchart LR
    START([Start]) --> INSTALL[Install Dependencies<br/>pip install -r requirements.txt]
    INSTALL --> CONFIG[Configure<br/>config/config.yaml]
    CONFIG --> APIKEY[Add API Keys<br/>Per Firewall]
    APIKEY --> TEST[Test Connection<br/>pa_query.py validate-config]
    TEST --> RUN[Run Query<br/>pa_query.py system-info]
    RUN --> SUCCESS([Success!])
    
    style START fill:#90EE90
    style SUCCESS fill:#90EE90
    style TEST fill:#FFE4B5
```

---

## Command Workflow

```mermaid
flowchart TD
    USER([User])
    
    USER --> A[pa_query.py<br/>system-info]
    USER --> B[pa_query.py<br/>all-stats]
    USER --> C[pa_query.py<br/>routing-info]
    USER --> D[pa_query.py<br/>interface-stats]
    
    A --> JSON1[JSON Output]
    B --> JSON2[JSON Output]
    C --> JSON3[JSON Output]
    D --> JSON4[JSON Output]
    
    A --> TABLE1[Table Output]
    B --> TABLE2[Table Output]
    C --> TABLE3[Table Output]
    D --> TABLE4[Table Output]
    
    JSON2 --> CONV[influxdb_converter.py]
    CONV --> METRICS[InfluxDB Metrics]
    METRICS --> GRAFANA[Grafana Dashboard]
    
    style USER fill:#e1f5ff
    style GRAFANA fill:#99ff99
```

---

## Multi-Firewall Collection

```mermaid
sequenceDiagram
    participant CLI
    participant Client
    participant FW1 as Firewall 1
    participant FW2 as Firewall 2
    participant FW3 as Firewall 3
    
    CLI->>Client: Initialize (multi-firewall)
    
    par Parallel Authentication
        Client->>FW1: Authenticate
        FW1-->>Client: ✓
    and
        Client->>FW2: Authenticate
        FW2-->>Client: ✓
    and
        Client->>FW3: Authenticate
        FW3-->>Client: ✓
    end
    
    CLI->>Client: get_system_data()
    
    par Parallel Collection
        Client->>FW1: Query stats
        FW1-->>Client: Data
    and
        Client->>FW2: Query stats
        FW2-->>Client: Data
    and
        Client->>FW3: Query stats
        FW3-->>Client: Data
    end
    
    Client-->>CLI: Aggregated results
```

---

## Data Transformation Pipeline

```mermaid
flowchart LR
    FW[Firewall<br/>XML API] --> CLIENT[PaloAltoClient<br/>XML → Dict]
    CLIENT --> STATS[Stats Collectors<br/>Extract & Parse]
    STATS --> JSON[JSON Output<br/>Structured Data]
    JSON --> CONV[Converter<br/>Dict → Line Protocol]
    CONV --> DB[(InfluxDB<br/>Time Series)]
    DB --> QUERY[Grafana Query<br/>InfluxQL/Flux]
    QUERY --> VIZ[Dashboard<br/>Visualization]
    
    style FW fill:#ff9999
    style DB fill:#9999ff
    style VIZ fill:#99ff99
```

---

## Configuration Structure

```mermaid
mindmap
  root((config.yaml))
    Logging
      Level
      File Path
      Max Size
      Backup Count
    Query Settings
      Max Retries
      Retry Delay
      Timeout
    Firewalls
      Firewall 1
        Host
        Port
        API Key
        Description
        Location
        SSL Verify
      Firewall 2
        Host
        Port
        API Key
        ...
      Firewall N
        ...
    Stats Collection
      Global Toggles
        System
        Interfaces
        Routing
        Counters
        GlobalProtect
        VPN
      Per-Firewall Overrides
```

---

## Stats Module Coverage

**Note:** For detailed measurement specifications, see `docs/influxdb_measurements.md` (42 measurements total).

```mermaid
graph TB
    subgraph System[System Stats - 13 measurements]
        S1[Identity]
        S2[Uptime]
        S3[Content Versions]
        S4[MAC Count]
        S5[CPU Usage]
        S6[Memory]
        S7[Swap]
        S8[Load Avg]
        S9[Tasks]
        S10[Disk]
        S11[HA Status]
        S12[DP Tasks]
        S13[DP Cores]
    end
    
    subgraph Env[Environmental - 4 measurements]
        E1[Thermal]
        E2[Fans]
        E3[Power]
        E4[PSU]
    end
    
    subgraph Interface[Interface Stats - 4 measurements]
        I1[HW Info]
        I2[Logical Config]
        I3[HW Counters]
        I4[Logical Counters]
    end
    
    subgraph Routing[Routing Stats - 4 measurements]
        R1[BGP Summary]
        R2[BGP Peers]
        R3[BGP Path Monitor]
        R4[Route Counts]
    end
    
    subgraph Counters[Global Counters - 10 categories]
        C1[Flow]
        C2[Session]
        C3[Packet]
        C4[AppID]
        C5[TCP]
        C6[CTD]
        C7[Log]
        C8[Proxy]
        C9[SSL]
        C10[HTTP2]
    end
    
    subgraph GP[GlobalProtect - 2 measurements]
        G1[Gateway]
        G2[Portal]
    end
    
    subgraph VPN[VPN Tunnels - 5 measurements]
        V1[VPN Flows]
        V2[IPsec Flows]
        V3[Tunnels]
        V4[Gateways]
        V5[IPsec SA]
    end
    
    style System fill:#ffe6e6
    style Env fill:#fff0e6
    style Interface fill:#e6f3ff
    style Routing fill:#e6ffe6
    style Counters fill:#fff9e6
    style GP fill:#f3e6ff
    style VPN fill:#e6ffff
```

---

## Deployment Patterns

### Pattern 1: Direct CLI Collection
```mermaid
flowchart LR
    CRON[Cron Job<br/>*/5 * * * *] --> CLI[pa_query.py]
    CLI --> PIPE[Pipe Output]
    PIPE --> CONV[influxdb_converter.py]
    CONV --> CURL[curl POST]
    CURL --> INFLUX[(InfluxDB)]
    
    style CRON fill:#ffffcc
    style INFLUX fill:#9999ff
```

### Pattern 2: File-Based Collection
```mermaid
flowchart LR
    CRON[Cron Job] --> CLI[pa_query.py<br/>--output-file stats.json]
    CLI --> FILE[stats.json]
    FILE --> CONV[influxdb_converter.py<br/>--input stats.json]
    CONV --> FILE2[metrics.txt]
    FILE2 --> BATCH[Batch Upload]
    BATCH --> INFLUX[(InfluxDB)]
    
    style CRON fill:#ffffcc
    style INFLUX fill:#9999ff
```

### Pattern 3: Container-Based Collection
```mermaid
flowchart TB
    COMPOSE[docker-compose.yml]
    
    subgraph "Container Network"
        APP[Monitor Container<br/>pa_query.py]
        DB[InfluxDB Container]
        GRAF[Grafana Container]
    end
    
    FW1[Firewall 1]
    FW2[Firewall 2]
    
    COMPOSE --> APP
    COMPOSE --> DB
    COMPOSE --> GRAF
    
    APP --> FW1
    APP --> FW2
    APP --> DB
    DB --> GRAF
    
    style COMPOSE fill:#ffffcc
    style APP fill:#ffcc99
    style DB fill:#9999ff
    style GRAF fill:#99ff99
```

---

## Error Handling Flow

```mermaid
flowchart TD
    REQ[API Request]
    
    REQ --> AUTH{Auth OK?}
    AUTH -->|No| LOG1[Log Error]
    AUTH -->|Yes| CONN{Connect OK?}
    
    CONN -->|No| RETRY{Retry?}
    RETRY -->|Yes| WAIT[Backoff Wait]
    WAIT --> REQ
    RETRY -->|No| LOG2[Log Error]
    
    CONN -->|Yes| PARSE{Parse OK?}
    PARSE -->|No| LOG3[Log Error]
    PARSE -->|Yes| SUCCESS[Return Data]
    
    LOG1 --> MULTI{Multi-FW?}
    LOG2 --> MULTI
    LOG3 --> MULTI
    
    MULTI -->|Yes| CONT[Continue Next]
    MULTI -->|No| FAIL[Fail]
    
    SUCCESS --> END([Done])
    CONT --> END
    FAIL --> END
    
    style SUCCESS fill:#90EE90
    style FAIL fill:#FFB6C6
    style CONT fill:#FFE4B5
```

---

## Typical Grafana Dashboard Layout

```mermaid
graph TB
    subgraph Dashboard["Palo Alto Firewall Dashboard"]
        subgraph Row1["System Overview"]
            P1[CPU Usage]
            P2[Memory Usage]
            P3[Load Average]
            P4[Uptime]
        end
        
        subgraph Row2["Network Traffic"]
            P5[Interface Bandwidth]
            P6[Packet Rates]
            P7[Error Rates]
        end
        
        subgraph Row3["Security"]
            P8[Threat Counters]
            P9[Session Count]
            P10[URL Filter Stats]
        end
        
        subgraph Row4["BGP Routing"]
            P11[Peer Status]
            P12[Prefix Counts]
            P13[Path Monitor]
        end
        
        subgraph Row5["VPN"]
            P14[GlobalProtect Users]
            P15[IPSec Tunnels]
            P16[VPN Flows]
        end
    end
    
    INFLUX[(InfluxDB)] --> P1
    INFLUX --> P2
    INFLUX --> P3
    INFLUX --> P4
    INFLUX --> P5
    INFLUX --> P6
    INFLUX --> P7
    INFLUX --> P8
    INFLUX --> P9
    INFLUX --> P10
    INFLUX --> P11
    INFLUX --> P12
    INFLUX --> P13
    INFLUX --> P14
    INFLUX --> P15
    INFLUX --> P16
    
    style Dashboard fill:#f0f0f0
    style INFLUX fill:#9999ff
```

---

## Common Use Cases

### Use Case 1: Monitor Single Firewall
```bash
# Configure single firewall in config.yaml
python pa_query.py --firewall primary system-info
```

```mermaid
flowchart LR
    CMD[Command] --> CLIENT[Client<br/>Single FW Mode]
    CLIENT --> FW[Primary<br/>Firewall]
    FW --> RESULT[JSON/Table<br/>Output]
```

### Use Case 2: Monitor All Firewalls
```bash
# All firewalls configured in config.yaml
python pa_query.py all-stats
```

```mermaid
flowchart TD
    CMD[Command] --> CLIENT[Client<br/>Multi-FW Mode]
    CLIENT --> FW1[Firewall 1]
    CLIENT --> FW2[Firewall 2]
    CLIENT --> FW3[Firewall N]
    FW1 --> AGG[Aggregate]
    FW2 --> AGG
    FW3 --> AGG
    AGG --> RESULT[Unified<br/>Output]
```

### Use Case 3: Send to InfluxDB
```bash
# Collect and send to InfluxDB with Curl
python pa_query.py -o json all-stats | \
  python influxdb_converter.py | \
  curl -XPOST 'http://influxdb:8086/write?db=telegraf' \
  --data-binary @-
```

```mermaid
flowchart LR
    QUERY[pa_query.py] --> JSON[JSON Output]
    JSON --> CONV[Converter]
    CONV --> LINE[Line Protocol]
    LINE --> CURL[curl]
    CURL --> DB[(InfluxDB)]
    DB --> GRAF[Grafana]
    
    style DB fill:#9999ff
    style GRAF fill:#99ff99
```

### Use Case 4: Validate Configuration
```bash
# Test all firewall connections
python pa_query.py validate-config
```

```mermaid
flowchart TD
    CMD[validate-config]
    CMD --> CHECK1{FW1<br/>Reachable?}
    CMD --> CHECK2{FW2<br/>Reachable?}
    CMD --> CHECK3{FW3<br/>Reachable?}
    
    CHECK1 -->|Yes| AUTH1{Auth OK?}
    CHECK1 -->|No| FAIL1[❌ Failed]
    AUTH1 -->|Yes| OK1[✅ Valid]
    AUTH1 -->|No| FAIL1
    
    CHECK2 -->|Yes| AUTH2{Auth OK?}
    CHECK2 -->|No| FAIL2[❌ Failed]
    AUTH2 -->|Yes| OK2[✅ Valid]
    AUTH2 -->|No| FAIL2
    
    CHECK3 -->|Yes| AUTH3{Auth OK?}
    CHECK3 -->|No| FAIL3[❌ Failed]
    AUTH3 -->|Yes| OK3[✅ Valid]
    AUTH3 -->|No| FAIL3
    
    OK1 --> REPORT[Validation<br/>Report]
    OK2 --> REPORT
    OK3 --> REPORT
    FAIL1 --> REPORT
    FAIL2 --> REPORT
    FAIL3 --> REPORT
```

---


## Quick Troubleshooting

```mermaid
flowchart TD
    ISSUE([Issue/Error])
    
    ISSUE --> Q1{Connection<br/>Error?}
    Q1 -->|Yes| CHECK1[Check:<br/>- Firewall reachable?<br/>- Port 443 open?<br/>- SSL config correct?]
    
    Q1 -->|No| Q2{Auth<br/>Error?}
    Q2 -->|Yes| CHECK2[Check:<br/>- API key valid?<br/>- API key enabled?<br/>- Correct firewall?]
    
    Q2 -->|No| Q3{Parse<br/>Error?}
    Q3 -->|Yes| CHECK3[Check:<br/>- Firewall version?<br/>- Command supported?<br/>- XML format changed?]
    
    Q3 -->|No| Q4{Config<br/>Error?}
    Q4 -->|Yes| CHECK4[Check:<br/>- config.yaml syntax<br/>- Required fields<br/>- Environment vars]
    
    Q4 -->|No| OTHER[Check logs:<br/>logs/pa_stats.log]
    
    CHECK1 --> LOGS[Review Logs]
    CHECK2 --> LOGS
    CHECK3 --> LOGS
    CHECK4 --> LOGS
    OTHER --> LOGS
    
    LOGS --> VERBOSE[Run with --verbose<br/>for more details]
    
    style ISSUE fill:#FFB6C6
    style LOGS fill:#ffffcc
    style VERBOSE fill:#90EE90
```

---

## Data Flow Summary

```
Firewalls (XML API)
         ↓
   PaloAltoClient (Authentication, XML parsing)
         ↓
   Stats Collectors (Data extraction)
     - SystemStats (13 system + 4 environmental)
     - InterfaceStats (4 measurements)
     - RoutingStats (4 measurements)
     - GlobalCounters (10 categories)
     - GlobalProtectStats (2 measurements)
     - VpnTunnelStats (5 measurements)
         ↓
   JSON Output (Structured data)
         ↓
   InfluxDB Converter (42 measurements → Line protocol)
         ↓
   InfluxDB (Time-series storage)
         ↓
   Grafana (Visualization)
         ↓
   User (Monitoring & Alerts)
```

---

## Next Steps

For detailed documentation, see:
- `README.md` - Main project documentation
- `docs/architecture.md` - Comprehensive architecture details
- `tests/README.md` - Testing documentation
- `config/config.yaml.example` - Configuration examples

