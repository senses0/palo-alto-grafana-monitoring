# InfluxDB Configuration Guide

## Overview

This guide explains how to configure InfluxDB for use with the Palo Alto Grafana Monitoring tool, with a focus on InfluxQL query language support across different InfluxDB versions.

## Table of Contents

- [InfluxQL and Grafana](#influxql-and-grafana)
- [InfluxDB Version Differences](#influxdb-version-differences)
- [InfluxDB 2.x/3.x/Cloud Configuration](#influxdb-2x3xcloud-configuration)
- [Grafana Data Source Configuration](#grafana-data-source-configuration)
- [DBRP Mapping](#dbrp-mapping)
- [Additional Resources](#additional-resources)

## InfluxQL and Grafana

**InfluxQL** is InfluxDB's SQL-like query language that is the preferred method for querying data in Grafana dashboards. It provides:

- Familiar SQL-like syntax
- Native support in Grafana's InfluxDB data source
- Simple and intuitive queries for time series data
- Better performance for dashboard queries compared to Flux

## InfluxDB Version Differences

### InfluxDB 1.x

- **Native InfluxQL Support**: InfluxQL is the primary query language
- **Database/Retention Policy Model**: Uses traditional database and retention policy structure
- **No Additional Setup Required**: Queries work out of the box
- **Grafana Integration**: Seamless - just point to the database

### InfluxDB 2.x, 3.x, and Cloud

- **Bucket-Based Model**: Uses buckets instead of databases
- **Primary Query Language**: Flux is the native query language
- **InfluxQL Support**: Available through DBRP (Database/Retention Policy) mapping
- **Additional Setup Required**: Must create DBRP mappings to use InfluxQL
- **Grafana Integration**: Requires DBRP mapping for InfluxQL queries


## InfluxDB 2.x/3.x/Cloud Configuration

### Understanding Buckets and DBRP

InfluxDB 2.x+ uses **buckets** instead of databases. To use InfluxQL (required for Grafana Dashboard provided with this project), you must create a **DBRP mapping** that maps a bucket to a database/retention policy name.

```
Bucket (v2/v3) → DBRP Mapping → Database/Retention Policy (v1 compatibility)
                                        ↓
                                  InfluxQL Queries
```

### Setup Steps

#### Step 1: Create a Bucket (if you don't already have one)

Using the InfluxDB UI:
1. Navigate to **Load Data** → **Buckets**
2. Click **Create Bucket**
3. Name: `telegraf`
4. Retention Period: Set as needed (e.g., 30 days)

Using the CLI:
```bash
influx bucket create \
  --name telegraf \
  --org your-org \
  --retention 720h
```

#### Step 2: Create a DBRP Mapping

This is the **critical step** for InfluxQL support. The mapping creates a database/retention policy view of your bucket.

**Using the influx CLI** (Recommended):

To get your bucket ID:
```bash
# Query Bucket ID
influx bucket list --name telegraf
```

```bash
# Create DBRP mapping
influx v1 dbrp create \
  --bucket-id <your-bucket-id> \
  --db telegraf \
  --rp autogen \
  --default \
  --org your-org
```



#### Step 3: Verify DBRP Mapping

**Using the CLI**:
```bash
# List all DBRP mappings
influx v1 dbrp list

# Filter by database name
influx v1 dbrp list --db telegraf

# Filter by bucket ID
influx v1 dbrp list --bucket-id <your-bucket-id>
```

## Grafana Data Source Configuration

For InfluxDB 2.x/3.x with InfluxQL:

- **Type**: InfluxDB
- **Query Language**: InfluxQL
- **URL**: `http://localhost:8086` (or your cloud URL)
- **Database**: `telegraf` (the DBRP mapped database name)
- **HTTP Method**: GET
- **Custom HTTP Headers**:
  - **Header**: `Authorization`
  - **Value**: `Token YOUR_API_TOKEN`

## DBRP Mapping

### What is DBRP?

**DBRP (Database/Retention Policy) mapping** is a compatibility layer that allows InfluxDB 2.x/3.x/Cloud to support InfluxQL queries. It maps:

- **Bucket** (v2/v3 concept) → **Database** (v1 concept)
- **Bucket retention** → **Retention Policy** (v1 concept)

### Why is it Needed?

- InfluxDB 2.x+ natively uses Flux as the query language
- Grafana dashboards work better with InfluxQL
- DBRP mapping provides backward compatibility
- Allows existing v1.x queries to work with v2/v3

### Automatic vs Manual DBRP Mapping

#### Automatic Mapping

InfluxDB 2.x+ automatically creates DBRP mappings when:
- Upgrading from InfluxDB 1.x to 2.x
- Writing data using the v1 compatibility API (`/write`)

#### Manual Mapping

You must manually create DBRP mappings when:
- Creating new buckets in v2/v3/Cloud
- Using the v2 native API (`/api/v2/write`)
- Writing data with this monitoring tool (uses v2 API)

### DBRP Mapping Operations

#### Create a Mapping

```bash
influx v1 dbrp create \
  --bucket-id <bucket-id> \
  --db <database-name> \
  --rp <retention-policy-name> \
  --default \
  --org <org-name>
```

#### List Mappings

```bash
# List all
influx v1 dbrp list

# Filter by database
influx v1 dbrp list --db palo_alto_metrics

# Filter by bucket
influx v1 dbrp list --bucket-id <bucket-id>
```

#### Update a Mapping

```bash
influx v1 dbrp update \
  --id <dbrp-id> \
  --rp new_retention_policy \
  --default
```

#### Delete a Mapping

```bash
influx v1 dbrp delete --id <dbrp-id>
```


## Additional Resources

- [InfluxDB Cloud DBRP Documentation](https://docs.influxdata.com/influxdb/cloud/query-data/influxql/dbrp/)
- [InfluxQL Reference](https://docs.influxdata.com/influxdb/latest/query_language/spec/)
- [Grafana InfluxDB Data Source](https://grafana.com/docs/grafana/latest/datasources/influxdb/)
- [InfluxDB API Reference](https://docs.influxdata.com/influxdb/latest/api/)
