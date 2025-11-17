# Documentation

This directory contains comprehensive documentation for the Palo Alto Grafana Monitoring project.

## 📚 Available Documentation

### Architecture Documentation
- **[architecture.md](architecture.md)** - Complete architecture documentation with detailed diagrams
  - System architecture overview
  - Component relationships
  - Data flow diagrams
  - Deployment patterns
  - Module interactions
  - Performance characteristics
  - Future enhancements

- **[diagrams-quick-reference.md](diagrams-quick-reference.md)** - Quick reference diagrams
  - Quick start workflows
  - Common use cases
  - Deployment patterns
  - Troubleshooting flowcharts
  - Scaling guidelines

### InfluxDB Integration Documentation
- **[influxdb_configuration.md](influxdb_configuration.md)** - Complete InfluxDB configuration guide
  - InfluxDB 1.x vs 2.x/3.x/Cloud differences
  - DBRP (Database/Retention Policy) mapping setup
  - Grafana integration and data source configuration

- **[influxdb_measurements.md](influxdb_measurements.md)** - Complete measurement catalog
  - 43 measurements covering all modules
  - Detailed tags and fields reference
  - Data types, units, and descriptions
  - Schema documentation for dashboard creation


## 📝 Documentation Standards

### Updating Documentation

When modifying the project, update relevant diagrams:

| Change Type | Diagrams to Update |
|-------------|-------------------|
| New module/component | Component Architecture, Module Interactions |
| New stats collector | Statistics Coverage, Data Flow |
| New output format | System Architecture, Data Flow |
| Configuration change | Configuration Structure |
| API change | Network Communication, Sequence Diagrams |
| Deployment method | Deployment Architecture, Deployment Patterns |


## 🔄 Maintenance

### When to Update
Update diagrams when:
- Adding new features or modules
- Changing data flow or architecture
- Modifying API interactions
- Adding deployment options
- Discovering new use cases
- Fixing inaccuracies


## 📖 Additional Resources

### Project Documentation
- [Main README](../README.md) - Project overview and usage
- [Configuration Example](../config/config.yaml.example) - Configuration reference
- [Testing Documentation](../tests/README.md) - Test suite documentation

### External References
- [Palo Alto Networks API](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-panorama-api) - Firewall API docs
- [InfluxDB Line Protocol](https://docs.influxdata.com/influxdb/v2.7/reference/syntax/line-protocol/) - Time-series format
- [InfluxDB DBRP Mapping](https://docs.influxdata.com/influxdb/cloud/query-data/influxql/dbrp/) - Official DBRP documentation

### Related Projects
- [panos-python](https://github.com/PaloAltoNetworks/pan-os-python) - Official Python SDK
- [pandevice](https://github.com/PaloAltoNetworks/pandevice) - Alternative Python library

## 💡 Tips for Using This Documentation

### Quick Tips
1. **Start with the quick reference** - Get familiar with basic concepts
2. **Use GitHub's table of contents** - Navigate long documents easily
3. **Search within pages** - Use Ctrl+F / Cmd+F to find specific topics
4. **Follow cross-references** - Links connect related concepts
5. **Check examples** - Real-world usage patterns included

### Best Practices
- Keep documentation open while coding
- Reference diagrams during code reviews
- Update docs with code changes
- Use diagrams in presentations and documentation
- Export diagrams for offline use
