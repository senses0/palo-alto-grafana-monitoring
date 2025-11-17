# Testing Guide

This directory contains the test suite for the Palo Alto Grafana Monitoring project.

## Simplified Testing Approach

The testing framework has been simplified to **always use a real firewall** for testing. This removes the complexity of mock vs real firewall configuration and ensures all tests run against actual firewall hardware.

## Configuration

### Option 1: Environment Variables (Recommended)

Set these environment variables before running tests:

```bash
export PA_FIREWALL_HOST="your-firewall-ip-or-hostname"
export PA_FIREWALL_API_KEY="your-actual-api-key"
export PA_FIREWALL_PORT=443
export PA_FIREWALL_VERIFY_SSL=false
export PA_FIREWALL_TIMEOUT=30
export PA_FIREWALL_NAME="test-fw"
```

### Option 2: Configuration File

Create `tests/firewall_config_local.yaml` (this file is gitignored):

```yaml
# Simple Firewall Configuration - Always Real
firewall:
  host: "your-firewall-ip-or-hostname"
  port: 443
  api_key: "your-actual-api-key"
  verify_ssl: false
  timeout: 30
  firewall_name: "test-fw"
  description: "Test Firewall"
  location: "Test Environment"
```

## Running Tests

### Activate Virtual Environment

```bash
source venv/bin/activate
```

### Run All Tests

```bash
pytest
```

### Run Specific Test Categories

```bash
# Unit tests only
pytest -m unit

# Real firewall tests only
pytest -m real_firewall

# Integration tests only
pytest -m integration

# Slow tests only
pytest -m slow
```

### Run Specific Test Files

```bash
# Authentication tests
pytest tests/test_client.py::TestPaloAltoAuth -v

# Client tests
pytest tests/test_client.py::TestPaloAltoClientSingleFirewall -v

# All client tests
pytest tests/test_client.py -v
```

### Run with Coverage

```bash
pytest --cov=src --cov-report=html
```

## Test Structure

### Fixtures

- `firewall_config`: Provides firewall configuration
- `client`: Provides a configured PaloAltoClient instance
- `auth`: Provides a configured PaloAltoAuth instance
- `sample_*_data`: Provides sample data for testing

### Test Markers

- `@pytest.mark.unit`: Unit tests (no network calls)
- `@pytest.mark.real_firewall`: Tests that require real firewall
- `@pytest.mark.integration`: Integration tests
- `@pytest.mark.slow`: Slow running tests

## Security Notes

- **Never commit real API keys** to version control
- Use environment variables for sensitive data
- The `firewall_config_local.yaml` file is gitignored
- All tests run against real firewall hardware

## Troubleshooting

### Configuration Errors

If you see configuration errors:

1. Check that environment variables are set correctly
2. Verify the firewall is reachable
3. Ensure the API key is valid
4. Check firewall connectivity

### Test Failures

Common test failure reasons:

1. **Network connectivity**: Firewall is not reachable
2. **Authentication**: Invalid API key
3. **SSL issues**: Certificate validation problems
4. **Timeout**: Firewall is slow to respond

### Debugging

To debug test issues:

```bash
# Run with verbose output
pytest -v

# Run with print statements
pytest -s

# Run specific failing test
pytest tests/test_client.py::TestPaloAltoAuth::test_real_authentication -v -s
```

## Migration from Mock Testing

If you were previously using mock testing:

1. **Remove mock fixtures**: No longer needed
2. **Update test imports**: Remove mock-related imports
3. **Simplify test setup**: Use the simplified fixtures
4. **Add real firewall tests**: Use `@pytest.mark.real_firewall`

## Benefits of Simplified Testing

- ✅ **Simplified configuration**: No mock/real complexity
- ✅ **Real testing**: All tests run against actual firewall
- ✅ **Cleaner code**: Single fixture per component
- ✅ **Easier maintenance**: Less configuration to manage
- ✅ **Clear intent**: Tests obviously test real functionality
- ✅ **Better coverage**: Tests actual firewall behavior
