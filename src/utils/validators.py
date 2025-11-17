"""Input validation utilities."""

import re
import ipaddress
from typing import Any, Optional, Union

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_hostname(hostname: str) -> bool:
    """Validate hostname format."""
    if not hostname or len(hostname) > 253:
        return False
    
    # Remove trailing dot
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Check each label
    labels = hostname.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return False
    
    return True

def validate_port(port: Union[str, int]) -> bool:
    """Validate port number."""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def validate_api_key(api_key: str) -> bool:
    """Validate API key format."""
    if not api_key:
        return False
    
    # Basic validation - API keys are typically alphanumeric
    # and have specific length patterns
    if len(api_key) < 10:
        return False
    
    # Check for basic alphanumeric pattern with underscores
    if not re.match(r'^[a-zA-Z0-9+/=_]+$', api_key):
        return False
    
    return True

def validate_timeout(timeout: Union[str, int]) -> bool:
    """Validate timeout value."""
    try:
        timeout_val = int(timeout)
        return 1 <= timeout_val <= 300  # 1 second to 5 minutes
    except (ValueError, TypeError):
        return False

def sanitize_command(command: str) -> Optional[str]:
    """Sanitize operational command to prevent injection."""
    if not command:
        return None
    
    # Remove any potentially dangerous characters
    # Allow only XML tags and basic characters
    allowed_pattern = r'^[a-zA-Z0-9\s<>/\-_\.="\'"]+$'
    
    if not re.match(allowed_pattern, command):
        return None
    
    # Ensure command starts and ends with proper XML tags
    command = command.strip()
    if not (command.startswith('<') and command.endswith('>')):
        return None
    
    return command

def validate_interface_name(interface: str) -> bool:
    """Validate interface name format."""
    if not interface:
        return False
    
    # Common interface naming patterns
    patterns = [
        r'^ethernet\d+/\d+$',  # ethernet1/1
        r'^ae\d+$',            # ae1
        r'^tunnel\.\d+$',      # tunnel.1
        r'^loopback\.\d+$',    # loopback.1
        r'^vlan\.\d+$',        # vlan.100
        r'^all$'               # Special case for all interfaces
    ]
    
    return any(re.match(pattern, interface, re.IGNORECASE) for pattern in patterns)

def validate_xml_command(command: str) -> bool:
    """Validate XML command structure."""
    if not command:
        return False
    
    try:
        # Basic XML validation
        import xml.etree.ElementTree as ET
        ET.fromstring(command)
        return True
    except ET.ParseError:
        return False

def validate_query_parameters(params: dict) -> tuple[bool, list[str]]:
    """Validate query parameters."""
    errors = []
    
    if not isinstance(params, dict):
        errors.append("Parameters must be a dictionary")
        return False, errors
    
    # Check for required parameters
    if 'type' not in params:
        errors.append("Query type is required")
    elif params['type'] not in ['op', 'config', 'commit']:
        errors.append("Invalid query type. Must be 'op', 'config', or 'commit'")
    
    # Validate command if present
    if 'cmd' in params:
        if not validate_xml_command(params['cmd']):
            errors.append("Invalid XML command format")
    
    return len(errors) == 0, errors

def validate_response_format(format_type: str) -> bool:
    """Validate response format type."""
    valid_formats = ['json', 'xml', 'table', 'csv']
    return format_type.lower() in valid_formats

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations."""
    if not filename:
        return "output"
    
    # Remove or replace dangerous characters
    import re
    # Keep only alphanumeric, dash, underscore, dot
    sanitized = re.sub(r'[^a-zA-Z0-9\-_\.]', '_', filename)
    
    # Remove leading/trailing dots and underscores
    sanitized = sanitized.strip('._')
    
    # Ensure it's not empty after sanitization
    if not sanitized:
        sanitized = "output"
    
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    
    return sanitized

def validate_log_level(level: str) -> bool:
    """Validate logging level."""
    valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    return level.upper() in valid_levels

def validate_file_path(file_path: str) -> bool:
    """Validate file path for security."""
    if not file_path:
        return False
    
    import os
    # Prevent directory traversal attacks
    if '..' in file_path or file_path.startswith('/'):
        return False
    
    # Check if path is within allowed directories
    allowed_dirs = ['logs', 'config', 'output', 'temp']
    path_parts = file_path.split(os.sep)
    
    if path_parts[0] not in allowed_dirs:
        return False
    
    return True

class ConfigValidator:
    """Configuration validator class."""
    
    @staticmethod
    def validate_firewall_config(config: dict) -> tuple[bool, list[str]]:
        """Validate firewall configuration."""
        errors = []
        
        # Check required fields
        if 'host' not in config or not config['host']:
            errors.append("Firewall host is required")
        elif not (validate_ip_address(config['host']) or validate_hostname(config['host'])):
            errors.append("Invalid firewall host format")
        
        if 'api_key' not in config or not config['api_key']:
            errors.append("API key is required")
        elif not validate_api_key(config['api_key']):
            errors.append("Invalid API key format")
        
        # Check optional fields
        if 'port' in config and not validate_port(config['port']):
            errors.append("Invalid port number")
        
        if 'timeout' in config and not validate_timeout(config['timeout']):
            errors.append("Invalid timeout value")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_logging_config(config: dict) -> tuple[bool, list[str]]:
        """Validate logging configuration."""
        errors = []
        
        # Check log level
        if 'level' in config:
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if config['level'].upper() not in valid_levels:
                errors.append(f"Invalid log level. Must be one of: {', '.join(valid_levels)}")
        
        # Check max_bytes
        if 'max_bytes' in config:
            try:
                max_bytes = int(config['max_bytes'])
                if max_bytes <= 0:
                    errors.append("max_bytes must be positive")
            except (ValueError, TypeError):
                errors.append("max_bytes must be a number")
        
        # Check backup_count
        if 'backup_count' in config:
            try:
                backup_count = int(config['backup_count'])
                if backup_count < 0:
                    errors.append("backup_count must be non-negative")
            except (ValueError, TypeError):
                errors.append("backup_count must be a number")
        
        return len(errors) == 0, errors

class SecurityValidator:
    """Security-focused validation class."""
    
    @staticmethod
    def validate_input_safety(user_input: str) -> bool:
        """Validate user input for potential security issues."""
        if not user_input:
            return True
        
        # Check for common injection patterns
        dangerous_patterns = [
            r'<script',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'\.\./',
            r'\\\.\\\.\\',
        ]
        
        import re
        for pattern in dangerous_patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                return False
        
        return True
    
    @staticmethod
    def validate_api_endpoint(endpoint: str) -> bool:
        """Validate API endpoint path."""
        if not endpoint:
            return False
        
        # Ensure endpoint starts with /api/
        if not endpoint.startswith('/api/'):
            return False
        
        # Check for dangerous patterns
        dangerous_chars = ['..', '<', '>', '"', "'", '&', '|', ';']
        return not any(char in endpoint for char in dangerous_chars)
    
    @staticmethod
    def validate_operational_command_safety(command: str) -> bool:
        """Validate that operational command is read-only."""
        if not command:
            return False
        
        # Commands that should NOT be allowed (write operations)
        forbidden_patterns = [
            r'<commit',
            r'<load',
            r'<save',
            r'<move',
            r'<clone',
            r'<rename',
            r'<delete',
            r'<set',
            r'<edit',
            r'action\s*=\s*["\'](?:set|edit|delete|move|rename)',
            r'type\s*=\s*["\'](?:commit|config)'
        ]
        
        import re
        for pattern in forbidden_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False
        
        # Must be a show command for read-only access
        if not re.search(r'<show', command, re.IGNORECASE):
            return False
        
        return True

class DataValidator:
    """Data validation and sanitization utilities."""
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format."""
        return validate_ip_address(ip)
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """Validate port number."""
        return validate_port(port)
    
    @staticmethod
    def validate_api_key(api_key: str) -> bool:
        """Validate API key format."""
        return validate_api_key(api_key)
    
    @staticmethod
    def validate_timestamp(timestamp: str) -> bool:
        """Validate timestamp format."""
        if not timestamp:
            return False
        
        try:
            from datetime import datetime
            # Handle various timestamp formats
            timestamp_clean = timestamp.replace('Z', '+00:00')
            datetime.fromisoformat(timestamp_clean)
            return True
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def validate_response_data(data: dict) -> tuple[bool, list[str]]:
        """Validate response data structure."""
        errors = []
        
        if not isinstance(data, dict):
            errors.append("Response data must be a dictionary")
            return False, errors
        
        # Check for required fields
        required_fields = ['success']
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")
        
        # Validate success field
        if 'success' in data and not isinstance(data['success'], bool):
            errors.append("Success field must be a boolean")
        
        # Validate timestamp if present
        if 'timestamp' in data:
            if not DataValidator.validate_timestamp(data['timestamp']):
                errors.append("Invalid timestamp format")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_statistics_data(data: dict) -> tuple[bool, list[str]]:
        """Validate statistics data structure."""
        errors = []
        
        if not isinstance(data, dict):
            errors.append("Statistics data must be a dictionary")
            return False, errors
        
        # Check for required fields in statistics
        required_fields = ['timestamp']
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")
        
        # Validate timestamp format if present
        if 'timestamp' in data:
            if not DataValidator.validate_timestamp(data['timestamp']):
                errors.append("Invalid timestamp format")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def sanitize_statistics_output(data: dict) -> dict:
        """Sanitize statistics data for safe output."""
        if not isinstance(data, dict):
            return {}
        
        sanitized = {}
        
        for key, value in data.items():
            # Sanitize key
            safe_key = re.sub(r'[^a-zA-Z0-9_\-]', '_', str(key))
            
            # Sanitize value based on type
            if isinstance(value, dict):
                sanitized[safe_key] = DataValidator.sanitize_statistics_output(value)
            elif isinstance(value, list):
                sanitized[safe_key] = [
                    DataValidator.sanitize_statistics_output(item) if isinstance(item, dict) else str(item)
                    for item in value
                ]
            elif isinstance(value, (str, int, float, bool)):
                sanitized[safe_key] = value
            else:
                sanitized[safe_key] = str(value)
        
        return sanitized
    
    @staticmethod
    def validate_numeric_range(value: any, min_val: float = None, max_val: float = None) -> bool:
        """Validate numeric value within range."""
        try:
            num_value = float(value)
            
            if min_val is not None and num_value < min_val:
                return False
            
            if max_val is not None and num_value > max_val:
                return False
            
            return True
        except (ValueError, TypeError):
            return False

# Utility functions for common validation tasks
def is_valid_ip_or_hostname(address: str) -> bool:
    """Check if address is valid IP or hostname."""
    return validate_ip_address(address) or validate_hostname(address)

def is_safe_for_logging(message: str) -> bool:
    """Check if message is safe for logging (no sensitive data)."""
    if not message:
        return True
    
    # Check for patterns that might contain sensitive information
    sensitive_patterns = [
        r'password\s*[:=]\s*\S+',
        r'api[_-]?key\s*[:=]\s*\S+',
        r'token\s*[:=]\s*\S+',
        r'secret\s*[:=]\s*\S+',
        r'auth\s*[:=]\s*\S+',
    ]
    
    import re
    for pattern in sensitive_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return False
    
    return True

def mask_sensitive_data(data: str) -> str:
    """Mask sensitive data in strings for safe logging."""
    if not data:
        return data
    
    import re
    
    # Mask API keys (keep first 4 and last 4 characters)
    data = re.sub(
        r'(api[_-]?key\s*[:=]\s*)(\S{4})(\S+)(\S{4})',
        r'\1\2***\4',
        data,
        flags=re.IGNORECASE
    )
    
    # Mask passwords completely
    data = re.sub(
        r'(password\s*[:=]\s*)(\S+)',
        r'\1***',
        data,
        flags=re.IGNORECASE
    )
    
    # Mask tokens (keep first 4 characters)
    data = re.sub(
        r'(token\s*[:=]\s*)(\S{4})(\S+)',
        r'\1\2***',
        data,
        flags=re.IGNORECASE
    )
    
    return data