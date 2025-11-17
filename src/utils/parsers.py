"""Data parsing utilities for Palo Alto Networks API responses.

This module provides shared parsing functions that can be used across different
stats modules to handle common data parsing tasks.

Usage Examples:
    from ..utils.parsers import parse_json_fields, parse_data_types
    
    # In a stats module method:
    response = client.execute_operational_command('<show><some-command></some-command></show>')
    result = response.get('result', {})
    parsed_data = parse_json_fields(result)
    converted_data = parse_data_types(parsed_data)
"""

from typing import Dict, Any, Union
import json
from .logger import get_logger

logger = get_logger(__name__)


def parse_json_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse JSON fields in a dictionary that contain JSON strings.
    
    This function recursively processes a dictionary and parses any 'json' fields
    that contain JSON strings, merging the parsed data into the root level.
    
    Args:
        data: Dictionary containing potentially nested JSON string fields
        
    Returns:
        Dictionary with parsed JSON fields merged into the root level
        
    Example:
        >>> data = {'name': 'test', 'json': '{"key": "value"}'}
        >>> parse_json_fields(data)
        {'name': 'test', 'key': 'value'}
    """
    parsed_data = {}
    for key, value in data.items():
        if isinstance(value, dict):
            # Recursively parse nested dictionaries
            parsed_data[key] = parse_json_fields(value)
        elif key == 'json' and isinstance(value, str):
            # Parse the 'json' field and merge it into the root level
            try:
                json_data = json.loads(value)
                if isinstance(json_data, dict):
                    # Merge the parsed JSON data into the root level
                    parsed_data.update(json_data)
                else:
                    # If it's not a dict, keep it as is
                    parsed_data[key] = json_data
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON string: {e}")
                parsed_data[key] = value
        else:
            parsed_data[key] = value
    return parsed_data


def parse_data_types(data: Union[Dict[str, Any], list, Any]) -> Union[Dict[str, Any], list, Any]:
    """
    Convert string numbers to integers and string booleans to Python booleans.
    
    This function recursively processes dictionaries and lists, converting:
    - String numbers (e.g., "123", "0", "-456") to integers
    - String booleans (e.g., "True", "False", "true", "false") to Python booleans
    - Any values that cannot be converted remain in their original data type
    
    Args:
        data: Data structure (dict, list, or primitive value) to process
        
    Returns:
        Data structure with converted types where possible
        
    Example:
        >>> data = {
        ...     'count': '123',
        ...     'enabled': 'True',
        ...     'nested': {'value': '456', 'active': 'false'},
        ...     'list': ['789', 'True', 'invalid']
        ... }
        >>> parse_data_types(data)
        {
            'count': 123,
            'enabled': True,
            'nested': {'value': 456, 'active': False},
            'list': [789, True, 'invalid']
        }
    """
    if isinstance(data, dict):
        return {key: parse_data_types(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [parse_data_types(item) for item in data]
    elif isinstance(data, str):
        # Try to convert string to integer
        if data.isdigit() or (data.startswith('-') and data[1:].isdigit()):
            try:
                return int(data)
            except ValueError:
                pass
        
        # Try to convert string to float
        try:
            return float(data)
        except ValueError:
            pass
        
        # Try to convert string to boolean
        if data.lower() in ('true', 'false'):
            return data.lower() == 'true'
        
        # Return original string if no conversion possible
        return data
    else:
        # Return original value for non-string types
        return data
