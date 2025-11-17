import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List

class Settings:
    """Configuration management for Palo Alto stats application."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or os.getenv('PA_CONFIG_FILE', 'config/config.yaml')
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file and environment variables."""
        config = {}
        
        # Load from YAML file if exists
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f) or {}
        
        # Handle firewall configuration (support both old and new formats)
        firewall_config = self._load_firewall_config(config)
        
        # Override with environment variables
        config.update({
            'firewalls': firewall_config,
            'logging': {
                'level': os.getenv('LOG_LEVEL', config.get('logging', {}).get('level', 'INFO')),
                'file': os.getenv('LOG_FILE', config.get('logging', {}).get('file', 'logs/pa_stats.log')),
                'max_bytes': int(os.getenv('LOG_MAX_BYTES', config.get('logging', {}).get('max_bytes', 10485760))),
                'backup_count': int(os.getenv('LOG_BACKUP_COUNT', config.get('logging', {}).get('backup_count', 5))),
            },
            'query': {
                'max_retries': int(os.getenv('PA_MAX_RETRIES', config.get('query', {}).get('max_retries', 3))),
                'retry_delay': int(os.getenv('PA_RETRY_DELAY', config.get('query', {}).get('retry_delay', 5))),
            }
        })
        
        return config
    
    def _load_firewall_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Load firewall configuration supporting both old and new formats."""
        firewalls = {}
        
        # Check for new multi-firewall format
        if 'firewalls' in config:
            firewalls = config['firewalls']
            # Ensure routing_mode is set for each firewall
            for firewall_name, firewall_config in firewalls.items():
                if 'routing_mode' not in firewall_config:
                    firewall_config['routing_mode'] = 'auto'  # Default to auto-detection
        # Check for old single firewall format (backward compatibility)
        elif 'firewall' in config:
            # Convert old format to new format
            old_firewall = config['firewall']
            firewalls['default'] = {
                'host': old_firewall.get('host'),
                'port': old_firewall.get('port', 443),
                'api_key': old_firewall.get('api_key'),
                'verify_ssl': old_firewall.get('verify_ssl', True),
                'timeout': old_firewall.get('timeout', 30),
                'description': 'Legacy firewall configuration',
                'location': 'Unknown'
            }
        
        # Override with environment variables if they exist
        # Environment variables will override the first firewall in the list
        if firewalls:
            first_firewall_key = list(firewalls.keys())[0]
            first_firewall = firewalls[first_firewall_key]
            
            # Override with environment variables
            first_firewall.update({
                'host': os.getenv('PA_HOST', first_firewall.get('host')),
                'port': int(os.getenv('PA_PORT', first_firewall.get('port', 443))),
                'api_key': os.getenv('PA_API_KEY', first_firewall.get('api_key')),
                'verify_ssl': self._parse_bool(os.getenv('PA_VERIFY_SSL', first_firewall.get('verify_ssl', True))),
                'timeout': int(os.getenv('PA_TIMEOUT', first_firewall.get('timeout', 30))),
            })
            
            firewalls[first_firewall_key] = first_firewall
        
        return firewalls
    
    def get_firewalls(self) -> Dict[str, Any]:
        """Get all configured firewalls."""
        return self.config.get('firewalls', {})
    
    def get_firewall(self, name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get a specific firewall configuration by name."""
        firewalls = self.get_firewalls()
        
        if not firewalls:
            return None
        
        # If no name specified, use default or first available
        if not name:
            default_name = self.config.get('default_firewall')
            if default_name and default_name in firewalls:
                return firewalls[default_name]
            # Return first firewall if no default specified
            return firewalls[list(firewalls.keys())[0]]
        
        return firewalls.get(name)
    
    def get_firewall_names(self) -> List[str]:
        """Get list of all configured firewall names."""
        return list(self.get_firewalls().keys())
    
    def _parse_bool(self, value: Any) -> bool:
        """Parse boolean value from various formats."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        if isinstance(value, (int, float)):
            return bool(value)
        return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value

# Global settings instance
settings = Settings()