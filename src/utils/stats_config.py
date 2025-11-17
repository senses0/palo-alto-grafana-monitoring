"""Stats collection configuration management."""

from typing import Dict, Any, Optional
import sys
import os

# Add the project root to the path to import config.settings
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import Settings


class StatsCollectionConfig:
    """Configuration helper for stat collection control."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.stats_config = settings.config.get('stats_collection', {})
    
    def is_module_enabled(self, module_name: str, firewall_name: str = None) -> bool:
        """Check if a module is enabled for collection.
        
        Args:
            module_name: Name of the module (e.g., 'system', 'network_interfaces')
            firewall_name: Optional firewall name for per-firewall overrides
            
        Returns:
            bool: True if module is enabled, False otherwise
        """
        # Check firewall-specific override first
        if firewall_name:
            firewall_overrides = self.stats_config.get('firewall_overrides', {})
            if firewall_name in firewall_overrides:
                firewall_config = firewall_overrides[firewall_name]
                if module_name in firewall_config:
                    # If module is explicitly disabled for this firewall, return false
                    if not firewall_config[module_name].get('enabled', True):
                        return False
                    # If module is enabled, continue to collection-level checks
        
        # Check global module configuration
        modules_config = self.stats_config.get('modules', {})
        if module_name in modules_config:
            return modules_config[module_name].get('enabled', True)
        
        # Default to enabled if not specified
        return True
    
    def is_collection_enabled(self, module_name: str, collection_name: str, firewall_name: str = None) -> bool:
        """Check if a specific collection within a module is enabled.
        
        Args:
            module_name: Name of the module (e.g., 'system', 'network_interfaces')
            collection_name: Name of the collection (e.g., 'system_info', 'interface_counters')
            firewall_name: Optional firewall name for per-firewall overrides
            
        Returns:
            bool: True if collection is enabled, False otherwise
        """
        # First check if the module itself is enabled
        if not self.is_module_enabled(module_name, firewall_name):
            return False
        
        # Check firewall-specific override first
        if firewall_name:
            firewall_overrides = self.stats_config.get('firewall_overrides', {})
            if firewall_name in firewall_overrides:
                firewall_config = firewall_overrides[firewall_name]
                if module_name in firewall_config:
                    collections = firewall_config[module_name].get('collections', {})
                    if collection_name in collections:
                        return collections[collection_name]
        
        # Check global module configuration
        modules_config = self.stats_config.get('modules', {})
        if module_name in modules_config:
            collections = modules_config[module_name].get('collections', {})
            if collection_name in collections:
                return collections[collection_name]
        
        # Default to enabled if not specified
        return True
    
    def get_enabled_modules(self) -> list:
        """Get list of globally enabled modules.
        
        Returns:
            list: List of enabled module names
        """
        return self.stats_config.get('enabled_modules', [])
    
    def get_module_collections(self, module_name: str) -> Dict[str, bool]:
        """Get all collections for a module with their enabled status.
        
        Args:
            module_name: Name of the module
            
        Returns:
            Dict[str, bool]: Dictionary mapping collection names to enabled status
        """
        modules_config = self.stats_config.get('modules', {})
        if module_name in modules_config:
            return modules_config[module_name].get('collections', {})
        return {}
    
    def get_firewall_overrides(self, firewall_name: str) -> Dict[str, Any]:
        """Get firewall-specific overrides for a given firewall.
        
        Args:
            firewall_name: Name of the firewall
            
        Returns:
            Dict[str, Any]: Firewall-specific configuration overrides
        """
        firewall_overrides = self.stats_config.get('firewall_overrides', {})
        return firewall_overrides.get(firewall_name, {})
