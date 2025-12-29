"""Main client for Palo Alto Networks API interactions (Read-Only)."""

import requests
import time
import urllib3
import json
from typing import Dict, Any, Optional, List, Callable
from urllib.parse import urljoin
from pathlib import Path
from datetime import datetime, timedelta, timezone
import xml.etree.ElementTree as ET
import xml.parsers.expat
import xmltodict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .auth import PaloAltoAuth
from .exceptions import *
from ..utils.logger import get_logger, update_logger_firewall_context
from config.settings import settings

logger = get_logger(__name__)

class PaloAltoClient:
    """Read-only client for querying Palo Alto Networks firewall statistics with unified multi-firewall support."""
    
    def __init__(self, firewall_name: str = None, host: str = None, port: int = None, verify_ssl: bool = None, 
                 timeout: int = None, max_retries: int = None, retry_delay: int = None, max_workers: int = 5):
        """
        Initialize the Palo Alto client with unified multi-firewall support.
        
        Args:
            firewall_name: Specific firewall name to target (if None, operates on all firewalls)
            host: Override host for specific firewall
            port: Override port for specific firewall
            verify_ssl: Override SSL verification for specific firewall
            timeout: Override timeout for specific firewall
            max_retries: Override max retries for specific firewall
            retry_delay: Override retry delay for specific firewall
            max_workers: Maximum concurrent workers for multi-firewall operations
        """
        self.max_workers = max_workers
        self.firewall_name = firewall_name
        
        # If a specific firewall is requested, initialize single firewall mode
        if firewall_name:
            self._initialize_single_firewall(firewall_name, host, port, verify_ssl, timeout, max_retries, retry_delay)
        else:
            # Multi-firewall mode - initialize all configured firewalls
            self._initialize_multi_firewall()
    
    def _initialize_single_firewall(self, firewall_name: str, host: str = None, port: int = None, 
                                  verify_ssl: bool = None, timeout: int = None, max_retries: int = None, 
                                  retry_delay: int = None):
        """Initialize client for a single specific firewall."""
        # Get firewall configuration
        firewall_config = settings.get_firewall(firewall_name)
        if not firewall_config:
            raise ConfigurationError(f"Firewall '{firewall_name}' not found in configuration")
        
        # Use provided values or fall back to firewall config
        self.host = host or firewall_config.get('host')
        self.port = port or firewall_config.get('port', 443)
        self.verify_ssl = verify_ssl if verify_ssl is not None else firewall_config.get('verify_ssl', False)
        self.timeout = timeout or firewall_config.get('timeout', 30)
        self.max_retries = max_retries or settings.get('query.max_retries', 3)
        self.retry_delay = retry_delay or settings.get('query.retry_delay', 5)
        
        # Store firewall metadata
        self.description = firewall_config.get('description', 'Unknown')
        self.location = firewall_config.get('location', 'Unknown')
        
        if not self.host:
            raise ConfigurationError("Firewall host must be specified")
        
        # Update logger with firewall context
        update_logger_firewall_context(logger, self.firewall_name, self.host)
        
        self.auth = PaloAltoAuth(self.host, self.port, self.verify_ssl, self.timeout, self.firewall_name)
        self.base_url = f"https://{self.host}:{self.port}"
        
        # Disable SSL warnings if verification is disabled
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL verification is disabled - this is not recommended for production use")
        
        # Initialize authentication
        self._initialize_auth(firewall_config)
        
        # Set single firewall mode
        self.multi_firewall_mode = False
        self.firewalls = {firewall_name: self}
        
        # Initialize hostname cache
        self._initialize_hostname_cache()
    
    def _initialize_multi_firewall(self):
        """Initialize client for multi-firewall operations."""
        self.multi_firewall_mode = True
        self.firewalls = {}
        
        # Get all configured firewalls and enabled firewalls
        all_firewall_configs = settings.get_firewalls()
        enabled_firewall_configs = settings.get_enabled_firewalls()
        disabled_firewall_configs = settings.get_disabled_firewalls()
        
        if not all_firewall_configs:
            raise ConfigurationError("No firewall configurations found")
        
        if not enabled_firewall_configs:
            raise ConfigurationError("No enabled firewall configurations found. All firewalls are disabled.")
        
        # Log disabled firewalls
        if disabled_firewall_configs:
            disabled_names = list(disabled_firewall_configs.keys())
            logger.info(f"Skipping {len(disabled_names)} disabled firewall(s): {', '.join(disabled_names)}")
        
        logger.info(f"Initializing multi-firewall client for {len(enabled_firewall_configs)} enabled firewall(s) out of {len(all_firewall_configs)} configured")
        
        # Initialize individual clients for each enabled firewall only
        for name, config in enabled_firewall_configs.items():
            try:
                # Create individual client instance
                individual_client = PaloAltoClient(firewall_name=name)
                self.firewalls[name] = individual_client
                logger.debug(f"Successfully initialized client for firewall: {name}")
            except Exception as e:
                logger.error(f"Failed to initialize client for firewall '{name}': {e}")
                continue
        
        if not self.firewalls:
            raise ConfigurationError("No firewalls could be initialized")
        
        # Reset logger context to generic for multi-firewall summary message
        update_logger_firewall_context(logger, "multi-firewall", "all")
        logger.info(f"Successfully initialized {len(self.firewalls)} out of {len(enabled_firewall_configs)} enabled firewall clients")
        
        # Set default values from first firewall for backward compatibility
        first_firewall = next(iter(self.firewalls.values()))
        self.host = first_firewall.host
        self.port = first_firewall.port
        self.verify_ssl = first_firewall.verify_ssl
        self.timeout = first_firewall.timeout
        self.max_retries = first_firewall.max_retries
        self.retry_delay = first_firewall.retry_delay
        self.auth = first_firewall.auth
        self.base_url = first_firewall.base_url
        
        # Initialize hostname cache (shared across all firewalls in multi-firewall mode)
        self._initialize_hostname_cache()
    
    def _initialize_auth(self, firewall_config: Dict[str, Any]):
        """Initialize authentication using API key."""
        api_key = firewall_config.get('api_key')
        
        if not api_key:
            raise ConfigurationError("API key is required for authentication")
        
        self.auth.set_api_key(api_key)
        logger.info(f"Using API key for authentication to {self.firewall_name} ({self.host})")
        
        # Test authentication
        if not self.auth.test_authentication():
            raise AuthenticationError(f"API key authentication test failed for {self.firewall_name}")
    
    # ========================================
    # Hostname Cache Methods
    # ========================================
    
    def _initialize_hostname_cache(self):
        """Initialize hostname cache from settings and load from disk if available."""
        # Get cache configuration
        self.hostname_cache_enabled = settings.get('hostname_cache.enabled', True)
        self.hostname_cache_ttl_hours = settings.get('hostname_cache.ttl_hours', 6)
        self.hostname_cache_file = Path(settings.get('hostname_cache.cache_file', 'config/hostname_cache.json'))
        
        # Initialize empty cache
        self.hostname_cache = {}
        
        # Load cache from disk if enabled
        if self.hostname_cache_enabled:
            self._load_hostname_cache()
            logger.debug(f"Hostname cache initialized with {len(self.hostname_cache)} entries, TTL={self.hostname_cache_ttl_hours}h")
    
    def _load_hostname_cache(self) -> Dict[str, Any]:
        """Load hostname cache from disk."""
        try:
            if self.hostname_cache_file.exists():
                with open(self.hostname_cache_file, 'r') as f:
                    self.hostname_cache = json.load(f)
                logger.debug(f"Loaded hostname cache from {self.hostname_cache_file}")
            else:
                logger.debug(f"No existing hostname cache file found at {self.hostname_cache_file}")
                self.hostname_cache = {}
        except Exception as e:
            logger.warning(f"Failed to load hostname cache: {e}. Starting with empty cache.")
            self.hostname_cache = {}
    
    def _save_hostname_cache(self):
        """Persist hostname cache to disk."""
        if not self.hostname_cache_enabled:
            return
        
        try:
            # Ensure directory exists
            self.hostname_cache_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.hostname_cache_file, 'w') as f:
                json.dump(self.hostname_cache, f, indent=2)
            logger.debug(f"Saved hostname cache to {self.hostname_cache_file}")
        except Exception as e:
            logger.warning(f"Failed to save hostname cache: {e}")
    
    def _is_cache_entry_valid(self, firewall_name: str) -> bool:
        """Check if a cache entry exists and is not expired."""
        if firewall_name not in self.hostname_cache:
            return False
        
        entry = self.hostname_cache[firewall_name]
        if 'expires_at' not in entry:
            return False
        
        try:
            expires_at = datetime.fromisoformat(entry['expires_at'].replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            return now < expires_at
        except Exception as e:
            logger.debug(f"Error checking cache expiration for {firewall_name}: {e}")
            return False
    
    def _refresh_hostname_cache(self, firewall_name: str, client: 'PaloAltoClient') -> Optional[str]:
        """
        Query and update hostname for a specific firewall.
        
        Args:
            firewall_name: Config name of the firewall
            client: PaloAltoClient instance to query
            
        Returns:
            Actual hostname from system info, or None if query failed
        """
        try:
            # Query system info to get actual hostname
            system_info = client.execute_operational_command('<show><system><info></info></system></show>')
            system_data = system_info.get('result', {})
            
            if 'system' in system_data and 'hostname' in system_data['system']:
                hostname = system_data['system']['hostname']
                
                # Update cache with new entry
                now = datetime.now(timezone.utc)
                expires_at = now + timedelta(hours=self.hostname_cache_ttl_hours)
                
                self.hostname_cache[firewall_name] = {
                    'hostname': hostname,
                    'cached_at': now.isoformat(),
                    'expires_at': expires_at.isoformat()
                }
                
                # Save cache to disk
                self._save_hostname_cache()
                
                logger.debug(f"Refreshed hostname cache for {firewall_name}: {hostname} (expires: {expires_at})")
                return hostname
            else:
                logger.warning(f"No hostname found in system info for {firewall_name}")
                return None
                
        except Exception as e:
            logger.warning(f"Failed to refresh hostname cache for {firewall_name}: {e}")
            return None
    
    def get_hostname(self, firewall_name: str) -> str:
        """
        Get actual hostname for a firewall (from cache or fresh query).
        
        This method returns the actual firewall hostname (from system info) rather than
        the config file name. It uses a cache with configurable TTL to avoid redundant queries.
        
        Args:
            firewall_name: Config name of the firewall
            
        Returns:
            Actual hostname from firewall system info, or config name if unavailable
        """
        # If cache is disabled, return firewall config name
        if not self.hostname_cache_enabled:
            return firewall_name
        
        # Check if we have a valid cached entry
        if self._is_cache_entry_valid(firewall_name):
            hostname = self.hostname_cache[firewall_name].get('hostname')
            if hostname:
                logger.debug(f"Using cached hostname for {firewall_name}: {hostname}")
                return hostname
        
        # Cache miss or expired - need to refresh
        logger.debug(f"Hostname cache miss/expired for {firewall_name}, refreshing...")
        
        # Get the appropriate client
        if self.multi_firewall_mode:
            client = self.firewalls.get(firewall_name)
            if not client:
                logger.warning(f"No client found for firewall {firewall_name}")
                return firewall_name
        else:
            client = self
        
        # Refresh cache
        hostname = self._refresh_hostname_cache(firewall_name, client)
        
        # Return hostname if successful, otherwise fall back to firewall config name
        return hostname if hostname else firewall_name
    
    # ========================================
    # Multi-Firewall Operations
    # ========================================
    
    def execute_on_all_firewalls(self, operation: Callable[['PaloAltoClient'], Any], 
                                timeout: int = 30) -> Dict[str, Any]:
        """Execute an operation on all firewalls concurrently."""
        if not self.multi_firewall_mode:
            # Single firewall mode - execute on the single firewall
            try:
                result = operation(self)
                hostname = self.get_hostname(self.firewall_name)
                return {self.firewall_name: {
                    'success': True,
                    'data': result,
                    'error': None,
                    'hostname': hostname
                }}
            except Exception as e:
                hostname = self.get_hostname(self.firewall_name)
                return {self.firewall_name: {
                    'success': False,
                    'data': None,
                    'error': str(e),
                    'hostname': hostname
                }}
        
        # Multi-firewall mode
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all operations
            future_to_firewall = {
                executor.submit(operation, client): name 
                for name, client in self.firewalls.items()
            }
            
            # Collect results
            for future in as_completed(future_to_firewall, timeout=timeout):
                firewall_name = future_to_firewall[future]
                hostname = self.get_hostname(firewall_name)
                try:
                    result = future.result()
                    results[firewall_name] = {
                        'success': True,
                        'data': result,
                        'error': None,
                        'hostname': hostname
                    }
                    logger.debug(f"Operation completed successfully for {firewall_name}")
                except Exception as e:
                    results[firewall_name] = {
                        'success': False,
                        'data': None,
                        'error': str(e),
                        'hostname': hostname
                    }
                    logger.error(f"Operation failed for {firewall_name}: {e}")
        
        return results
    
    def execute_on_specific_firewalls(self, firewall_names: List[str], 
                                    operation: Callable[['PaloAltoClient'], Any],
                                    timeout: int = 30) -> Dict[str, Any]:
        """Execute an operation on specific firewalls."""
        if not self.multi_firewall_mode:
            # Single firewall mode - check if the requested firewall matches
            if self.firewall_name in firewall_names:
                try:
                    result = operation(self)
                    hostname = self.get_hostname(self.firewall_name)
                    return {self.firewall_name: {
                        'success': True,
                        'data': result,
                        'error': None,
                        'hostname': hostname
                    }}
                except Exception as e:
                    hostname = self.get_hostname(self.firewall_name)
                    return {self.firewall_name: {
                        'success': False,
                        'data': None,
                        'error': str(e),
                        'hostname': hostname
                    }}
            else:
                return {}
        
        # Multi-firewall mode
        results = {}
        
        # Filter to only requested firewalls
        requested_firewalls = {
            name: client for name, client in self.firewalls.items() 
            if name in firewall_names
        }
        
        if not requested_firewalls:
            logger.warning(f"No requested firewalls found: {firewall_names}")
            return results
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_firewall = {
                executor.submit(operation, client): name 
                for name, client in requested_firewalls.items()
            }
            
            for future in as_completed(future_to_firewall, timeout=timeout):
                firewall_name = future_to_firewall[future]
                hostname = self.get_hostname(firewall_name)
                try:
                    result = future.result()
                    results[firewall_name] = {
                        'success': True,
                        'data': result,
                        'error': None,
                        'hostname': hostname
                    }
                except Exception as e:
                    results[firewall_name] = {
                        'success': False,
                        'data': None,
                        'error': str(e),
                        'hostname': hostname
                    }
                    logger.error(f"Operation failed for {firewall_name}: {e}")
        
        return results
    
    def get_firewall_names(self) -> List[str]:
        """Get list of all available firewall names."""
        if not self.multi_firewall_mode:
            return [self.firewall_name]
        return list(self.firewalls.keys())
    
    def get_firewall_summary(self) -> Dict[str, Any]:
        """Get a summary of all configured firewalls (including disabled ones)."""
        all_configs = settings.get_firewalls()
        enabled_configs = settings.get_enabled_firewalls()
        disabled_configs = settings.get_disabled_firewalls()
        
        if not self.multi_firewall_mode:
            firewall_config = settings.get_firewall(self.firewall_name)
            is_enabled = settings.is_firewall_enabled(self.firewall_name)
            return {
                'total_firewalls': 1,
                'enabled_firewalls': 1 if is_enabled else 0,
                'disabled_firewalls': 0 if is_enabled else 1,
                'firewalls': {
                    self.firewall_name: {
                        'host': self.host,
                        'port': self.port,
                        'description': self.description,
                        'location': self.location,
                        'verify_ssl': self.verify_ssl,
                        'timeout': self.timeout,
                        'enabled': is_enabled
                    }
                }
            }
        
        summary = {
            'total_firewalls': len(all_configs),
            'enabled_firewalls': len(enabled_configs),
            'disabled_firewalls': len(disabled_configs),
            'firewalls': {}
        }
        
        # Include all firewalls in summary (both enabled and disabled)
        for name, config in all_configs.items():
            is_enabled = settings.is_firewall_enabled(name)
            if is_enabled and name in self.firewalls:
                client = self.firewalls[name]
                summary['firewalls'][name] = {
                    'host': client.host,
                    'port': client.port,
                    'description': client.description,
                    'location': client.location,
                    'verify_ssl': client.verify_ssl,
                    'timeout': client.timeout,
                    'enabled': True
                }
            else:
                # Disabled firewall - get info from config
                summary['firewalls'][name] = {
                    'host': config.get('host', 'Unknown'),
                    'port': config.get('port', 443),
                    'description': config.get('description', 'Unknown'),
                    'location': config.get('location', 'Unknown'),
                    'verify_ssl': config.get('verify_ssl', False),
                    'timeout': config.get('timeout', 30),
                    'enabled': is_enabled
                }
        
        return summary
    
    def validate_firewall_config(self) -> Dict[str, Any]:
        """Validate all firewall configurations."""
        if not self.multi_firewall_mode:
            # For single firewall, just validate the current connection
            try:
                # Test authentication
                if not self.auth.test_authentication():
                    return {self.firewall_name: {
                        'valid': False,
                        'errors': ['Authentication failed']
                    }}
                
                # Test basic connectivity
                self._make_request('GET', '/api/', params={'type': 'op', 'cmd': 'show system info'})
                
                return {self.firewall_name: {
                    'valid': True,
                    'errors': []
                }}
            except Exception as e:
                return {self.firewall_name: {
                    'valid': False,
                    'errors': [str(e)]
                }}
        
        # Multi-firewall mode
        validation_results = {}
        
        for name, client in self.firewalls.items():
            try:
                # Test authentication
                if not client.auth.test_authentication():
                    validation_results[name] = {
                        'valid': False,
                        'errors': ['Authentication failed']
                    }
                    continue
                
                # Test basic connectivity
                client._make_request('GET', '/api/', params={'type': 'op', 'cmd': 'show system info'})
                
                validation_results[name] = {
                    'valid': True,
                    'errors': []
                }
            except Exception as e:
                validation_results[name] = {
                    'valid': False,
                    'errors': [str(e)]
                }
        
        return validation_results

    def _make_request(self, method: str, endpoint: str, params: Dict[str, Any] = None, 
                     retries: int = None) -> requests.Response:
        """Make HTTP request with retry logic."""
        # Update logger context for this specific firewall instance
        if hasattr(self, 'firewall_name') and self.firewall_name:
            update_logger_firewall_context(logger, self.firewall_name, self.host)
        
        if retries is None:
            retries = self.max_retries
            
        url = urljoin(self.base_url, endpoint)
        
        # Add API key to parameters
        if params is None:
            params = {}
        params['key'] = self.auth.get_api_key()
        
        for attempt in range(retries + 1):
            try:
                logger.debug(f"Making {method} request to {url} (attempt {attempt + 1}, verify_ssl={self.verify_ssl})")
                
                response = requests.request(
                    method=method,
                    url=url,
                    params=params,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt == retries:
                    logger.error(f"Request failed after {retries + 1} attempts: {e}")
                    raise ConnectionError(f"Failed to connect to firewall: {e}")
                else:
                    logger.warning(f"Request attempt {attempt + 1} failed: {e}. Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
    
    def _parse_xml_response(self, response: requests.Response) -> Dict[str, Any]:
        """Parse XML response and check for errors."""
        try:
            # Parse XML to dict for easier handling
            xml_dict = xmltodict.parse(response.text)
            
            # Check response status
            if 'response' in xml_dict:
                response_data = xml_dict['response']
                status = response_data.get('@status')
                
                if status == 'success':
                    return response_data
                elif status == 'error':
                    error_msg = response_data.get('msg', 'Unknown error')
                    raise APIError(f"API error: {error_msg}")
                else:
                    raise APIError(f"Unexpected response status: {status}")
            else:
                raise APIError("Invalid response format")
                
        except (ET.ParseError, xml.parsers.expat.ExpatError) as e:
            raise APIError(f"Failed to parse XML response: {e}")
    
    def execute_operational_command(self, cmd: str) -> Dict[str, Any]:
        """Execute a read-only operational command."""
        # Update logger context for this specific firewall instance
        if hasattr(self, 'firewall_name') and self.firewall_name:
            update_logger_firewall_context(logger, self.firewall_name, self.host)
        
        logger.info(f"Executing operational command: {cmd}")
        
        params = {
            'type': 'op',
            'cmd': cmd
        }
        
        response = self._make_request('GET', '/api/', params=params)
        return self._parse_xml_response(response)
    