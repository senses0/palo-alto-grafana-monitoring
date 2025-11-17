"""Authentication module for Palo Alto Networks API (Read-Only)."""

import requests
import urllib3
from typing import Optional
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

from .exceptions import *
from ..utils.logger import get_logger, update_logger_firewall_context

logger = get_logger(__name__)

class PaloAltoAuth:
    """Authentication handler for Palo Alto Networks API (API key only)."""
    
    def __init__(self, host: str, port: int = 443, verify_ssl: bool = True, timeout: int = 30, firewall_name: str = None):
        self.host = host
        self.port = port
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.api_key = None
        self.base_url = f"https://{host}:{port}"
        self.firewall_name = firewall_name or host
        
        # Update logger with firewall context
        update_logger_firewall_context(logger, self.firewall_name, self.host)
        
        # Disable SSL warnings if verification is disabled
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning(f"SSL verification disabled for {host}")
    
    def set_api_key(self, api_key: str) -> None:
        """Set API key for authentication."""
        self.api_key = api_key
        logger.info("API key set successfully")
    
    def test_authentication(self) -> bool:
        """Test if current API key is valid."""
        if not self.api_key:
            return False
            
        try:
            url = urljoin(self.base_url, "/api/")
            params = {
                'type': 'op',
                'cmd': '<show><system><info></info></system></show>',
                'key': self.api_key
            }
            
            response = requests.get(url, params=params, verify=self.verify_ssl, timeout=self.timeout)
            response.raise_for_status()
            
            root = ET.fromstring(response.text)
            return root.get('status') == 'success'
            
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL verification failed for {self.host}: {e}")
            if self.verify_ssl:
                logger.error(f"SSL verification is enabled but failed. Consider setting verify_ssl: false in config for {self.firewall_name}")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection failed for {self.host}: {e}")
            return False
        except Exception as e:
            logger.error(f"Authentication test failed for {self.host}: {e}")
            return False
    
    def get_api_key(self) -> str:
        """Get current API key."""
        if not self.api_key:
            raise AuthenticationError("No API key available. Please set API key first.")
        return self.api_key