"""Custom exceptions for Palo Alto client."""

class PaloAltoError(Exception):
    """Base exception for Palo Alto operations."""
    pass

class AuthenticationError(PaloAltoError):
    """Authentication failed."""
    pass

class ConnectionError(PaloAltoError):
    """Connection to firewall failed."""
    pass

class APIError(PaloAltoError):
    """API request failed."""
    def __init__(self, message: str, status_code: int = None, response_text: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text

class ConfigurationError(PaloAltoError):
    """Configuration is invalid."""
    pass