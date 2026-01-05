"""Logging configuration and utilities."""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional
from config.settings import settings

# Global flag to control console logging
# Set to True to suppress console output (file logging still works)
_console_logging_suppressed = False


class FirewallContextFilter(logging.Filter):
    """Filter to add firewall context to log records."""
    
    def __init__(self):
        super().__init__()
        self.firewall_name = None
        self.firewall_host = None
    
    def set_firewall_context(self, firewall_name: str, firewall_host: str = None):
        """Set the firewall context for this filter."""
        self.firewall_name = firewall_name
        self.firewall_host = firewall_host
    
    def filter(self, record):
        """Add firewall context to the log record."""
        if self.firewall_name:
            record.firewall_name = self.firewall_name
            record.firewall_host = self.firewall_host or 'unknown'
        else:
            record.firewall_name = 'unknown'
            record.firewall_host = 'unknown'
        return True

def get_logger(name: str, firewall_name: str = None, firewall_host: str = None) -> logging.Logger:
    """Get configured logger instance with optional firewall context."""
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        # Configure logger
        level = getattr(logging, settings.get('logging.level', 'INFO').upper())
        logger.setLevel(level)
        
        # Create formatters with firewall context
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - [%(firewall_name)s:%(firewall_host)s] - %(levelname)s - %(message)s'
        )
        
        # Console handler - only add if not suppressed
        if not _console_logging_suppressed:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            
            # Add firewall context filter
            firewall_filter = FirewallContextFilter()
            if firewall_name:
                firewall_filter.set_firewall_context(firewall_name, firewall_host)
            console_handler.addFilter(firewall_filter)
            logger.addHandler(console_handler)
        
        # File handler
        log_file = settings.get('logging.file', 'logs/pa_stats.log')
        log_dir = os.path.dirname(log_file)
        if log_dir:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=settings.get('logging.max_bytes', 10485760),
            backupCount=settings.get('logging.backup_count', 5)
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        
        # Add firewall context filter to file handler too
        file_firewall_filter = FirewallContextFilter()
        if firewall_name:
            file_firewall_filter.set_firewall_context(firewall_name, firewall_host)
        file_handler.addFilter(file_firewall_filter)
        logger.addHandler(file_handler)
    
    # Update firewall context for existing handlers if provided
    if firewall_name and logger.handlers:
        for handler in logger.handlers:
            for filter_obj in handler.filters:
                if isinstance(filter_obj, FirewallContextFilter):
                    filter_obj.set_firewall_context(firewall_name, firewall_host)
    
    return logger

def get_firewall_logger(name: str, firewall_name: str, firewall_host: str = None) -> logging.Logger:
    """Get a logger specifically configured for a firewall."""
    return get_logger(name, firewall_name, firewall_host)

def update_logger_firewall_context(logger: logging.Logger, firewall_name: str, firewall_host: str = None):
    """Update the firewall context for an existing logger."""
    for handler in logger.handlers:
        for filter_obj in handler.filters:
            if isinstance(filter_obj, FirewallContextFilter):
                filter_obj.set_firewall_context(firewall_name, firewall_host)
                break


def suppress_console_logging():
    """Suppress console output for all loggers while keeping file logging active.
    
    This is useful for TUI applications (like traffic_viewer.py) where console
    output would interfere with the terminal UI, but you still want logs written
    to the log file.
    
    Call this function early in your application before any other imports.
    It sets a global flag that prevents console handlers from being added to
    new loggers, and also disables any existing console handlers.
    """
    global _console_logging_suppressed
    _console_logging_suppressed = True
    
    # Also suppress any console handlers that already exist
    # Get the root logger and all existing loggers
    root_logger = logging.getLogger()
    
    # Set console handlers to CRITICAL+1 (effectively disabled) for root logger
    for handler in root_logger.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
            handler.setLevel(logging.CRITICAL + 1)
    
    # Also handle any loggers that have already been created
    for logger_name in logging.Logger.manager.loggerDict:
        logger = logging.getLogger(logger_name)
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                handler.setLevel(logging.CRITICAL + 1)