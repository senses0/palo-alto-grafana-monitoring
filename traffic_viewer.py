#!/usr/bin/env python3
"""
Terminal Traffic Viewer - Real-time interface traffic monitoring for Palo Alto firewalls.

Uses Textual TUI framework with Screen-based navigation for smooth transitions.

This is the entry point script. The implementation is in src/traffic_viewer/.
"""

from src.traffic_viewer import main

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        from src.traffic_viewer.app import test_data_retrieval
        test_data_retrieval()
    else:
        main()
