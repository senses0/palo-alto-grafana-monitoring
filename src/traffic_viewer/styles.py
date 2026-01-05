"""
CSS styles for the Traffic Viewer.

Contains:
- get_splash_css: CSS for the splash/loading screen
- get_css: CSS for the selection screen
- get_monitor_css: CSS for the monitor screen
"""

from .models import ColorTheme, THEME


def get_splash_css(theme: ColorTheme = THEME) -> str:
    """Generate CSS for the splash screen using theme colors."""
    return f"""
/* Splash Screen - No header, fully centered content */
SplashScreen {{
    background: {theme.background};
    align: center middle;
}}

#splash-outer {{
    width: 100%;
    height: 100%;
    align: center middle;
}}

#splash-content {{
    width: auto;
    height: auto;
    padding: 4 8;
    background: {theme.surface};
    border: double {theme.primary_dark};
    align: center middle;
}}

/* Main title - bold and prominent */
.splash-title {{
    text-align: center;
    text-style: bold;
    color: {theme.primary};
    margin-bottom: 0;
}}

/* Subtitle - softer appearance */
.splash-subtitle {{
    text-align: center;
    color: {theme.text_dim};
    margin-bottom: 2;
}}

/* Progress bar container */
#splash-progress {{
    width: 50;
    height: 1;
    margin: 1 0;
    content-align: center middle;
}}

/* Status message - updates during loading */
.splash-status {{
    text-align: center;
    color: {theme.warning};
    margin-top: 1;
}}

/* Error display on splash */
.splash-error {{
    text-align: center;
    color: {theme.error};
    margin-top: 1;
}}

/* Decorative dots animation styling */
.splash-dots {{
    text-align: center;
    color: {theme.primary_light};
    margin: 1 0;
}}
"""


def get_css(theme: ColorTheme = THEME) -> str:
    """Generate CSS for the selection screen using theme colors."""
    return f"""
Screen {{
    background: {theme.background};
}}

#header-panel {{
    height: 1;
    background: {theme.surface_light};
    color: {theme.text};
    text-align: center;
    padding: 0 1;
    border-bottom: solid {theme.border};
    content-align: center middle;
}}

#main-container {{
    height: 1fr;
    padding: 0 1 1 1;
}}

#firewall-tree {{
    width: 100%;
    height: 1fr;
    border: solid {theme.border};
    background: {theme.surface};
}}

#status-bar {{
    height: 3;
    background: {theme.surface_dark};
    padding: 1;
    border-top: solid {theme.border};
    color: {theme.text};
}}

.firewall-header {{
    background: {theme.surface_light};
    padding: 0 1;
    text-style: bold;
    color: {theme.primary};
}}

.interface-item {{
    padding: 0 2;
    color: {theme.text};
}}

.selected-count {{
    text-style: bold;
    color: {theme.success};
}}

#loading-container {{
    align: center middle;
    height: 100%;
    color: {theme.text};
}}

#loading-animation {{
    align: center middle;
    padding: 2;
}}

.loading-text {{
    text-align: center;
    margin-bottom: 1;
    color: {THEME.primary};
}}

.loading-subtext {{
    text-align: center;
    margin-bottom: 1;
    color: {THEME.text_dim};
}}

.loading-tip {{
    text-align: center;
    color: {THEME.warning};
    margin-top: 2;
}}

/* Fancy loading indicator */
LoadingIndicator#fancy-loader {{
    height: 5;
    width: 100%;
    background: {theme.surface};
    color: {theme.primary_light};
}}

#selection-list {{
    height: 1fr;
    border: solid {theme.border};
    background: {theme.surface};
}}

.selection-list--option {{
    padding: 0 1;
    color: {theme.text};
}}

.selection-list--option-highlighted {{
    background: {theme.primary_dark};
    color: {theme.text};
}}

Tree {{
    height: 1fr;
    color: {theme.text};
}}

Tree > .tree--guides {{
    color: {theme.primary};
}}

Tree > .tree--cursor {{
    background: {theme.primary};
    color: {theme.background};
}}

#button-bar {{
    height: 4;
    align: center middle;
    padding: 0 1;
    background: {theme.surface_dark};
    border-top: solid {theme.border};
}}

Button {{
    margin: 0 1;
    background: {theme.surface_light};
    border: solid {theme.border};
    color: {theme.text};
}}

Button:hover {{
    background: {theme.primary_dark};
    border: solid {theme.primary};
}}

Button:focus {{
    background: {theme.primary};
    border: solid {theme.primary_light};
}}

#proceed-btn {{
    background: #3d5f4a;
    color: {theme.text};
}}

#proceed-btn:hover {{
    background: #4a7058;
}}

#cancel-btn {{
    background: #5f4a4a;
    color: {theme.text};
}}

#cancel-btn:hover {{
    background: #705858;
}}

#options-bar {{
    height: 4;
    align: center middle;
    padding: 0 1;
    background: {theme.surface};
    border-bottom: solid {theme.border};
}}

#polling-label {{
    padding: 0 1;
    text-style: bold;
    color: {theme.text};
    height: 3;
    content-align: left middle;
}}

#polling-select {{
    width: 20;
    height: 3;
}}

Select {{
    width: 20;
    background: {theme.surface};
    color: {theme.text};
}}

Select > SelectCurrent {{
    border: solid {theme.border};
    background: {theme.surface};
    color: {theme.text};
}}

Select:focus > SelectCurrent {{
    border: solid {theme.primary};
}}

Select > SelectOverlay {{
    background: {theme.surface};
    border: solid {theme.border};
}}

Select > SelectOverlay > SelectOption {{
    color: {theme.text};
}}

Select > SelectOverlay > SelectOption:hover {{
    background: {theme.primary_dark};
}}

#help-panel {{
    width: 100%;
    height: 1fr;
}}

#help-loading {{
    background: {theme.surface_dark};
    border: solid {theme.border};
    padding: 2;
}}

.help-key {{
    text-style: bold;
    color: {theme.success};
}}

.help-desc {{
    color: {theme.text_dim};
}}
"""


def get_monitor_css(theme: ColorTheme = THEME) -> str:
    """Generate CSS for the monitor screen using theme colors."""
    return f"""
Screen {{
    background: {theme.background};
}}

#traffic-container {{
    height: 1fr;
    padding: 0 1 1 1;
}}

#stats-table {{
    height: auto;
    max-height: 40%;
    border: solid {theme.border};
    margin-bottom: 1;
    background: {theme.surface};
}}

#graph-container {{
    width: 100%;
    height: 1fr;
    border: solid {theme.border};
    padding: 0;
    background: {theme.background};
}}

.interface-row {{
    width: 100%;
    height: auto;
    min-height: 18;
    padding: 0 1;
    margin-bottom: 1;
    border-bottom: solid {theme.border};
}}

.interface-graph-scroll {{
    width: 50%;
    height: auto;
    min-height: 16;
    overflow-x: auto;
    overflow-y: hidden;
    background: {theme.background};
}}

.interface-graph {{
    width: auto;
    min-width: 100%;
    height: auto;
    padding: 1 0;
    margin-bottom: 1;
    background: {theme.background};
}}

.interface-table {{
    width: 50%;
    height: 16;
    margin-left: 1;
    background: {theme.surface};
    border: solid {theme.border};
    scrollbar-gutter: stable;
}}

.interface-table > .datatable--header {{
    background: {theme.surface_light};
    text-style: bold;
    color: {theme.primary_light};
}}

.interface-table > .datatable--row-even {{
    background: {theme.surface};
}}

.interface-table > .datatable--row-odd {{
    background: {theme.surface_dark};
}}

.graph-label {{
    height: 1;
    text-style: bold;
}}

#status-footer {{
    height: 3;
    background: {theme.surface};
    padding: 0 1;
    border-top: solid {theme.border};
    color: {theme.text};
    align: left middle;
}}

#status-indicator {{
    width: auto;
    padding: 0 1 0 0;
    color: {theme.text_dim};
    height: 3;
    content-align: left middle;
}}

#status-text {{
    width: 1fr;
    padding: 0 1;
    height: 3;
    content-align: left middle;
}}

#monitor-polling-select {{
    width: 16;
    height: 3;
    margin: 0 1 0 0;
}}

#monitor-polling-select > SelectCurrent {{
    border: solid {theme.border};
    background: {theme.surface_light};
    color: {theme.primary_light};
    padding: 0 1;
    height: 3;
}}

#monitor-polling-select:focus > SelectCurrent {{
    border: solid {theme.primary};
    background: {theme.primary_dark};
}}

#monitor-polling-select SelectOverlay {{
    background: {theme.surface};
    border: solid {theme.border};
    width: 16;
}}

#monitor-polling-select SelectOverlay OptionList {{
    width: 16;
}}

#monitor-polling-select SelectOverlay OptionList > .option-list--option {{
    color: {theme.text};
    padding: 0 1;
}}

#monitor-polling-select SelectOverlay OptionList > .option-list--option-highlighted {{
    background: {theme.primary_dark};
    color: {theme.text};
}}

#legend {{
    height: 1;
    padding: 0 1;
    background: {theme.surface_light};
    border-bottom: solid {theme.border};
    color: {theme.text};
    content-align: center middle;
}}

DataTable {{
    height: auto;
    background: {theme.surface};
}}

DataTable > .datatable--header {{
    background: {theme.surface_light};
    text-style: bold;
    color: {theme.text};
    border-bottom: solid {theme.border};
}}

DataTable > .datatable--header-cell {{
    color: {theme.text};
}}

DataTable > .datatable--cell {{
    color: {theme.text};
}}

DataTable > .datatable--cursor {{
    background: {theme.primary_dark};
    color: {theme.text};
}}

DataTable > .datatable--row-even {{
    background: {theme.surface};
}}

DataTable > .datatable--row-odd {{
    background: {theme.surface_dark};
}}
"""

