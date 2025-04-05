#!/usr/bin/env python3
"""
BlackIce - IoT Vulnerability Scanner

A comprehensive tool for finding, analyzing, and assessing security vulnerabilities
in Internet of Things (IoT) devices using the Shodan API and other security tools.

Features:
- IoT device discovery using Shodan API
- Vulnerability assessment and CVSS scoring
- Default credential testing
- Network segmentation analysis
- SSL/TLS security checking
- Exploit database integration (ExploitDB, Vulners)
- Device fingerprinting with Nmap
- Visualization with maps, charts, and network graphs
- Historical device tracking and change detection
- Proxy support for anonymous scanning
- Colorful console output and logging
- Interactive shell and command-line interfaces
- Parallel processing for enhanced performance
- Passive/stealth scanning mode

Usage:
  python BlackIce.py --interactive         # Run in interactive shell mode
  python BlackIce.py --query "webcam" --limit 50   # Direct search mode
  python BlackIce.py --help                # Show all available options

Requirements:
  - Python 3.6+
  - Shodan API key
  - Various libraries (see import statements)

License:
  This tool is for educational and authorized security testing only.
  The author is not responsible for any misuse or damage.

Project:
  GitHub: https://github.com/yourusername/blackice
  Version: 1.0.0
"""

# BlackIce - IoT Vulnerability Scanner
# A comprehensive tool for finding and analyzing vulnerable IoT devices

import argparse
import csv
import datetime
import ftplib
import hashlib
import ipaddress
import json
import logging
import os
import platform
import queue
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import webbrowser
import shutil
from config import *
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse
import asyncio
import telnetlib3

# Import configuration settings
from config import *

# Progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# HTTP requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: requests module not available. Most functionality will be limited.")

# Tabular data display
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False
    print("Warning: tabulate module not available. Table output will be limited.")

# Colored terminal output
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# Interactive shell
try:
    import cmd
    CMD_AVAILABLE = True
except ImportError:
    CMD_AVAILABLE = False

# Shodan API
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

# SSH functionality
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("Warning: paramiko module not available. SSH functionality will be disabled.")

# Map visualization
try:
    import folium
    from folium.plugins import MarkerCluster
    FOLIUM_AVAILABLE = True
except ImportError:
    FOLIUM_AVAILABLE = False

# Network analysis
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    NETWORK_AVAILABLE = True
except ImportError:
    NETWORK_AVAILABLE = False

# Data analysis
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

# Community detection for network graphs
try:
    import community as community_louvain
    COMMUNITY_AVAILABLE = True
except ImportError:
    COMMUNITY_AVAILABLE = False

# Nmap for device fingerprinting
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Create logger
logger = logging.getLogger('blackice')
logger.setLevel(logging.INFO)

# Configure file handler
log_file = os.path.join(LOG_DIR, f"blackice_{datetime.now().strftime('%Y%m%d')}.log")
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.DEBUG)

# Configure console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)  # Only show warnings and errors in console

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ASCII Art Banner
BANNER = r"""
 ▄▄▄▄    ██▓    ▄▄▄       ▄████▄   ██ ▄█▀ ██▓ ▄████▄  ▓█████ 
▓█████▄ ▓██▒   ▒████▄    ▒██▀ ▀█   ██▄█▒ ▓██▒▒██▀ ▀█  ▓█   ▀ 
▒██▒ ▄██▒██░   ▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒██▒▒▓█    ▄ ▒███   
▒██░█▀  ▒██░   ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ░██░▒▓▓▄ ▄██▒▒▓█  ▄ 
░▓█  ▀█▓░██████▒▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░██░▒ ▓███▀ ░░▒████▒
░▒▓███▀▒░ ▒░▓  ░▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░▓  ░ ░▒ ▒  ░░░ ▒░ ░
▒░▒   ░ ░ ░ ▒  ░ ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ▒ ░  ░  ▒    ░ ░  ░
 ░    ░   ░ ░    ░   ▒   ░        ░ ░░ ░  ▒ ░░           ░   
 ░          ░  ░     ░  ░░ ░      ░  ░    ░  ░ ░         ░  ░
      ░                  ░                   ░               
              [ IoT Vulnerability Scanner Suite ]
        [ Version 1.0.0 - github.com/box1402/blackice ]
"""

# Legal disclaimer
LEGAL_DISCLAIMER = """
[!] LEGAL DISCLAIMER [!]

This tool is provided for educational and research purposes only.
Using this tool against devices or networks without explicit permission is illegal.
You are responsible for your actions and potential damage caused by using this tool.
The authors assume no liability and are not responsible for any misuse or damage.
"""

# Commonly used HTTP headers
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close"
}

# Common device types and their search queries
DEVICE_TEMPLATES = {
    "ip_cameras": "webcam has_screenshot:true",
    "routers": "router port:80,443",
    "smart_tvs": "smart tv has_screenshot:true",
    "printers": "printer has_screenshot:true",
    "industrial_control": "scada port:502",
    "home_automation": "home automation",
    "medical_devices": "medical port:80,443",
    "nvrs": "nvr has_screenshot:true",
    "smart_home": "smart port:80,443 has_screenshot:true",
    "exposed_databases": "mongodb port:27017 OR elasticsearch port:9200",
    "building_control": "building management",
    "default_credentials": "default password",
    "voip": "voip asterisk port:5060",
    "vulnerable_ssh": "ssh port:22 OpenSSH",
    "vulnerable_ssl": "ssl port:443 200 OK"
}

# Setup functions
def setup_proxy():
    """
    Configure proxy settings for requests
    
    Returns:
        Dictionary with proxy configuration or None if no proxy is configured
    """
    global PROXY_ENABLED, HTTP_PROXY, HTTPS_PROXY, SOCKS_PROXY
    
    if not PROXY_ENABLED:
        logger.debug("Proxy settings disabled")
        return None
    
    # If specific proxies are not set, try to get from environment
    if not HTTP_PROXY:
        HTTP_PROXY = os.environ.get('HTTP_PROXY')
    if not HTTPS_PROXY:
        HTTPS_PROXY = os.environ.get('HTTPS_PROXY')
    if not SOCKS_PROXY:
        SOCKS_PROXY = os.environ.get('SOCKS_PROXY')
    
    proxies = {}
    
    # Use configured proxy settings from BlackIce
    if HTTP_PROXY:
        proxies['http'] = HTTP_PROXY
    if HTTPS_PROXY:
        proxies['https'] = HTTPS_PROXY
    if SOCKS_PROXY:
        # For SOCKS proxies, we need the requests[socks] package
        try:
            import socks
            logger.debug("SOCKS module available")
            proxies['http'] = SOCKS_PROXY
            proxies['https'] = SOCKS_PROXY
        except ImportError:
            logger.warning("SOCKS proxy configured but PySocks package not available")
    
    # Handle proxy authentication
    if PROXY_USERNAME and PROXY_PASSWORD:
        for protocol in proxies:
            url = proxies[protocol]
            parsed = urlparse(url)
            if parsed.scheme and not parsed.username:
                auth_url = f"{parsed.scheme}://{PROXY_USERNAME}:{PROXY_PASSWORD}@{parsed.hostname}"
                if parsed.port:
                    auth_url += f":{parsed.port}"
                if parsed.path:
                    auth_url += parsed.path
                proxies[protocol] = auth_url
    
    logger.debug(f"Using configured proxies: {proxies}")
    return proxies if proxies else None

def setup_api_key():
    """
    Setup and validate the Shodan API key
    
    Returns:
        str: API key if available, otherwise None
    """
    # First try the API key from the config file
    api_key = SHODAN_API_KEY
    
    # If not set in config file or is the default placeholder, try environment variables
    if not api_key or api_key == "your_shodan_api_key_here":
        # Try to get API key from environment
        api_key = os.environ.get('SHODAN_API_KEY')
        
        if not api_key:
            # Look for API key in common config locations
            config_paths = [
                os.path.expanduser("~/.shodan/api_key"),
                os.path.expanduser("~/.config/shodan/api_key"),
                os.path.expanduser("~/.blackice/shodan_api_key")
            ]
            
            for path in config_paths:
                try:
                    if os.path.exists(path):
                        with open(path, 'r') as f:
                            api_key = f.read().strip()
                        if api_key:
                            logger.info(f"Using API key from {path}")
                            break
                except Exception as e:
                    logger.error(f"Error reading API key from {path}: {str(e)}")
    
    if api_key:
        try:
            # Verify the API key works
            api = shodan.Shodan(api_key)
            api.info()
            logger.info("Shodan API key verified")
        except Exception as e:
            logger.error(f"Invalid API key: {str(e)}")
            api_key = None
            
    return api_key

def cached_request(url, method='GET', headers=None, params=None, data=None, timeout=10):
    """
    Make HTTP requests with caching to reduce API calls
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST, etc.)
        headers: Request headers
        params: URL parameters
        data: Request body for POST requests
        timeout: Request timeout in seconds
        
    Returns:
        Response object or None if request failed
    """
    if not REQUESTS_AVAILABLE:
        logger.error("Requests library not installed. Install with: pip install requests")
        return None
        
    try:
        # Generate cache key based on request parameters
        cache_key = f"{method}_{url}"
        if params:
            cache_key += f"_{json.dumps(params, sort_keys=True)}"
        if data:
            cache_key += f"_{json.dumps(data, sort_keys=True)}"
        
        # Convert to a valid filename by hashing
        cache_key = hashlib.md5(cache_key.encode()).hexdigest()
        cache_file = os.path.join(CACHE_DIR, f"request_{cache_key}.json")
        
        # Check if we have a valid cached response
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                    
                # Check if cache is still valid
                if time.time() - cached_data.get('timestamp', 0) < CACHE_TIMEOUT:
                    logger.debug(f"Using cached response for {url}")
                    
                    # Create a mock response object
                    class MockResponse:
                        def __init__(self, data):
                            self.status_code = data.get('status_code')
                            self._text = data.get('text')
                            self._json = data.get('json')
                            
                        def json(self):
                            return self._json
                            
                        @property
                        def text(self):
                            return self._text
                    
                    return MockResponse(cached_data)
            except Exception as e:
                logger.debug(f"Error reading cache for {url}: {e}")
        
        # Set default headers
        if headers is None:
            headers = {'User-Agent': USER_AGENT}
        else:
            headers.setdefault('User-Agent', USER_AGENT)
        
        # Make the actual request
        logger.debug(f"Making request to {url}")
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            timeout=timeout,
            proxies=setup_proxy(),
            verify=False  # Disable SSL verification for simplicity
        )
        
        # Save response to cache if successful
        if response.status_code == 200:
            try:
                cache_data = {
                    'timestamp': int(time.time()),
                    'url': url,
                    'status_code': response.status_code,
                    'text': response.text,
                    'json': response.json() if 'application/json' in response.headers.get('Content-Type', '') else None
                }
                
                # Ensure cache directory exists
                os.makedirs(os.path.dirname(cache_file), exist_ok=True)
                
                # Write to cache file
                with open(cache_file, 'w') as f:
                    json.dump(cache_data, f)
                    
                logger.debug(f"Cached response from {url}")
            except Exception as e:
                logger.debug(f"Error caching response from {url}: {e}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error in request for {url}: {e}")
        return None

def check_for_updates(repo_url=None):
    """
    Check for updates to BlackIce by comparing current version with latest release on GitHub
    
    Args:
        repo_url (str): URL to GitHub repository, defaults to GITHUB_REPO
    
    Returns:
        Tuple of (has_update, latest_version)
        - has_update: Boolean indicating if an update is available
        - latest_version: String containing the latest version number
    """
    if not repo_url:
        repo_url = GITHUB_REPO
    
    # Extract username and repo from GitHub URL
    match = re.search(r"github.com/([^/]+)/([^/]+)", repo_url)
    if not match:
        logger.error("Invalid GitHub repository URL format")
        return False, VERSION
    
    username, repo = match.groups()
    
    try:
        # GitHub API URL for latest release
        api_url = f"https://api.github.com/repos/{username}/{repo}/releases/latest"
        
        logger.info(f"Checking for updates from {api_url}")
        
        # Use requests directly with error handling
        try:
            headers = {
                "User-Agent": USER_AGENT,
                "Accept": "application/json"
            }
            response = requests.get(api_url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                logger.error(f"Failed to check for updates. Status code: {response.status_code}")
                return False, VERSION
            
            release_data = response.json()
        except requests.RequestException as e:
            logger.error(f"Request error checking for updates: {str(e)}")
            return False, VERSION
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response from GitHub: {str(e)}")
            return False, VERSION
        
        # Get tag name as version (e.g., "v1.0.0" -> "1.0.0")
        latest_version = release_data.get('tag_name', '').lstrip('v')
        
        # If no version found, use the release name
        if not latest_version:
            latest_version = release_data.get('name', '').lstrip('v')
        
        if not latest_version:
            logger.error("Failed to determine latest version from GitHub")
            return False, VERSION
        
        # Compare versions
        current_version_parts = [int(x) for x in VERSION.split('.')]
        latest_version_parts = [int(x) for x in latest_version.split('.')]
        
        # Pad version arrays to same length
        while len(current_version_parts) < len(latest_version_parts):
            current_version_parts.append(0)
        while len(latest_version_parts) < len(current_version_parts):
            latest_version_parts.append(0)
        
        # Compare each part
        for current, latest in zip(current_version_parts, latest_version_parts):
            if latest > current:
                logger.info(f"Update available: {VERSION} -> {latest_version}")
                return True, latest_version
            elif current > latest:
                return False, VERSION
        
        # If we get here, versions are equal
        return False, VERSION
    
    except Exception as e:
        logger.error(f"Error checking for updates: {str(e)}")
        return False, VERSION

def check_dependencies():
    """Check for required dependencies and print status"""
    dependencies = {
        "shodan": {
            "available": SHODAN_AVAILABLE,
            "import": "import shodan",
            "install": "pip install shodan",
            "required": True,
            "description": "API client for Shodan.io"
        },
        "requests": {
            "available": REQUESTS_AVAILABLE,
            "import": "import requests",
            "install": "pip install requests",
            "required": True,
            "description": "HTTP client library"
        },
        "colorama": {
            "available": COLORAMA_AVAILABLE,
            "import": "from colorama import Fore, Back, Style",
            "install": "pip install colorama",
            "required": False,
            "description": "Colored console output"
        },
        "tabulate": {
            "available": TABULATE_AVAILABLE,
            "import": "from tabulate import tabulate",
            "install": "pip install tabulate",
            "required": False,
            "description": "Pretty-print tabular data"
        },
        "folium": {
            "available": FOLIUM_AVAILABLE,
            "import": "import folium",
            "install": "pip install folium",
            "required": False,
            "description": "Map visualization"
        },
        "pandas": {
            "available": PANDAS_AVAILABLE,
            "import": "import pandas as pd",
            "install": "pip install pandas",
            "required": False,
            "description": "Data analysis"
        },
        "matplotlib": {
            "available": NETWORK_AVAILABLE,
            "import": "import matplotlib.pyplot as plt",
            "install": "pip install matplotlib",
            "required": False,
            "description": "Plotting library"
        },
        "nmap": {
            "available": NMAP_AVAILABLE,
            "import": "import nmap",
            "install": "pip install python-nmap",
            "required": False,
            "description": "Network scanning"
        },
        "paramiko": {
            "available": PARAMIKO_AVAILABLE,
            "import": "import paramiko",
            "install": "pip install paramiko",
            "required": False,
            "description": "SSH client"
        },
        "tqdm": {
            "available": TQDM_AVAILABLE,
            "import": "from tqdm import tqdm",
            "install": "pip install tqdm",
            "required": False,
            "description": "Progress bar"
        }
    }
    
    missing_required = []
    missing_optional = []
    available = []
    
    print("\nChecking dependencies:")
    print("=====================")
    
    # Check each dependency
    for name, info in dependencies.items():
        if info["available"]:
            status = "✓ Available" if not COLORAMA_AVAILABLE else f"{Fore.GREEN}✓ Available{Style.RESET_ALL}"
            available.append(name)
        else:
            if info["required"]:
                status = "✗ MISSING (REQUIRED)" if not COLORAMA_AVAILABLE else f"{Fore.RED}✗ MISSING (REQUIRED){Style.RESET_ALL}"
                missing_required.append(name)
            else:
                status = "✗ Missing (Optional)" if not COLORAMA_AVAILABLE else f"{Fore.YELLOW}✗ Missing (Optional){Style.RESET_ALL}"
                missing_optional.append(name)
        
        print(f"{name:12} - {status:25} - {info['description']}")
    
    # Print installation instructions if needed
    if missing_required or missing_optional:
        print("\nInstallation instructions:")
        
        if missing_required:
            print("\nRequired dependencies:")
            for name in missing_required:
                info = dependencies[name]
                print(f"  {info['install']}")
        
        if missing_optional:
            print("\nOptional dependencies (for enhanced functionality):")
            for name in missing_optional:
                info = dependencies[name]
                print(f"  {info['install']}  # {info['description']}")
        
        print("\nYou can install all dependencies using:")
        print("  pip install -r requirements.txt")
    
    # Return lists of dependencies
    return {
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "available": available
    }

def get_device_vulns(product, version=None):
    """Query the NVD database for vulnerabilities related to a product"""
    params = {
        'keywordSearch': product,
        'resultsPerPage': 10
    }
    
    if version:
        params['keywordSearch'] += f" {version}"
    
    try:
        response = requests.get(NVD_API_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            vulns = []
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                vuln_data = {
                    'id': cve.get('id', 'Unknown'),
                    'description': cve.get('descriptions', [{}])[0].get('value', 'No description'),
                    'severity': 'Unknown',
                    'published': cve.get('published', 'Unknown')
                }
                
                # Get CVSS score if available
                metrics = cve.get('metrics', {})
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss = metrics['cvssMetricV31'][0].get('cvssData', {})
                    vuln_data['severity'] = cvss.get('baseSeverity', 'Unknown')
                    vuln_data['score'] = cvss.get('baseScore', 0)
                
                vulns.append(vuln_data)
            return vulns
        else:
            print(f"Error querying NVD API: {response.status_code}", file=sys.stderr)
            return []
    except Exception as e:
        print(f"Error querying vulnerability data: {e}", file=sys.stderr)
        return []

def search_vulnerable_iot_devices(query, limit=10, output_format="text", output_file=None, 
                                 country_filter=None, port_filter=None, check_vulns=False):
    """
    Search for vulnerable IoT devices using Shodan API
    
    Args:
        query (str): Search query for Shodan
        limit (int): Maximum number of results to return
        output_format (str): Output format (text, json, csv)
        output_file (str): Path to output file
        country_filter (str): Filter by country code
        port_filter (int): Filter by specific port
        check_vulns (bool): Whether to check for vulnerabilities
        
    Returns:
        list: List of device dictionaries
    """
    if not SHODAN_AVAILABLE:
        logger.error("Shodan module not available. Please install: pip install shodan")
        return []
    
    # Setup API key
    api_key = setup_api_key()
    if not api_key:
        logger.error("No valid Shodan API key found. Please set in config.py or environment.")
        return []
    
    api = shodan.Shodan(api_key)
    
    # Apply filters
    search = query
    if country_filter:
        search += f" country:{country_filter}"
    if port_filter:
        search += f" port:{port_filter}"
    
    logger.info(f"Searching Shodan for: {search}")
    
    # Perform search with error handling
    try:
        # Use a progress bar if available
        if TQDM_AVAILABLE:
            print(f"Searching for devices matching: {search}")
            results = api.search(search, limit=limit)
            total = min(limit, results['total'])
            matches = results['matches']
            
            progress = tqdm(total=total, desc="Retrieving devices", unit="device")
            for i, match in enumerate(matches):
                if i >= limit:
                    break
                progress.update(1)
            progress.close()
        else:
            # No progress bar available
            print(f"Searching for IoT devices matching: {search}")
            results = api.search(search, limit=limit)
            matches = results['matches']
        
        # Process results
        devices = []
        for match in matches[:limit]:
            device = {
                'ip': match.get('ip_str', 'Unknown'),
                'port': match.get('port', 0),
                'hostnames': match.get('hostnames', []),
                'domains': match.get('domains', []),
                'os': match.get('os', 'Unknown'),
                'timestamp': match.get('timestamp', ''),
                'isp': match.get('isp', 'Unknown'),
                'asn': match.get('asn', 'Unknown'),
                'location': {
                    'country_code': match.get('location', {}).get('country_code', 'Unknown'),
                    'country_name': match.get('location', {}).get('country_name', 'Unknown'),
                    'city': match.get('location', {}).get('city', 'Unknown'),
                    'longitude': match.get('location', {}).get('longitude', 0),
                    'latitude': match.get('location', {}).get('latitude', 0)
                },
                'org': match.get('org', 'Unknown'),
                'data': match.get('data', ''),
                'product': match.get('product', 'Unknown'),
                'version': match.get('version', 'Unknown'),
                'tags': match.get('tags', []),
                'shodan': match.get('_shodan', {}),
                'vulns': match.get('vulns', {})
            }
            
            # Check for vulnerabilities if requested
            if check_vulns and not device['vulns']:
                device['vulns'] = get_device_vulns(device['product'], device['version'])
            
            devices.append(device)
        
        # Display or export results based on format
        if output_format == "text":
            display_text_results(devices, show_vulns=check_vulns)
        elif output_format == "table":
            display_table_results(devices, show_vulns=check_vulns)
        
        # Export if requested
        if output_file:
            if output_format == "csv":
                export_to_csv(devices, output_file, include_vulns=check_vulns)
            elif output_format == "json":
                export_to_json(devices, output_file)
        
        return devices
    
    except shodan.APIError as e:
        logger.error(f"Shodan API Error: {e}")
        if str(e) == "No information available for that IP.":
            logger.info("No devices found matching your search criteria.")
        return []
    except Exception as e:
        logger.error(f"Error searching Shodan: {str(e)}")
        return []

def display_text_results(devices, show_vulns=False):
    """Display results in text format"""
    print(f"Displaying {len(devices)} devices:")
    
    for device in devices:
        print(f"IP: {device['ip_str']}")
        print(f"Port: {device['port']}")
        print(f"Hostname: {', '.join(device.get('hostnames', []) or ['N/A'])}")
        print(f"Org: {device.get('org', 'N/A')}")
        print(f"ISP: {device.get('isp', 'N/A')}")
        print(f"OS: {device.get('os', 'N/A')}")
        print(f"Product: {device.get('product', 'N/A')}")
        print(f"Version: {device.get('version', 'N/A')}")
        print(f"Location: {device.get('location', {}).get('country_name', 'N/A')}, "
              f"{device.get('location', {}).get('city', 'N/A')}")
        print(f"Last Update: {device.get('timestamp', 'N/A')}")
        
        if 'data' in device:
            print(f"Banner: {device['data'][:200]}...")
            
        # Display vulnerabilities if available
        if show_vulns and device.get('_vulns'):
            print("Vulnerabilities:")
            for v in device['_vulns']:
                print(f"  - {v['id']} (Severity: {v['severity']}, Score: {v.get('score', 'N/A')})")
                print(f"    {v['description'][:100]}...")
                
        print("="*40)

def display_table_results(devices, show_vulns=False):
    """Display results in table format"""
    table_data = []
    for device in devices:
        vuln_count = len(device.get('_vulns', []))
        vuln_text = f"{vuln_count} found" if vuln_count > 0 else "None"
        
        row = [
            device['ip_str'],
            device['port'],
            device.get('org', 'N/A'),
            device.get('product', 'N/A'),
            device.get('location', {}).get('country_name', 'N/A'),
            vuln_text if show_vulns else "N/A"
        ]
        table_data.append(row)
    
    headers = ["IP", "Port", "Organization", "Product", "Country", "Vulnerabilities"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # If vulnerabilities were found and checked, display them separately
    if show_vulns:
        print("\nVulnerability Details:")
        for i, device in enumerate(devices):
            if device.get('_vulns'):
                print(f"\nDevice {i+1}: {device['ip_str']}:{device['port']}")
                vuln_data = []
                for v in device['_vulns']:
                    desc = v['description']
                    if len(desc) > 70:
                        desc = desc[:70] + "..."
                    vuln_data.append([v['id'], v.get('severity', 'N/A'), v.get('score', 'N/A'), desc])
                print(tabulate(vuln_data, headers=["CVE ID", "Severity", "Score", "Description"], tablefmt="grid"))

def export_to_csv(devices, output_file, include_vulns=False):
    """Export results to CSV file"""
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['ip', 'port', 'hostnames', 'org', 'isp', 'os', 'product', 'version',
                      'country', 'city', 'timestamp']
        
        if include_vulns:
            fieldnames.extend(['vuln_count', 'vuln_details'])
            
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for device in devices:
            row = {
                'ip': device['ip_str'],
                'port': device['port'],
                'hostnames': ','.join(device.get('hostnames', []) or []),
                'org': device.get('org', ''),
                'isp': device.get('isp', ''),
                'os': device.get('os', ''),
                'product': device.get('product', ''),
                'version': device.get('version', ''),
                'country': device.get('location', {}).get('country_name', ''),
                'city': device.get('location', {}).get('city', ''),
                'timestamp': device.get('timestamp', '')
            }
            
            if include_vulns:
                vulns = device.get('_vulns', [])
                row['vuln_count'] = len(vulns)
                
                # Compile vulnerability details into a single field
                vuln_details = []
                for v in vulns:
                    vuln_details.append(f"{v['id']}({v.get('severity', 'Unknown')})")
                row['vuln_details'] = ';'.join(vuln_details)
                
            writer.writerow(row)
            
        print(f"Results exported to {output_file}")

def export_to_json(devices, output_file):
    """Export results to JSON file"""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(devices, f, indent=2)
    print(f"Results exported to {output_file}")

def load_from_json(input_file):
    """Load device data from a JSON file"""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Handle case where the JSON might be a single device or other structure
        if isinstance(data, dict) and 'matches' in data:
            data = data['matches']
        elif isinstance(data, dict) and not 'ip_str' in data:
            data = []
        elif isinstance(data, dict):
            data = [data]
            
        return data
    except Exception as e:
        print(f"Error loading JSON data: {e}", file=sys.stderr)
        return []

def create_device_fingerprint(device):
    """Create a unique fingerprint for a device to track changes over time"""
    fingerprint = {
        'ip': device.get('ip_str', 'unknown'),
        'ports': device.get('port', 'unknown'),
        'product': device.get('product', 'unknown'),
        'version': device.get('version', 'unknown'),
        'banner': device.get('data', '')[:500] if device.get('data') else '',
        'timestamp': datetime.now().isoformat()
    }
    
    # Create a hash of the fingerprint for quick comparison
    fingerprint_str = json.dumps(fingerprint, sort_keys=True)
    fingerprint['hash'] = hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    return fingerprint

def test_device_credentials(device, credentials=None, timeout=3):
    """Test a device for default or weak credentials"""
    if not device.get('ip_str') or not device.get('port'):
        device['credential_test'] = {
            'status': 'skipped',
            'reason': 'No IP or port information available'
        }
        return device
    
    if not credentials:
        credentials = DEFAULT_CREDENTIALS
    
    host = device['ip_str']
    port = device['port']
    
    # Initialize credential test results
    device['credential_test'] = {
        'status': 'tested',
        'tested': len(credentials),
        'vulnerable': False,
        'working_credentials': []
    }
    
    # Determine protocol based on port
    protocol = None
    if port == 21:
        protocol = 'ftp'
    elif port == 23:
        protocol = 'telnet'
    elif port in [80, 8080, 8888, 443, 8443]:
        protocol = 'web'
    else:
        device['credential_test']['status'] = 'skipped'
        device['credential_test']['reason'] = f'Unsupported port: {port}'
        return device
    
    # Test each credential
    for cred in credentials:
        username = cred['username']
        password = cred.get('password', '')
        
        success = False
        if protocol == 'telnet':
            success = test_telnet_credentials(host, port, username, password, timeout)
        elif protocol == 'ftp':
            success = test_ftp_credentials(host, port, username, password, timeout)
        elif protocol == 'web':
            success = test_web_credentials(host, port, username, password, timeout)
            
        if success:
            device['credential_test']['vulnerable'] = True
            device['credential_test']['working_credentials'].append({
                'protocol': protocol,
                'username': username,
                'password': password
            })
    
    return device

def test_telnet_credentials(host, port, username, password, timeout=3):
    """Test Telnet credentials on a target device"""
    try:
        # Create an async function to handle telnet connection
        async def _telnet_connect():
            try:
                reader, writer = await telnetlib3.open_connection(host, port, timeout=timeout)
                
                # Read until login prompt
                response = await reader.read(1024)
                if "login:" in response:
                    writer.write(username + "\n")
                    
                    # Wait for password prompt
                    response = await reader.read(1024)
                    if "Password:" in response:
                        writer.write(password + "\n")
                        
                        # Check if login was successful
                        response = await reader.read(1024)
                        if "$" in response or b">" in response or b"#" in response:
                            writer.close()
                            return True
                
                writer.close()
                return False
            except Exception as e:
                logger.debug(f"Telnet connection error: {str(e)}")
                return False
        
        # Set up event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_telnet_connect())
            return result
        finally:
            loop.close()
            
    except Exception as e:
        logger.debug(f"Telnet credential test error: {str(e)}")
        return False

def test_ftp_credentials(host, port, username, password, timeout=3):
    """Test FTP credentials on a target device"""
    try:
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(host, port)
        ftp.login(username, password)
        ftp.quit()
        return True
    except Exception:
        return False

def test_web_credentials(host, port, username, password, timeout=3):
    """Test web form credentials"""
    # Future implementation for testing web forms
    logger.info(f"Web credential test not yet implemented for {host}:{port}")
    return False

def search_exploits(device):
    """Search for known exploits for a device"""
    # Create a copy to avoid modifying the original
    device = device.copy()
    
    if not device.get('product'):
        device['exploits'] = {
            'status': 'skipped',
            'reason': 'No product information available'
        }
        return device
    
    # Initialize exploits record
    device['exploits'] = {
        'status': 'checked',
        'count': 0,
        'items': []
    }
    
    product = device.get('product', '')
    version = device.get('version', '')
    
    try:
        # Construct query for exploit-db or other exploit sources
        query = product
        if version:
            query += f" {version}"
            
        # For demo purposes, we'll just search the NVD CVE database
        # In a real application, this would query exploit-db, Metasploit, etc.
        vulns = get_device_vulns(product, version)
        
        # Filter for vulnerabilities that might have exploits
        for vuln in vulns:
            # Check description for clues about exploitation
            desc = vuln.get('description', '').lower()
            if any(word in desc for word in ['exploit', 'remote code execution', 'rce', 'unauthenticated', 'code execution', 'command execution']):
                device['exploits']['items'].append({
                    'id': vuln.get('id', 'Unknown'),
                    'description': vuln.get('description', 'No description'),
                    'severity': vuln.get('severity', 'Unknown'),
                    'score': vuln.get('score', 0),
                    'likelihood': 'High' if 'exploit' in desc else 'Medium'
                })
        
        device['exploits']['count'] = len(device['exploits']['items'])
        
    except Exception as e:
        device['exploits'] = {
            'status': 'error',
            'reason': str(e)
        }
    
    return device

def check_ssl_tls_security(device):
    """Check for SSL/TLS vulnerabilities and weak cipher suites"""
    if not device.get('ip_str') or not device.get('port'):
        device['ssl_check'] = {
            'status': 'skipped',
            'reason': 'No IP or port information available'
        }
        return device
    
    host = device['ip_str']
    port = device['port']
    
    # Check if the port is likely to use SSL/TLS
    is_ssl_port = port in [443, 8443, 4443, 993, 995, 465, 636, 989, 990, 992, 993, 995]
    
    if not is_ssl_port and device.get('ssl', {}) is None:
        device['ssl_check'] = {
            'status': 'skipped',
            'reason': 'Not an SSL/TLS service'
        }
        return device
    
    # Store SSL check results
    device['ssl_check'] = {
        'status': 'checked',
        'supported_protocols': [],
        'weak_ciphers': [],
        'vulnerable': False,
        'certificate': {}
    }
    
    try:
        # Check SSL/TLS protocols
        protocols = [
            ssl.PROTOCOL_TLS,
            ssl.PROTOCOL_TLS_CLIENT
        ]
        
        for protocol in protocols:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            try:
                with socket.create_connection((host, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        # Get protocol version
                        version = ssock.version()
                        device['ssl_check']['supported_protocols'].append(version)
                        
                        # Check for weak protocol versions
                        if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            device['ssl_check']['vulnerable'] = True
                        
                        # Get cipher
                        cipher = ssock.cipher()
                        if cipher:
                            cipher_name = cipher[0]
                            
                            # Check for weak ciphers
                            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
                            if any(wc in cipher_name for wc in weak_ciphers):
                                device['ssl_check']['weak_ciphers'].append(cipher_name)
                                device['ssl_check']['vulnerable'] = True
                        
                        # Get certificate info
                        cert = ssock.getpeercert(binary_form=True)
                        if cert:
                            cert_hash = hashlib.sha1(cert).hexdigest()
                            device['ssl_check']['certificate']['sha1'] = cert_hash
                            
                            # Get certificate details (in binary form)
                            device['ssl_check']['certificate']['valid'] = True
                            
                            # Parse more certificate details here if needed
            except (socket.timeout, ssl.SSLError, ConnectionRefusedError):
                # This protocol is not supported
                pass
    except Exception as e:
        device['ssl_check'] = {
            'status': 'error',
            'reason': str(e)
        }
    
    return device

def filter_by_cvss_score(devices, min_score=None, severity=None):
    """Filter devices by CVSS score or severity level"""
    if not devices:
        return []
    
    if severity and severity.upper() in CVSS_THRESHOLDS:
        min_score = CVSS_THRESHOLDS[severity.upper()]
    
    if not min_score:
        return devices
    
    filtered_devices = []
    for device in devices:
        # Check if device has vulnerabilities
        vulns = device.get('_vulns', [])
        if not vulns:
            continue
        
        # Check if any vulnerability meets the criteria
        for vuln in vulns:
            if 'score' in vuln and vuln['score'] >= min_score:
                filtered_devices.append(device)
                break
    
    return filtered_devices

def track_device_history(device, history_db=None):
    """Track a device over time to detect changes"""
    if not history_db:
        # Default history database file
        history_db = HISTORY_DB_FILE
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(history_db), exist_ok=True)
    
    # Load existing history
    history = {}
    if os.path.exists(history_db):
        try:
            with open(history_db, 'r') as f:
                history = json.load(f)
        except Exception:
            # If the file is corrupted, start fresh
            history = {}
    
    # Create a device fingerprint
    device_fingerprint = create_device_fingerprint(device)
    
    # Use IP as a key for now (could be enhanced with more identifiers)
    device_key = device.get('ip_str', 'unknown')
    
    # Record observation
    timestamp = datetime.now().isoformat()
    observation = {
        'timestamp': timestamp,
        'fingerprint': device_fingerprint,
        'ports': device.get('port'),
        'product': device.get('product', 'unknown'),
        'version': device.get('version', 'unknown'),
        'vulnerabilities': len(device.get('_vulns', [])),
        'fingerprint_hash': device_fingerprint['hash']
    }
    
    # Initialize device history if this is a new device
    if device_key not in history:
        history[device_key] = {
            'first_seen': timestamp,
            'observations': [],
            'changes': []
        }
    
    # Get previous observation if available
    prev_observations = history[device_key]['observations']
    
    # Check for changes
    change_detected = False
    if prev_observations:
        last_obs = prev_observations[-1]
        
        # Compare fingerprint hashes
        if last_obs['fingerprint_hash'] != observation['fingerprint_hash']:
            change_detected = True
            
            # Record the change
            change = {
                'timestamp': timestamp,
                'previous_timestamp': last_obs['timestamp'],
                'previous_hash': last_obs['fingerprint_hash'],
                'current_hash': observation['fingerprint_hash'],
                'changed_fields': []
            }
            
            # Identify specific changes
            for field in ['ports', 'product', 'version', 'vulnerabilities']:
                if last_obs[field] != observation[field]:
                    change['changed_fields'].append({
                        'field': field,
                        'previous': last_obs[field],
                        'current': observation[field]
                    })
            
            history[device_key]['changes'].append(change)
    
    # Add observation to history
    history[device_key]['observations'].append(observation)
    
    # Update last_seen
    history[device_key]['last_seen'] = timestamp
    
    # Add history to device record
    device['history'] = {
        'first_seen': history[device_key]['first_seen'],
        'last_seen': timestamp,
        'change_count': len(history[device_key]['changes']),
        'observation_count': len(history[device_key]['observations']),
        'latest_change': history[device_key]['changes'][-1] if change_detected else None
    }
    
    # Save history
    try:
        with open(history_db, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"Error saving device history: {e}", file=sys.stderr)
    
    return device

def get_network_segments(devices):
    """Analyze network segments and identify segmentation issues"""
    segments = {}
    
    # Group devices by subnet
    for device in devices:
        ip = device.get('ip_str')
        if not ip:
            continue
        
        try:
            # Create subnet using CIDR notation (using /24 for simplicity)
            if '.' in ip:  # IPv4
                subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
            else:  # IPv6 - simplified
                subnet = ip + '/64'  # Using /64 for IPv6
                
            # Initialize subnet if not seen
            if subnet not in segments:
                segments[subnet] = {
                    'devices': [],
                    'device_types': set(),
                    'segmentation_issues': False,
                    'critical_devices': 0
                }
            
            # Add device to segment
            segments[subnet]['devices'].append({
                'ip': ip,
                'port': device.get('port'),
                'product': device.get('product', 'unknown'),
                'vulns': len(device.get('_vulns', []))
            })
            
            # Track device type
            if device.get('product'):
                segments[subnet]['device_types'].add(device.get('product'))
            
            # Check for critical devices (those with vulnerabilities)
            if device.get('_vulns'):
                segments[subnet]['critical_devices'] += 1
        except Exception:
            continue
    
    # Analyze segmentation issues
    for subnet, data in segments.items():
        # Check for mixed device types in same network
        if len(data['device_types']) > 3:  # Arbitrary threshold
            data['segmentation_issues'] = True
            data['recommendation'] = "Network contains many different device types. Consider segmentation."
        
        # Convert set to list for JSON serialization
        data['device_types'] = list(data['device_types'])
    
    return segments 

class InteractiveShell(cmd.Cmd):
    """Interactive shell for Shodan IoT device search"""
    intro = f"\n{BANNER}\nWelcome to BlackIce Interactive Shell!\nType 'help' or '?' to list commands, 'exit' to quit."
    prompt = "BlackIce> "
    last_results = []
    
    def __init__(self, api_key=None):
        super().__init__()
        self.api_key = api_key
        
        # Set color prompt if supported
        if sys.platform != 'win32':
            self.prompt = "\033[1;34mBlackIce>\033[0m "
    
    def do_search(self, arg):
        """
        Search for IoT devices using Shodan
        Usage: search [query] [--limit=n] [--country=code] [--port=n] [--check-vulns]
        
        Examples:
          search webcam
          search port:23 --limit=50 --country=US
          search router --check-vulns
          search template:webcams --country=DE --limit=20
        """
        if not SHODAN_AVAILABLE:
            print("Shodan API is not available. Install with: pip install shodan")
            return
            
        # Parse arguments
        args = arg.split()
        if not args:
            print("Please provide a search query.")
            return
            
        # Check for template use
        if args[0].startswith("template:"):
            template_name = args[0].split(":", 1)[1]
            if template_name in SEARCH_TEMPLATES:
                query = SEARCH_TEMPLATES[template_name]
                args = args[1:]  # Remove template arg
            else:
                print(f"Unknown template: {template_name}")
                print(f"Available templates: {', '.join(SEARCH_TEMPLATES.keys())}")
                return
        else:
            query = args[0]
            args = args[1:]  # Remove query arg
            
        # Parse options
        limit = 10
        country = None
        port = None
        check_vulns = False
        
        for arg in args:
            if arg.startswith("--limit="):
                try:
                    limit = int(arg.split("=")[1])
                except ValueError:
                    print("Invalid limit value. Using default.")
            elif arg.startswith("--country="):
                country = arg.split("=")[1]
            elif arg.startswith("--port="):
                try:
                    port = int(arg.split("=")[1])
                except ValueError:
                    print("Invalid port value. Ignoring port filter.")
            elif arg == "--check-vulns":
                check_vulns = True
                
        # Search for devices
        print(f"Searching for: {query}")
        devices = search_vulnerable_iot_devices(
            query, 
            limit=limit,
            output_format="table",
            country_filter=country,
            port_filter=port,
            check_vulns=check_vulns
        )
        
        # Store results for later use
        self.last_results = devices
    
    def do_shodan_info(self, arg):
        """Display information about your Shodan API key and usage"""
        if not SHODAN_AVAILABLE:
            print("Shodan API is not available. Install with: pip install shodan")
            return
            
        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            info = api.info()
            
            print("\n=== Shodan API Key Information ===")
            print(f"Query Credits: {info['query_credits']}")
            print(f"Scan Credits: {info['scan_credits']}")
            print(f"Plan: {info.get('plan', 'Unknown')}")
            print(f"HTTPS: {info.get('https', False)}")
            print(f"Unlocked: {info.get('unlocked', False)}")
            print("="*35)
        except Exception as e:
            print(f"Error getting Shodan info: {e}")
    
    def do_list_templates(self, arg):
        """List available search templates"""
        print("\n=== Available Search Templates ===")
        for name, query in SEARCH_TEMPLATES.items():
            print(f"{name}: {query}")
    
    def do_show(self, arg):
        """
        Show detailed information about a specific device from the last search
        Usage: show [index]
        """
        if not self.last_results:
            print("No results to show. Run a search first.")
            return
            
        try:
            index = int(arg) - 1  # Convert to 0-based index
            if index < 0 or index >= len(self.last_results):
                print(f"Invalid index. Please specify a number between 1 and {len(self.last_results)}.")
                return
                
            device = self.last_results[index]
            
            print("\n=== Device Details ===")
            print(f"IP: {device['ip_str']}")
            print(f"Port: {device['port']}")
            print(f"Hostname: {', '.join(device.get('hostnames', []) or ['N/A'])}")
            print(f"Organization: {device.get('org', 'N/A')}")
            print(f"ISP: {device.get('isp', 'N/A')}")
            print(f"Operating System: {device.get('os', 'N/A')}")
            print(f"Product: {device.get('product', 'N/A')}")
            print(f"Version: {device.get('version', 'N/A')}")
            print(f"Location: {device.get('location', {}).get('country_name', 'N/A')}, "
                  f"{device.get('location', {}).get('city', 'N/A')}")
            print(f"Last Update: {device.get('timestamp', 'N/A')}")
            
            # Show banner/data
            if 'data' in device:
                print("\n=== Banner Data ===")
                print(device['data'])
            
            # Show vulnerabilities if available
            if device.get('_vulns'):
                print("\n=== Vulnerabilities ===")
                for i, v in enumerate(device['_vulns']):
                    print(f"  {i+1}. {v['id']} (Severity: {v['severity']}, Score: {v.get('score', 'N/A')})")
                    print(f"     {v['description']}")
            
            # Show credential test results if available
            if device.get('credential_test'):
                print("\n=== Credential Test Results ===")
                cred_test = device['credential_test']
                print(f"Status: {cred_test['status']}")
                
                if cred_test.get('vulnerable'):
                    print("VULNERABLE to default credentials!")
                    for cred in cred_test.get('working_credentials', []):
                        print(f"  - Protocol: {cred['protocol']}, Username: {cred['username']}, Password: {cred['password']}")
            
            # Show exploit information if available
            if device.get('exploits'):
                print("\n=== Exploit Information ===")
                exploits = device['exploits']
                print(f"Status: {exploits['status']}")
                print(f"Found exploits: {exploits['count']}")
                
                for i, exploit in enumerate(exploits.get('items', [])):
                    print(f"  {i+1}. {exploit['id']} (Severity: {exploit['severity']}, Score: {exploit.get('score', 'N/A')})")
                    print(f"     {exploit['description']}")
                    print(f"     Exploitation likelihood: {exploit.get('likelihood', 'Unknown')}")
            
            # Show SSL/TLS check results if available
            if device.get('ssl_check'):
                print("\n=== SSL/TLS Security Check ===")
                ssl_check = device['ssl_check']
                print(f"Status: {ssl_check['status']}")
                
                if ssl_check.get('vulnerable'):
                    print("VULNERABLE to SSL/TLS issues!")
                    
                    if ssl_check.get('supported_protocols'):
                        print("Supported protocols:")
                        for protocol in ssl_check['supported_protocols']:
                            print(f"  - {protocol}")
                    
                    if ssl_check.get('weak_ciphers'):
                        print("Weak ciphers:")
                        for cipher in ssl_check['weak_ciphers']:
                            print(f"  - {cipher}")
            
            # Show history information if available
            if device.get('history'):
                print("\n=== Device History ===")
                history = device['history']
                print(f"First seen: {history['first_seen']}")
                print(f"Last seen: {history['last_seen']}")
                print(f"Observations: {history['observation_count']}")
                print(f"Changes detected: {history['change_count']}")
                
                if history.get('latest_change'):
                    print("\nLatest change:")
                    change = history['latest_change']
                    print(f"Time: {change['timestamp']}")
                    print(f"Previous time: {change['previous_timestamp']}")
                    
                    if change.get('changed_fields'):
                        print("Changed fields:")
                        for field in change['changed_fields']:
                            print(f"  - {field['field']}: {field['previous']} -> {field['current']}")
        except ValueError:
            print("Please specify a valid device index number.")
        except Exception as e:
            print(f"Error displaying device: {e}")
    
    def do_export(self, arg):
        """
        Export search results to a file
        Usage: export [format] [filename]
        
        Supported formats: csv, json
        Example: export csv results.csv
        """
        if not self.last_results:
            print("No results to export. Run a search first.")
            return
            
        args = arg.split()
        if len(args) < 2:
            print("Please specify both format and filename.")
            print("Usage: export [format] [filename]")
            return
            
        format_type = args[0].lower()
        filename = args[1]
        
        if format_type == "csv":
            export_to_csv(self.last_results, filename, include_vulns=True)
        elif format_type == "json":
            export_to_json(self.last_results, filename)
        else:
            print(f"Unsupported format: {format_type}")
            print("Supported formats: csv, json")
    
    def do_load(self, arg):
        """
        Load previous search results from a JSON file
        Usage: load [filename]
        
        Example: load results.json
        """
        if not arg:
            print("Please specify a file to load.")
            return
            
        try:
            devices = load_from_json(arg)
            if devices:
                self.last_results = devices
                print(f"Loaded {len(devices)} devices from {arg}")
                display_table_results(devices)
            else:
                print("No devices found in the file or file format is invalid.")
        except Exception as e:
            print(f"Error loading file: {e}")
    
    def do_visualize(self, arg):
        """
        Visualize the results of the last search with maps and charts
        Usage: visualize [output_dir]
        """
        if not FOLIUM_AVAILABLE or not NETWORK_AVAILABLE:
            print("Visualization modules are not available. Make sure you have installed the required packages:")
            print("pip install folium matplotlib pandas")
            return
            
        if not self.last_results:
            print("No results to visualize. Run a search first.")
            return
            
        output_dir = arg.strip() if arg else "blackice_output"
        
        try:
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate timestamp for filenames
            timestamp = int(time.time())
            
            # Create map
            print("Creating device location map...")
            map_file = os.path.join(output_dir, f"device_map_{timestamp}.html")
            create_map(self.last_results, map_file)
            
            # Create charts
            print("Creating device statistics charts...")
            chart_prefix = os.path.join(output_dir, f"device_charts_{timestamp}")
            chart_files = create_device_charts(self.last_results, chart_prefix)
            
            # Create network graph
            print("Creating device network graph...")
            graph_file = os.path.join(output_dir, f"network_graph_{timestamp}.png")
            create_network_graph(self.last_results, graph_file)
            
            # Generate HTML report with all visualizations
            print("Generating comprehensive HTML report...")
            report_file = os.path.join(output_dir, f"report_{timestamp}.html")
            generate_html_report(self.last_results, chart_files, map_file, report_file)
            
            # Show success message
            print(f"\nVisualization complete. All files saved to: {output_dir}")
            print(f"HTML Report: {report_file}")
            
            # Ask if user wants to open the report
            choice = input("Would you like to open the HTML report now? (yes/no): ")
            if choice.lower() in ['yes', 'y']:
                webbrowser.open(f"file://{os.path.abspath(report_file)}")
                
        except Exception as e:
            print(f"Error during visualization: {e}")
            import traceback
            traceback.print_exc()
    
    def do_map(self, arg):
        """
        Create a map of devices from the last search
        Usage: map [output_file]
        """
        if not FOLIUM_AVAILABLE:
            print("Folium is not available. Install with: pip install folium")
            return
            
        if not self.last_results:
            print("No results to map. Run a search first.")
            return
            
        output_file = arg.strip() if arg else None
        
        try:
            map_file = create_map(self.last_results, output_file)
            if map_file:
                print(f"Map created at: {map_file}")
        except Exception as e:
            print(f"Error creating map: {e}")
    
    def do_charts(self, arg):
        """
        Create charts to visualize device statistics
        Usage: charts [output_prefix]
        """
        if not NETWORK_AVAILABLE:
            print("Matplotlib is not available. Install with: pip install matplotlib")
            return
            
        if not self.last_results:
            print("No results to visualize. Run a search first.")
            return
            
        output_prefix = arg.strip() if arg else None
        
        try:
            create_device_charts(self.last_results, output_prefix)
        except Exception as e:
            print(f"Error creating charts: {e}")
    
    def do_network_graph(self, arg):
        """
        Create a network graph showing relationships between devices
        Usage: network_graph [output_file]
        """
        if not NETWORK_AVAILABLE:
            print("NetworkX is not available. Install with: pip install networkx matplotlib")
            return
            
        if not self.last_results:
            print("No results to analyze. Run a search first.")
            return
            
        output_file = arg.strip() if arg else "network_graph.png"
        
        try:
            graph_file = create_network_graph(self.last_results, output_file)
            if graph_file:
                print(f"Network graph created and saved to: {graph_file}")
        except Exception as e:
            print(f"Error creating network graph: {e}")
    
    def do_test_credentials(self, arg):
        """
        Test devices for default or weak credentials
        Usage: test_credentials [--limit=N] [--parallel]
        
        WARNING: Only use on systems you have permission to test!
        """
        if not self.last_results:
            print("No devices to test. Run a search first.")
            return
        
        # Parse arguments
        limit = None
        use_parallel = '--parallel' in arg
        
        if '--limit=' in arg:
            try:
                limit = int(re.search(r'--limit=(\d+)', arg).group(1))
            except Exception:
                print("Invalid limit value.")
                return
        
        # Show legal disclaimer and get confirmation
        if COLORAMA_AVAILABLE:
            print(f"{Fore.RED}{LEGAL_DISCLAIMER}{Style.RESET_ALL}")
        else:
            print(LEGAL_DISCLAIMER)
            
        confirm = input("Do you confirm that you have permission to test these systems? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Credential testing aborted.")
            return
        
        # Get devices to test
        devices = self.last_results
        if limit:
            devices = devices[:limit]
            
        print(f"Testing {len(devices)} devices for default credentials...")
        
        # Process them, with or without parallel execution
        if use_parallel:
            # Define the test function for parallel execution
            def test_device(device):
                host = device.get('ip_str')
                port = device.get('port')
                product = device.get('product', '')
                
                # Determine protocol based on port/banner
                protocol = 'http'
                if port == 22:
                    protocol = 'ssh'
                elif port == 23:
                    protocol = 'telnet'
                elif port == 21:
                    protocol = 'ftp'
                elif port == 161:
                    protocol = 'snmp'
                elif 'HTTP' in device.get('data', ''):
                    protocol = 'http'
                    
                # Test the device
                result = test_default_credentials(host, port, protocol, product)
                
                # Add results to device
                if result:
                    device['credential_test'] = {
                        'status': 'tested',
                        'tested_count': result['tested'],
                        'vulnerable': result['successful'] > 0,
                        'working_credentials': result['credentials']
                    }
                
                return device
            
            # Execute in parallel with progress bar
            self.last_results = parallel_execution(
                devices,
                test_device,
                max_workers=MAX_PARALLEL_SCANS,
                desc="Testing credentials"
            )
        else:
            # Sequential processing with progress bar
            for i, device in enumerate(devices):
                if TQDM_AVAILABLE:
                    # Progress indicator if available
                    with tqdm(total=1, desc=f"Device {i+1}/{len(devices)}: {device.get('ip_str')}:{device.get('port')}") as pbar:
                        host = device.get('ip_str')
                        port = device.get('port')
                        product = device.get('product', '')
                        
                        # Determine protocol based on port/banner
                        protocol = 'http'
                        if port == 22:
                            protocol = 'ssh'
                        elif port == 23:
                            protocol = 'telnet'
                        elif port == 21:
                            protocol = 'ftp'
                        elif port == 161:
                            protocol = 'snmp'
                        elif 'HTTP' in device.get('data', ''):
                            protocol = 'http'
                            
                        # Test the device
                        result = test_default_credentials(host, port, protocol, product)
                        
                        # Add results to device
                        if result:
                            device['credential_test'] = {
                                'status': 'tested',
                                'tested_count': result['tested'],
                                'vulnerable': result['successful'] > 0,
                                'working_credentials': result['credentials']
                            }
                            
                        pbar.update(1)
                else:
                    # Simple progress output
                    print(f"Testing device {i+1}/{len(devices)}: {device.get('ip_str')}:{device.get('port')}")
                    host = device.get('ip_str')
                    port = device.get('port')
                    product = device.get('product', '')
                    
                    # Determine protocol based on port/banner
                    protocol = 'http'
                    if port == 22:
                        protocol = 'ssh'
                    elif port == 23:
                        protocol = 'telnet'
                    elif port == 21:
                        protocol = 'ftp'
                    elif port == 161:
                        protocol = 'snmp'
                    elif 'HTTP' in device.get('data', ''):
                        protocol = 'http'
                        
                    # Test the device
                    result = test_default_credentials(host, port, protocol, product)
                    
                    # Add results to device
                    if result:
                        device['credential_test'] = {
                            'status': 'tested',
                            'tested_count': result['tested'],
                            'vulnerable': result['successful'] > 0,
                            'working_credentials': result['credentials']
                        }
        
        # Count vulnerable devices
        vulnerable = sum(1 for d in self.last_results if d.get('credential_test', {}).get('vulnerable', False))
        
        # Display results
        if COLORAMA_AVAILABLE and vulnerable > 0:
            print(f"{Fore.RED}Found {vulnerable} device(s) vulnerable to default credentials!{Style.RESET_ALL}")
        else:
            print(f"Found {vulnerable} device(s) vulnerable to default credentials.")
            
        if vulnerable > 0:
            print("\nVulnerable devices:")
            for device in self.last_results:
                if device.get('credential_test', {}).get('vulnerable', False):
                    creds = device.get('credential_test', {}).get('working_credentials', [])
                    if COLORAMA_AVAILABLE:
                        print(f"{Fore.YELLOW}{device.get('ip_str')}:{device.get('port')} - {device.get('product', 'Unknown')}{Style.RESET_ALL}")
                        for cred in creds:
                            print(f"  {Fore.RED}Username: {cred.get('username')}, Password: {cred.get('password')}{Style.RESET_ALL}")
                    else:
                        print(f"{device.get('ip_str')}:{device.get('port')} - {device.get('product', 'Unknown')}")
                        for cred in creds:
                            print(f"  Username: {cred.get('username')}, Password: {cred.get('password')}")
                            
        # Reminder about legal usage
        if vulnerable > 0:
            if COLORAMA_AVAILABLE:
                print(f"\n{Fore.RED}IMPORTANT: This information should only be used for authorized security testing!{Style.RESET_ALL}")
            else:
                print("\nIMPORTANT: This information should only be used for authorized security testing!")
    
    def do_find_exploits(self, arg):
        """
        Search for known exploits for discovered devices
        Usage: find_exploits [--limit=N] [--parallel] [--update]
        """
        if not self.last_results:
            print("No devices to analyze. Run a search first.")
            return
        
        
        # Parse limit argument
        limit = None
        if '--limit=' in arg:
            try:
                limit = int(re.search(r'--limit=(\d+)', arg).group(1))
            except Exception:
                print("Invalid limit value.")
                return
        
        # Get devices to check
        devices = self.last_results
        if limit:
            devices = devices[:limit]
        
        # Search for exploits
        print(f"Searching for exploits for {len(devices)} devices...")
        for i, device in enumerate(devices):
            print(f"Checking device {i+1}/{len(devices)}: {device.get('ip_str')}:{device.get('port')}")
            device = search_exploits(device)
        
        # Count devices with exploits
        with_exploits = sum(1 for d in devices if d.get('exploits', {}).get('count', 0) > 0)
        print(f"Found exploits for {with_exploits} device(s).")
        
        # Update last results
        self.last_results = devices
    
    def do_check_ssl(self, arg):
        """
        Check devices for SSL/TLS vulnerabilities
        Usage: check_ssl [--limit=N] [--parallel]
        """
        if not self.last_results:
            print("No devices to test. Run a search first.")
            return
        
        # Parse arguments
        limit = None
        use_parallel = '--parallel' in arg
        
        if '--limit=' in arg:
            try:
                limit = int(re.search(r'--limit=(\d+)', arg).group(1))
            except Exception:
                print("Invalid limit value.")
                return
        
        # Get devices to check
        devices = self.last_results
        if limit:
            devices = devices[:limit]
        
        print(f"Checking {len(devices)} devices for SSL/TLS vulnerabilities...")
        
        # Process them, with or without parallel execution
        if use_parallel:
            # Define the test function for parallel execution
            def check_device_ssl(device):
                host = device.get('ip_str')
                port = device.get('port')
                
                # Check SSL/TLS
                result = check_ssl_security(host, port)
                
                # Add results to device
                if result:
                    device['ssl_check'] = {
                        'status': 'checked',
                        'supports_ssl': result['supports_ssl'],
                        'vulnerable': len(result['issues']) > 0,
                        'grade': result['grade'],
                        'issues': result['issues'],
                        'protocol': result.get('protocol', 'Unknown'),
                        'cert_info': result.get('cert_info', {})
                    }
                
                return device
            
            # Execute in parallel with progress bar
            self.last_results = parallel_execution(
                devices,
                check_device_ssl,
                max_workers=MAX_PARALLEL_SCANS,
                desc="Checking SSL/TLS"
            )
        else:
            # Sequential processing with progress bar
            for i, device in enumerate(devices):
                if TQDM_AVAILABLE:
                    # Progress indicator if available
                    with tqdm(total=1, desc=f"Device {i+1}/{len(devices)}: {device.get('ip_str')}:{device.get('port')}") as pbar:
                        host = device.get('ip_str')
                        port = device.get('port')
                        
                        # Check SSL/TLS
                        result = check_ssl_security(host, port)
                        
                        # Add results to device
                        if result:
                            device['ssl_check'] = {
                                'status': 'checked',
                                'supports_ssl': result['supports_ssl'],
                                'vulnerable': len(result['issues']) > 0,
                                'grade': result['grade'],
                                'issues': result['issues'],
                                'protocol': result.get('protocol', 'Unknown'),
                                'cert_info': result.get('cert_info', {})
                            }
                            
                        pbar.update(1)
                else:
                    # Simple progress output
                    print(f"Checking device {i+1}/{len(devices)}: {device.get('ip_str')}:{device.get('port')}")
                    host = device.get('ip_str')
                    port = device.get('port')
                    
                    # Check SSL/TLS
                    result = check_ssl_security(host, port)
                    
                    # Add results to device
                    if result:
                        device['ssl_check'] = {
                            'status': 'checked',
                            'supports_ssl': result['supports_ssl'],
                            'vulnerable': len(result['issues']) > 0,
                            'grade': result['grade'],
                            'issues': result['issues'],
                            'protocol': result.get('protocol', 'Unknown'),
                            'cert_info': result.get('cert_info', {})
                        }
        
        # Count devices supporting SSL and devices with issues
        supports_ssl = sum(1 for d in self.last_results if d.get('ssl_check', {}).get('supports_ssl', False))
        vulnerable = sum(1 for d in self.last_results if d.get('ssl_check', {}).get('vulnerable', False))
        
        # Display results summary
        print(f"\nSSL/TLS Vulnerability Check Results:")
        print(f"- {supports_ssl} device(s) support SSL/TLS")
        
        if COLORAMA_AVAILABLE and vulnerable > 0:
            print(f"- {Fore.RED}{vulnerable} device(s) have SSL/TLS vulnerabilities{Style.RESET_ALL}")
        else:
            print(f"- {vulnerable} device(s) have SSL/TLS vulnerabilities")
            
        # Display security grade distribution
        grades = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0, 'Unknown': 0}
        for device in self.last_results:
            grade = device.get('ssl_check', {}).get('grade', 'Unknown')
            grades[grade] += 1
            
        print("\nSecurity Grade Distribution:")
        for grade, count in grades.items():
            if count > 0:
                if COLORAMA_AVAILABLE:
                    if grade == 'A':
                        print(f"  {Fore.GREEN}Grade {grade}: {count} device(s){Style.RESET_ALL}")
                    elif grade == 'B':
                        print(f"  {Fore.CYAN}Grade {grade}: {count} device(s){Style.RESET_ALL}")
                    elif grade == 'C':
                        print(f"  {Fore.YELLOW}Grade {grade}: {count} device(s){Style.RESET_ALL}")
                    elif grade == 'D' or grade == 'F':
                        print(f"  {Fore.RED}Grade {grade}: {count} device(s){Style.RESET_ALL}")
                    else:
                        print(f"  Grade {grade}: {count} device(s)")
                else:
                    print(f"  Grade {grade}: {count} device(s)")
                    
        # Show top issues
        if vulnerable > 0:
            issue_count = {}
            for device in self.last_results:
                for issue in device.get('ssl_check', {}).get('issues', []):
                    if issue not in issue_count:
                        issue_count[issue] = 0
                    issue_count[issue] += 1
                    
            if issue_count:
                print("\nCommon SSL/TLS Issues:")
                for issue, count in sorted(issue_count.items(), key=lambda x: x[1], reverse=True):
                    if COLORAMA_AVAILABLE:
                        print(f"  {Fore.RED}{issue}: {count} device(s){Style.RESET_ALL}")
                    else:
                        print(f"  {issue}: {count} device(s)")
    
    def do_track_history(self, arg):
        """
        Track device history over time
        Usage: track_history [--limit=N] [--parallel]
        """
        if not self.last_results:
            print("No devices to track. Run a search first.")
            return
        
        # Parse arguments
        limit = None
        use_parallel = '--parallel' in arg
        
        if '--limit=' in arg:
            try:
                limit = int(re.search(r'--limit=(\d+)', arg).group(1))
            except Exception:
                print("Invalid limit value.")
                return
        
        # Get devices to check
        devices = self.last_results
        if limit:
            devices = devices[:limit]
        
        # Initialize history database
        try:
            if os.path.exists(HISTORY_DB_FILE):
                with open(HISTORY_DB_FILE, 'r') as f:
                    history_db = json.load(f)
            else:
                history_db = {}
        except Exception as e:
            print(f"Error loading history database: {e}")
            history_db = {}
        
        print(f"Tracking history for {len(devices)} devices...")
        
        # Process them, with or without parallel execution
        if use_parallel:
            # Define the tracking function for parallel execution
            def track_device(device):
                result = check_device_history(device, history_db)
                
                # Add results to device
                if result:
                    device['history'] = {
                        'first_seen': result['first_seen'],
                        'last_seen': result['last_seen'],
                        'change_count': len(result['changes']),
                        'changes': result['changes'],
                        'snapshot_count': len(result['snapshots'])
                    }
                
                return device
            
            # Execute in parallel with progress bar
            self.last_results = parallel_execution(
                devices,
                track_device,
                max_workers=MAX_PARALLEL_SCANS,
                desc="Tracking history"
            )
        else:
            # Sequential processing with progress bar
            for i, device in enumerate(devices):
                if TQDM_AVAILABLE:
                    # Progress indicator if available
                    with tqdm(total=1, desc=f"Device {i+1}/{len(devices)}: {device.get('ip_str')}:{device.get('port')}") as pbar:
                        result = check_device_history(device, history_db)
                        
                        # Add results to device
                        if result:
                            device['history'] = {
                                'first_seen': result['first_seen'],
                                'last_seen': result['last_seen'],
                                'change_count': len(result['changes']),
                                'changes': result['changes'],
                                'snapshot_count': len(result['snapshots'])
                            }
                            
                        pbar.update(1)
                else:
                    # Simple progress output
                    print(f"Processing device {i+1}/{len(devices)}: {device.get('ip_str')}:{device.get('port')}")
                    result = check_device_history(device, history_db)
                    
                    # Add results to device
                    if result:
                        device['history'] = {
                            'first_seen': result['first_seen'],
                            'last_seen': result['last_seen'],
                            'change_count': len(result['changes']),
                            'changes': result['changes'],
                            'snapshot_count': len(result['snapshots'])
                        }
        
        # Count devices with changes
        with_changes = sum(1 for d in self.last_results if d.get('history', {}).get('change_count', 0) > 0)
        
        # Display results
        print(f"\nHistory Tracking Results:")
        
        # Display first-seen statistics
        now = int(time.time())
        age_groups = {
            'New (< 1 day)': 0,
            'Recent (1-7 days)': 0,
            'Week+ (7-30 days)': 0,
            'Month+ (30-90 days)': 0,
            'Old (90+ days)': 0
        }
        
        for device in self.last_results:
            if 'history' in device:
                first_seen = device['history'].get('first_seen', now)
                age_days = (now - first_seen) / (60 * 60 * 24)
                
                if age_days < 1:
                    age_groups['New (< 1 day)'] += 1
                elif age_days < 7:
                    age_groups['Recent (1-7 days)'] += 1
                elif age_days < 30:
                    age_groups['Week+ (7-30 days)'] += 1
                elif age_days < 90:
                    age_groups['Month+ (30-90 days)'] += 1
                else:
                    age_groups['Old (90+ days)'] += 1
        
        print("\nDevice Age Distribution:")
        for age, count in age_groups.items():
            if count > 0:
                if COLORAMA_AVAILABLE:
                    if age.startswith('New'):
                        print(f"  {Fore.CYAN}{age}: {count} device(s){Style.RESET_ALL}")
                    elif age.startswith('Old'):
                        print(f"  {Fore.YELLOW}{age}: {count} device(s){Style.RESET_ALL}")
                    else:
                        print(f"  {age}: {count} device(s)")
                else:
                    print(f"  {age}: {count} device(s)")
        
        # Show devices with changes
        if with_changes > 0:
            if COLORAMA_AVAILABLE:
                print(f"\n{Fore.YELLOW}Found {with_changes} device(s) with historical changes{Style.RESET_ALL}")
            else:
                print(f"\nFound {with_changes} device(s) with historical changes")
                
            print("\nRecent Changes:")
            for device in self.last_results:
                changes = device.get('history', {}).get('changes', [])
                if changes:
                    if COLORAMA_AVAILABLE:
                        print(f"{Fore.YELLOW}{device.get('ip_str')}:{device.get('port')} - "
                              f"{device.get('product', 'Unknown')}{Style.RESET_ALL}")
                    else:
                        print(f"{device.get('ip_str')}:{device.get('port')} - "
                              f"{device.get('product', 'Unknown')}")
                    
                    for change in changes:
                        change_time = datetime.datetime.fromtimestamp(change.get('timestamp', 0))
                        field = change.get('field', 'unknown')
                        old = change.get('old', '')
                        new = change.get('new', '')
                        
                        if COLORAMA_AVAILABLE:
                            print(f"  {Fore.CYAN}{change_time.strftime('%Y-%m-%d')}: {field} changed "
                                  f"from {Fore.RED}{old}{Fore.CYAN} to {Fore.GREEN}{new}{Style.RESET_ALL}")
                        else:
                            print(f"  {change_time.strftime('%Y-%m-%d')}: {field} changed from {old} to {new}")
        else:
            print("\nNo historical changes detected in any devices.")
            
        # Display security implications
        if with_changes > 0:
            print("\nSecurity Implications:")
            print("- Device changes may indicate firmware updates, reconfigurations, or compromises")
            print("- Sudden changes to services or versions should be investigated")
            print("- Regular monitoring helps identify unauthorized changes")
    
    def do_filter_cvss(self, arg):
        """
        Filter results based on CVSS vulnerability scores
        Usage: filter_cvss [severity|score]
        
        Examples:
          filter_cvss HIGH         # Filter devices with HIGH severity vulnerabilities
          filter_cvss 7.5          # Filter devices with CVSS score >= 7.5
        """
        if not self.last_results:
            print("No results to filter. Run a search first.")
            return
        
        if not arg:
            print("Please specify a severity level or minimum CVSS score.")
            print("Severity levels: LOW, MEDIUM, HIGH, CRITICAL")
            print("Example: filter_cvss HIGH")
            print("Example: filter_cvss 7.5")
            return
        
        original_count = len(self.last_results)
        
        # Check if it's a severity string or score
        if arg.upper() in CVSS_THRESHOLDS:
            self.last_results = filter_by_cvss_score(self.last_results, severity=arg.upper())
        else:
            try:
                min_score = float(arg)
                self.last_results = filter_by_cvss_score(self.last_results, min_score=min_score)
            except ValueError:
                print(f"Invalid CVSS filter value: {arg}")
                print("Please use a severity level (LOW, MEDIUM, HIGH, CRITICAL) or a numeric score.")
                return
        
        print(f"Filtered {original_count} devices to {len(self.last_results)} based on CVSS criteria.")
        
        if self.last_results:
            display_table_results(self.last_results)
        else:
            print("No devices match the CVSS filter criteria.")
    
    def do_segment_analysis(self, arg):
        """
        Analyze network segmentation and identify issues
        Usage: segment_analysis [--detailed]
        """
        if not self.last_results:
            print("No results to analyze. Run a search first.")
            return
        
        # Parse arguments
        show_detailed = '--detailed' in arg
        
        # Analyze network segments
        segments = analyze_network_segments(self.last_results)
        
        # Display analysis
        print("\n=== Network Segmentation Analysis ===")
        print(f"Identified {len(segments)} network segments")
        
        # Count segments by risk level
        risk_levels = {'High': 0, 'Medium': 0, 'Low': 0}
        for segment in segments:
            risk_level = segment.get('risk_level', 'Low')
            risk_levels[risk_level] += 1
        
        # Display risk level distribution
        print("\nRisk Level Distribution:")
        for level, count in risk_levels.items():
            if count > 0:
                if COLORAMA_AVAILABLE:
                    if level == 'High':
                        print(f"  {Fore.RED}{level} Risk: {count} segment(s){Style.RESET_ALL}")
                    elif level == 'Medium':
                        print(f"  {Fore.YELLOW}{level} Risk: {count} segment(s){Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.GREEN}{level} Risk: {count} segment(s){Style.RESET_ALL}")
                else:
                    print(f"  {level} Risk: {count} segment(s)")
        
        # Show details for segments with high/medium risk
        high_risk_segments = [s for s in segments if s.get('risk_level') in ['High', 'Medium']]
        if high_risk_segments:
            if COLORAMA_AVAILABLE:
                print(f"\n{Fore.YELLOW}Segments with High/Medium Risk:{Style.RESET_ALL}")
            else:
                print("\nSegments with High/Medium Risk:")
                
            for segment in high_risk_segments:
                network = segment.get('network', 'Unknown')
                risk_level = segment.get('risk_level', 'Low')
                device_count = segment.get('device_count', 0)
                has_sensitive = segment.get('has_sensitive_devices', False)
                has_mixed = segment.get('has_mixed_devices', False)
                
                if COLORAMA_AVAILABLE:
                    color = Fore.RED if risk_level == 'High' else Fore.YELLOW
                    print(f"\n{color}Network: {network}{Style.RESET_ALL}")
                    print(f"  Risk Level: {color}{risk_level}{Style.RESET_ALL}")
                    print(f"  Devices: {device_count}")
                    print(f"  Contains Sensitive Devices: {Fore.RED if has_sensitive else Fore.GREEN}{has_sensitive}{Style.RESET_ALL}")
                    print(f"  Mixed Device Types: {Fore.RED if has_mixed else Fore.GREEN}{has_mixed}{Style.RESET_ALL}")
                else:
                    print(f"\nNetwork: {network}")
                    print(f"  Risk Level: {risk_level}")
                    print(f"  Devices: {device_count}")
                    print(f"  Contains Sensitive Devices: {has_sensitive}")
                    print(f"  Mixed Device Types: {has_mixed}")
                
                # Device types
                device_types = segment.get('device_types', {})
                if device_types:
                    print("  Device Types:")
                    for device_type, count in sorted(device_types.items(), key=lambda x: x[1], reverse=True):
                        print(f"    - {device_type}: {count}")
                
                # Recommendations
                recommendations = segment.get('recommendations', [])
                if recommendations:
                    if COLORAMA_AVAILABLE:
                        print(f"  {Fore.CYAN}Recommendations:{Style.RESET_ALL}")
                        for rec in recommendations:
                            print(f"    {Fore.CYAN}* {rec}{Style.RESET_ALL}")
                    else:
                        print("  Recommendations:")
                        for rec in recommendations:
                            print(f"    * {rec}")
        
        # Show low risk segments if detailed view requested
        if show_detailed:
            low_risk_segments = [s for s in segments if s.get('risk_level') == 'Low']
            if low_risk_segments:
                print("\nLow Risk Segments:")
                for segment in low_risk_segments:
                    network = segment.get('network', 'Unknown')
                    device_count = segment.get('device_count', 0)
                    
                    if COLORAMA_AVAILABLE:
                        print(f"{Fore.GREEN}Network: {network} ({device_count} devices){Style.RESET_ALL}")
                    else:
                        print(f"Network: {network} ({device_count} devices)")
        
        # Add segment info to devices
        for device in self.last_results:
            ip = device.get('ip_str')
            if not ip:
                continue
                
            # Try to find the device's segment
            for segment in segments:
                segment_network = segment.get('network', '')
                # Simple check for IPv4
                if segment_network and ip.startswith(segment_network.split('.')[0]):
                    device['network_segment'] = {
                        'network': segment.get('network', ''),
                        'risk_level': segment.get('risk_level', 'Low'),
                        'device_count': segment.get('device_count', 0),
                        'has_sensitive_devices': segment.get('has_sensitive_devices', False),
                        'has_mixed_devices': segment.get('has_mixed_devices', False),
                        'recommendations': segment.get('recommendations', [])
                    }
                    break
        
        # Overall recommendations
        print("\nOverall Network Security Recommendations:")
        if risk_levels['High'] > 0:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}* PRIORITY: Address high-risk segments immediately{Style.RESET_ALL}")
            else:
                print("* PRIORITY: Address high-risk segments immediately")
                
        if any(s.get('has_mixed_devices', False) for s in segments):
            print("* Separate sensitive and non-sensitive devices into different network segments")
            
        if any(s.get('device_count', 0) > 20 for s in segments):
            print("* Break up large network segments into smaller subnets")
            
        if len(segments) < 3 and len(self.last_results) > 10:
            print("* Implement more network segmentation to reduce attack surface")
            
        print("* Regularly audit network segments for unauthorized devices")
        print("* Consider implementing VLANs for better network isolation")
        
        # Final statistics
        print(f"\nTotal devices analyzed: {len(self.last_results)}")
        print(f"Total network segments: {len(segments)}")
        sensitive_devices = sum(1 for d in self.last_results if is_sensitive_device(d))
        print(f"Sensitive devices: {sensitive_devices} ({sensitive_devices/len(self.last_results)*100:.1f}%)")
        print(f"Segments with issues: {risk_levels['High'] + risk_levels['Medium']}")
        
        # Save results to file option
        if high_risk_segments:
            choice = input("\nWould you like to save the segmentation analysis to a file? (yes/no): ")
            if choice.lower() in ['yes', 'y']:
                filename = f"network_segmentation_{int(time.time())}.json"
                try:
                    with open(filename, 'w') as f:
                        json.dump({
                            'segments': segments,
                            'analysis_time': int(time.time()),
                            'total_devices': len(self.last_results),
                            'risk_levels': risk_levels
                        }, f, indent=2)
                    print(f"Analysis saved to {filename}")
                except Exception as e:
                    print(f"Error saving analysis: {e}")
    
    def do_fingerprint(self, arg):
        """
        Fingerprint devices using Nmap to get detailed information
        Usage: fingerprint [--limit=N] [--parallel] [--passive]
        
        WARNING: Active scanning may be detected by security systems!
                 Use --passive for a more stealthy approach.
        """
        if not self.last_results:
            print("No devices to fingerprint. Run a search first.")
            return
        
        if not NMAP_AVAILABLE:
            print("Nmap Python library not available. Install with: pip install python-nmap")
            return
        
        # Parse arguments
        limit = None
        use_parallel = '--parallel' in arg
        passive_mode = '--passive' in arg or PASSIVE_MODE
        
        if '--limit=' in arg:
            try:
                limit = int(re.search(r'--limit=(\d+)', arg).group(1))
            except Exception:
                print("Invalid limit value.")
                return
        
        # Get devices to fingerprint
        devices = self.last_results
        if limit:
            devices = devices[:limit]
        
        # Display warning for active scanning
        if not passive_mode:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}WARNING: Active scanning may be detected by security systems!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Use --passive for a more stealthy approach.{Style.RESET_ALL}")
            else:
                print("WARNING: Active scanning may be detected by security systems!")
                print("Use --passive for a more stealthy approach.")
                
            confirm = input("Do you want to continue with active scanning? (yes/no): ")
            if confirm.lower() != 'yes':
                print("Fingerprinting aborted.")
                return
        else:
            print("Using passive fingerprinting mode (limited information but stealthier)")
        
        print(f"Fingerprinting {len(devices)} devices...")
        
        # Process them, with or without parallel execution
        if use_parallel:
            # Define the fingerprint function for parallel execution
            def fingerprint_device(device):
                host = device.get('ip_str')
                port = device.get('port')
                
                # Fingerprint the device
                result = fingerprint_device_with_nmap(host, port, passive=passive_mode)
                
                # Add results to device
                if result:
                    device['fingerprint'] = {
                        'status': 'complete',
                        'os': result.get('os', []),
                        'services': result.get('services', {}),
                        'ports': result.get('ports', {}),
                        'scripts': result.get('scripts', {})
                    }
                else:
                    device['fingerprint'] = {
                        'status': 'failed'
                    }
                
                return device
            
            # Execute in parallel with progress bar
            self.last_results = parallel_execution(
                devices,
                fingerprint_device,
                max_workers=MAX_PARALLEL_SCANS,
                desc="Fingerprinting devices"
            )
        else:
            # Sequential processing with progress bar
            for i, device in enumerate(devices):
                if TQDM_AVAILABLE:
                    # Progress indicator if available
                    with tqdm(total=1, desc=f"Device {i+1}/{len(devices)}: {device.get('ip_str')}:{device.get('port')}") as pbar:
                        host = device.get('ip_str')
                        port = device.get('port')
                        
                        # Fingerprint the device
                        result = fingerprint_device_with_nmap(host, port, passive=passive_mode)
                        
                        # Add results to device
                        if result:
                            device['fingerprint'] = {
                                'status': 'complete',
                                'os': result.get('os', []),
                                'services': result.get('services', {}),
                                'ports': result.get('ports', {}),
                                'scripts': result.get('scripts', {})
                            }
                        else:
                            device['fingerprint'] = {
                                'status': 'failed'
                            }
                            
                        pbar.update(1)
                else:
                    # Simple progress output
                    print(f"Fingerprinting device {i+1}/{len(devices)}: {device.get('ip_str')}:{device.get('port')}")
                    host = device.get('ip_str')
                    port = device.get('port')
                    
                    # Fingerprint the device
                    result = fingerprint_device_with_nmap(host, port, passive=passive_mode)
                    
                    # Add results to device
                    if result:
                        device['fingerprint'] = {
                            'status': 'complete',
                            'os': result.get('os', []),
                            'services': result.get('services', {}),
                            'ports': result.get('ports', {}),
                            'scripts': result.get('scripts', {})
                        }
                    else:
                        device['fingerprint'] = {
                            'status': 'failed'
                        }
        
        # Count successfully fingerprinted devices
        successful = sum(1 for d in self.last_results if d.get('fingerprint', {}).get('status') == 'complete')
        
        # Display results
        print(f"\nFingerprinting Results:")
        print(f"Successfully fingerprinted: {successful}/{len(devices)} devices")
        
        # OS statistics
        os_count = {}
        for device in self.last_results:
            for os_match in device.get('fingerprint', {}).get('os', []):
                os_name = os_match.get('name', 'Unknown')
                if os_name not in os_count:
                    os_count[os_name] = 0
                os_count[os_name] += 1
        
        if os_count:
            print("\nOperating System Distribution:")
            for os_name, count in sorted(os_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                if COLORAMA_AVAILABLE:
                    print(f"  {Fore.CYAN}{os_name}: {count} device(s){Style.RESET_ALL}")
                else:
                    print(f"  {os_name}: {count} device(s)")
        
        # Additional ports/services discovered
        additional_ports = set()
        for device in self.last_results:
            ports = device.get('fingerprint', {}).get('ports', {})
            for port_num in ports:
                if int(port_num) != device.get('port'):
                    additional_ports.add(int(port_num))
        
        if additional_ports:
            if COLORAMA_AVAILABLE:
                print(f"\n{Fore.YELLOW}Additional Ports Discovered:{Style.RESET_ALL}")
            else:
                print("\nAdditional Ports Discovered:")
                
            # Get top 15 most common additional ports
            additional_ports = sorted(additional_ports)[:15]
            print(f"  {', '.join(map(str, additional_ports))}")
            
            print("\nThis indicates these devices may have more services than initially detected.")
            
        # Show any vulnerabilities identified by nmap scripts
        vulns_found = False
        for device in self.last_results:
            scripts = device.get('fingerprint', {}).get('scripts', {})
            for port, script_results in scripts.items():
                for script_name, result in script_results.items():
                    if 'vuln' in script_name.lower() and result:
                        if not vulns_found:
                            if COLORAMA_AVAILABLE:
                                print(f"\n{Fore.RED}Vulnerabilities Detected by Nmap Scripts:{Style.RESET_ALL}")
                            else:
                                print("\nVulnerabilities Detected by Nmap Scripts:")
                            vulns_found = True
                            
                        if COLORAMA_AVAILABLE:
                            print(f"{Fore.RED}{device.get('ip_str')}:{port} - {script_name}{Style.RESET_ALL}")
                            print(f"  {result[:300]}...")
                        else:
                            print(f"{device.get('ip_str')}:{port} - {script_name}")
                            print(f"  {result[:300]}...")
        
        if not vulns_found and not passive_mode:
            print("\nNo vulnerabilities detected by Nmap scripts")
    
    def do_exit(self, arg):
        """Exit the program"""
        print("Goodbye!")
        return True
    
    def do_quit(self, arg):
        """Exit the program"""
        return self.do_exit(arg)
        
    def do_clear(self, arg):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(BANNER)
    
    def do_help(self, arg):
        """List available commands with help text or detailed help for a command"""
        if arg:
            # Show help for specific command
            try:
                func = getattr(self, 'help_' + arg)
                func()
            except AttributeError:
                try:
                    doc = getattr(self, 'do_' + arg).__doc__
                    if doc:
                        self.stdout.write(f"{arg}: {doc}\n")
                    else:
                        self.stdout.write(f"No help available for '{arg}'\n")
                except AttributeError:
                    self.stdout.write(f"No command '{arg}'\n")
        else:
            # List all commands with brief help
            commands = {}
            for attr in dir(self):
                if attr.startswith('do_'):
                    cmd = attr[3:]
                    doc = getattr(self, attr).__doc__ or ''
                    brief = doc.split('\n')[0]
                    commands[cmd] = brief
            
            # Group commands by category
            categories = {
                "Search": ["search", "list_templates", "show", "filter_cvss"],
                "Export": ["export", "load"],
                "Visualization": ["visualize", "map", "charts", "network_graph", "segment_analysis"],
                "Analysis": ["test_credentials", "find_exploits", "check_ssl", "track_history", "fingerprint"],
                "Information": ["shodan_info", "update"],
                "Settings": ["proxy", "clear"],
                "General": ["help", "exit", "quit"]
            }
            
            # Display commands by category
            for category, cmds in categories.items():
                if any(cmd in commands for cmd in cmds):
                    self.stdout.write(f"\n{category}:\n")
                    for cmd in cmds:
                        if cmd in commands:
                            self.stdout.write(f"  {cmd:<15} {commands[cmd]}\n")
                            
    def do_proxy(self, arg):
        """
        Configure proxy settings for network connections
        Usage: proxy [option]
        
        Options:
          show    - Show current proxy configuration
          http    - Set HTTP/HTTPS proxy (format: http://host:port)
          socks   - Set SOCKS proxy (format: socks5://host:port)
          clear   - Disable all proxies
          
        Examples:
          proxy show
          proxy http http://10.0.0.1:8080
          proxy socks socks5://127.0.0.1:9050
          proxy clear
        """
        global PROXY_ENABLED, HTTP_PROXY, HTTPS_PROXY, SOCKS_PROXY
        
        args = arg.strip().split()
        if not args or args[0] == "show":
            # Show current proxy configuration
            print("\nCurrent Proxy Configuration:")
            print(f"Proxy Enabled: {PROXY_ENABLED}")
            print(f"HTTP/HTTPS Proxy: {HTTP_PROXY}")
            print(f"SOCKS Proxy: {SOCKS_PROXY}")
            return
            
        if args[0] == "http":
            if len(args) < 2:
                print("Please provide a proxy URL (e.g., http://host:port)")
                return
                
            HTTP_PROXY = args[1]
            HTTPS_PROXY = args[1]
            PROXY_ENABLED = True
            print(f"HTTP/HTTPS proxy set to: {HTTP_PROXY}")
            
        elif args[0] == "socks":
            if len(args) < 2:
                print("Please provide a SOCKS proxy URL (e.g., socks5://host:port)")
                return
                
            SOCKS_PROXY = args[1]
            PROXY_ENABLED = True
            print(f"SOCKS proxy set to: {SOCKS_PROXY}")
            
        elif args[0] == "clear":
            PROXY_ENABLED = False
            print("Proxy settings disabled")
            
        else:
            print(f"Unknown option: {args[0]}")
            print("Use 'proxy show', 'proxy http', 'proxy socks', or 'proxy clear'")
            
    def emptyline(self):
        """Do nothing on empty line"""
        pass

    def do_update(self, arg):
        """
        Check for updates to BlackIce
        Usage: update [--auto]
        
        Use --auto to automatically download and install updates.
        """
        # Check for auto-update flag
        auto_update = '--auto' in arg
        
        print("Checking for updates to BlackIce...")
        has_update, latest_version = check_for_updates()
        
        if not has_update:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.GREEN}BlackIce is up to date (version {VERSION}){Style.RESET_ALL}")
            else:
                print(f"BlackIce is up to date (version {VERSION})")
            return
        
        if not auto_update:
            # Just inform the user about the update
            if COLORAMA_AVAILABLE:
                print(f"{Fore.YELLOW}You can update manually by downloading the latest version from:")
                print(f"{Fore.CYAN}{GITHUB_REPO}/releases/latest{Style.RESET_ALL}")
            else:
                print("You can update manually by downloading the latest version from:")
                print(f"{GITHUB_REPO}/releases/latest")
                
            choice = input("Would you like to attempt an automatic update now? (yes/no): ")
            if choice.lower() != 'yes':
                return
        
        try:
            # Attempt to download the update
            print("Attempting to download the latest version...")
            
            # Form the download URL for the raw script
            repo_parts = GITHUB_REPO.split('/')
            if len(repo_parts) >= 5:  # https://github.com/username/repo
                username = repo_parts[-2]
                repo = repo_parts[-1]
                download_url = f"https://raw.githubusercontent.com/{username}/{repo}/main/BlackIce.py"
                
                # Download the latest version
                response = cached_request(download_url)
                
                if not response or response.status_code != 200:
                    raise Exception(f"Failed to download update. Status code: {response.status_code if response else 'None'}")
                
                # Backup current version
                backup_file = f"BlackIce_backup_{int(time.time())}.py"
                try:
                    shutil.copy(__file__, backup_file)
                    print(f"Current version backed up to {backup_file}")
                except Exception as e:
                    print(f"Warning: Failed to create backup: {e}")
                
                # Write the new version
                with open(__file__, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                
                if COLORAMA_AVAILABLE:
                    print(f"{Fore.GREEN}Update successful! BlackIce updated to version {latest_version}")
                    print(f"{Fore.YELLOW}Please restart BlackIce to use the new version.{Style.RESET_ALL}")
                else:
                    print(f"Update successful! BlackIce updated to version {latest_version}")
                    print("Please restart BlackIce to use the new version.")
                    
                # Ask user if they want to restart now
                choice = input("Would you like to restart BlackIce now? (yes/no): ")
                if choice.lower() == 'yes':
                    print("Restarting BlackIce...")
                    python = sys.executable
                    os.execl(python, python, *sys.argv)
            else:
                raise Exception("Invalid GitHub repository URL format")
                
        except Exception as e:
            if COLORAMA_AVAILABLE:
                print(f"{Fore.RED}Error updating BlackIce: {e}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Please update manually from: {GITHUB_REPO}/releases/latest{Style.RESET_ALL}")
            else:
                print(f"Error updating BlackIce: {e}")
                print(f"Please update manually from: {GITHUB_REPO}/releases/latest")

def update_exploit_database():
    """Download and update the local exploit database"""
    try:
        logger.info("Updating exploit database from ExploitDB...")
        exploit_db = {}
        
        # Create cache directory if it doesn't exist
        os.makedirs(os.path.dirname(EXPLOITDB_CACHE_FILE), exist_ok=True)
        
        # Download the CSV file
        response = cached_request(EXPLOITDB_CSV_URL)
        if not response or response.status_code != 200:
            logger.error(f"Failed to download ExploitDB CSV. Status code: {response.status_code if response else 'None'}")
            return load_cache(EXPLOITDB_CACHE_FILE)
        
        # Parse CSV
        csv_data = response.text.splitlines()
        reader = csv.DictReader(csv_data)
        
        # Process entries
        for entry in reader:
            try:
                # Extract key information
                eid = entry.get('id', '').strip()
                file = entry.get('file', '').strip()
                description = entry.get('description', '').strip()
                date = entry.get('date', '').strip()
                platform = entry.get('platform', '').strip()
                type_name = entry.get('type', '').strip()
                
                # Process title for better search
                title = description.lower()
                
                # Skip entries without an ID
                if not eid:
                    continue
                    
                # Store in database
                exploit_db[eid] = {
                    'id': eid,
                    'file': file,
                    'description': description,
                    'date': date,
                    'platform': platform,
                    'type': type_name,
                    'title': title,
                    'timestamp': int(time.time())
                }
            except Exception as e:
                logger.debug(f"Error processing exploit DB entry: {e}")
                continue
        
        # Save to cache
        logger.info(f"Loaded {len(exploit_db)} exploits from ExploitDB")
        save_cache(EXPLOITDB_CACHE_FILE, exploit_db)
        
        return exploit_db
    except Exception as e:
        logger.error(f"Error updating exploit database: {e}")
        return load_cache(EXPLOITDB_CACHE_FILE)

def search_exploits_for_device(device, exploit_db=None):
    """Search for exploits matching a device's details"""
    results = []
    
    # Extract device details
    product = device.get('product', '').lower()
    version = device.get('version', '').lower()
    module = device.get('module', '').lower()
    port = device.get('port')
    
    # Load exploit database if not provided
    if exploit_db is None:
        exploit_db = load_cache(EXPLOITDB_CACHE_FILE)
        if not exploit_db:
            exploit_db = update_exploit_database()
    
    # Search terms based on device details
    search_terms = []
    if product:
        search_terms.append(product)
        if version:
            search_terms.append(f"{product} {version}")
    
    if module and module != product:
        search_terms.append(module)
        if version:
            search_terms.append(f"{module} {version}")
    
    # Search for matching exploits
    for eid, exploit in exploit_db.items():
        title = exploit.get('title', '').lower()
        description = exploit.get('description', '').lower()
        
        # Check if any search term matches
        for term in search_terms:
            if term in title or term in description:
                # Calculate relevance score
                score = 0
                if term in title:
                    score += 3
                if term in description:
                    score += 1
                if version and version in title:
                    score += 2
                
                # Add to results if not already there
                if not any(r['id'] == eid for r in results):
                    results.append({
                        'id': eid,
                        'title': exploit.get('description', ''),
                        'date': exploit.get('date', ''),
                        'type': exploit.get('type', ''),
                        'platform': exploit.get('platform', ''),
                        'file': exploit.get('file', ''),
                        'score': score,
                        'url': f"https://www.exploit-db.com/exploits/{eid}"
                    })
    
    # Sort by relevance score
    results.sort(key=lambda x: x['score'], reverse=True)
    
    # Return up to 10 most relevant results
    return results[:10]

def search_vulners_for_cve(product, version=None):
    """Search Vulners.com for CVEs related to a product/version"""
    results = []
    
    try:
        # Construct search query
        query = f"{product}"
        if version:
            query += f" {version}"
        
        # Add cache key
        cache_key = f"vulners_{query.replace(' ', '_')}"
        
        # Check cache first
        cache = load_cache(SHODAN_CACHE_FILE)
        if cache_key in cache and (time.time() - cache[cache_key].get('timestamp', 0) < CACHE_TIMEOUT):
            return cache[cache_key].get('data', [])
        
        # Make API request
        params = {
            'query': f"{query} type:cve",
            'fields': 'id,title,description,published,cvss,type,href',
            'size': 20
        }
        
        response = cached_request(
            VULNERS_API_URL,
            method='GET',
            params=params
        )
        
        if not response or response.status_code != 200:
            logger.error(f"Vulners API error: {response.status_code if response else 'No response'}")
            return []
        
        data = response.json()
        
        # Process results
        for item in data.get('data', {}).get('search', []):
            try:
                cvss = float(item.get('cvss', {}).get('score', 0))
                cve_id = item.get('id', '')
                
                if cve_id and cve_id.startswith('CVE-'):
                    result = {
                        'id': cve_id,
                        'title': item.get('title', ''),
                        'description': item.get('description', ''),
                        'published': item.get('published', ''),
                        'cvss': cvss,
                        'url': item.get('href', '')
                    }
                    results.append(result)
            except Exception as e:
                logger.debug(f"Error processing Vulners result: {e}")
        
        # Sort by CVSS score
        results.sort(key=lambda x: x.get('cvss', 0), reverse=True)
        
        # Cache the results
        if cache and results:
            cache[cache_key] = {
                'data': results,
                'timestamp': int(time.time())
            }
            save_cache(SHODAN_CACHE_FILE, cache)
        
        return results
    except Exception as e:
        logger.error(f"Error searching Vulners for {product} {version}: {e}")
        return []

def test_default_credentials(host, port, protocol, product=None):
    """Test if a device is using default credentials"""
    if not DEFAULT_CREDENTIALS:
        logger.warning("No default credentials loaded")
        return None
    
    results = {
        'host': host,
        'port': port,
        'protocol': protocol,
        'tested': 0,
        'successful': 0,
        'credentials': []
    }
    
    logger.info(f"Testing default credentials for {host}:{port} ({protocol})")
    
    # Filter credentials by product if specified
    creds_to_test = DEFAULT_CREDENTIALS
    if product:
        creds_to_test = [c for c in DEFAULT_CREDENTIALS if product.lower() in c.get('product', '').lower()]
        if not creds_to_test:
            # Fallback to all credentials if no match by product
            creds_to_test = DEFAULT_CREDENTIALS
    
    # Test each credential based on protocol
    for cred in creds_to_test:
        try:
            user = cred.get('username', '')
            password = cred.get('password', '')
            results['tested'] += 1
            
            # Different handling based on protocol
            if protocol.lower() == 'http' or protocol.lower() == 'https':
                success = test_http_auth(host, port, protocol, user, password)
            elif protocol.lower() == 'ssh':
                success = test_ssh_auth(host, port, user, password)
            elif protocol.lower() == 'ftp':
                success = test_ftp_auth(host, port, user, password)
            elif protocol.lower() == 'telnet':
                success = test_telnet_auth(host, port, user, password)
            elif protocol.lower() == 'snmp':
                success = test_snmp_auth(host, port, user, password)
            else:
                logger.warning(f"Unsupported protocol for credential testing: {protocol}")
                success = False
            
            # Record successful auth
            if success:
                results['successful'] += 1
                results['credentials'].append({
                    'username': user,
                    'password': password,
                    'product': cred.get('product', ''),
                    'notes': cred.get('notes', '')
                })
                
                # Log the success
                logger.warning(f"FOUND DEFAULT CREDENTIALS for {host}:{port} - {user}:{password}")
        except Exception as e:
            logger.debug(f"Error testing credential {user}:{password} on {host}:{port}: {e}")
    
    return results

def test_http_auth(host, port, protocol, username, password):
    """Test HTTP Basic Auth credentials"""
    try:
        url = f"{protocol}://{host}:{port}/"
        response = requests.get(
            url, 
            auth=(username, password), 
            timeout=5,
            verify=False,  # Don't verify SSL certificates
            proxies=setup_proxy()
        )
        
        # Check status code for successful auth
        return response.status_code == 200 and response.status_code != 401
    except Exception as e:
        logger.debug(f"HTTP auth test error: {e}")
        return False

def test_ssh_auth(host, port, username, password):
    """Test SSH credentials"""
    if not PARAMIKO_AVAILABLE:
        logger.error("Paramiko library not installed. Install with: pip install paramiko")
        return False
        
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(
            host, 
            port=int(port), 
            username=username, 
            password=password, 
            timeout=5
        )
        
        client.close()
        return True
    except Exception as e:
        logger.debug(f"SSH auth test error: {str(e)}")
        return False

def test_ftp_auth(host, port, username, password):
    """Test FTP credentials"""
    try:
        from ftplib import FTP
        
        ftp = FTP()
        ftp.connect(host, int(port), timeout=5)
        ftp.login(username, password)
        ftp.quit()
        return True
    except Exception as e:
        logger.debug(f"FTP auth test error: {str(e)}")
        return False

def test_telnet_auth(host, port, username, password):
    """Test Telnet credentials"""
    try:
        # Create an async function to handle telnet connection
        async def _telnet_auth():
            try:
                reader, writer = await telnetlib3.open_connection(host, int(port), timeout=5)
                
                # Read until login prompt
                response = await reader.read(1024)
                if "login:" in response:
                    writer.write(username + "\n")
                    
                    # Wait for password prompt
                    response = await reader.read(1024)
                    if "Password:" in response:
                        writer.write(password + "\n")
                        
                        # Check if login was successful
                        response = await reader.read(1024)
                        if "$" in response or ">" in response or "#" in response:
                            writer.close()
                            return True
                
                writer.close()
                return False
            except Exception as e:
                logger.debug(f"Telnet connection error: {str(e)}")
                return False
        
        # Set up event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_telnet_auth())
            return result
        finally:
            loop.close()
            
    except Exception as e:
        logger.debug(f"Telnet auth test error: {str(e)}")
        return False

def test_snmp_auth(host, port, username, password):
    """Test SNMP community string"""
    try:
        from pysnmp.hlapi import (
            SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, getCmd
        )
        
        # In SNMP, password is the community string
        community_string = password
        
        # Create SNMP GET request (sysDescr OID)
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community_string),
            UdpTransportTarget((host, int(port)), timeout=5, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
        )
        
        # Process response
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        
        # Check for errors
        if errorIndication or errorStatus:
            return False
        
        return True
    except ImportError:
        logger.error("PySNMP library not installed. Install with: pip install pysnmp")
        return False
    except Exception as e:
        logger.debug(f"SNMP auth test error: {str(e)}")
        return False

def check_ssl_security(host, port):
    """Check for SSL/TLS security issues"""
    result = {
        'host': host,
        'port': port,
        'supports_ssl': False,
        'issues': [],
        'grade': 'Unknown',
        'cert_info': {}
    }
    
    try:
        import ssl
        import socket
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        # Try to establish SSL connection
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, int(port)), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result['supports_ssl'] = True
                
                # Get protocol version
                result['protocol'] = ssock.version()
                
                # Check for weak protocol versions
                if result['protocol'] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    result['issues'].append(f"Weak protocol: {result['protocol']}")
                
                # Get certificate details
                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    # Extract certificate information
                    result['cert_info'] = {
                        'subject': str(cert.subject),
                        'issuer': str(cert.issuer),
                        'not_valid_before': cert.not_valid_before.isoformat(),
                        'not_valid_after': cert.not_valid_after.isoformat(),
                        'expired': cert.not_valid_after < datetime.datetime.now()
                    }
                    
                    # Check expiration
                    if result['cert_info']['expired']:
                        result['issues'].append("Certificate expired")
                    
                    # Check for self-signed certificate
                    if cert.issuer == cert.subject:
                        result['issues'].append("Self-signed certificate")
                
                # Get supported cipher suites
                ciphers = []
                
                # Check for common weak ciphers
                weak_ciphers = [
                    'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'ANULL', 
                    'aNULL', 'IDEA', 'ADH', 'AECDH'
                ]
                
                for cipher in weak_ciphers:
                    try:
                        # Create a context that only supports the weak cipher
                        test_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                        test_context.set_ciphers(cipher)
                        
                        with socket.create_connection((host, int(port)), timeout=2) as test_sock:
                            with test_context.wrap_socket(test_sock, server_hostname=host) as test_ssock:
                                cipher_name = test_ssock.cipher()[0]
                                if cipher_name:
                                    ciphers.append(cipher_name)
                                    result['issues'].append(f"Weak cipher supported: {cipher_name}")
                    except:
                        # This is expected for ciphers not supported
                        pass
        
        # Calculate security grade
        issue_count = len(result['issues'])
        if issue_count == 0:
            result['grade'] = 'A'
        elif issue_count == 1:
            result['grade'] = 'B'
        elif issue_count == 2:
            result['grade'] = 'C'
        elif issue_count == 3:
            result['grade'] = 'D'
        else:
            result['grade'] = 'F'
            
    except ImportError:
        result['issues'].append("Required libraries missing. Install with: pip install cryptography")
        logger.error("Required libraries missing for SSL check. Install with: pip install cryptography")
    except Exception as e:
        result['issues'].append(f"Connection error: {str(e)}")
        logger.debug(f"SSL check error for {host}:{port}: {e}")
    
    return result

def check_device_history(device, history_db=None):
    """Check if a device has changed over time"""
    host = device.get('ip_str', '')
    port = device.get('port', 0)
    
    if not host or not port:
        return None
    
    # Create device identifier
    device_id = f"{host}:{port}"
    
    # Set up history database
    if history_db is None:
        history_db = {}
        
        # Try to load from file
        try:
            if os.path.exists(HISTORY_DB_FILE):
                with open(HISTORY_DB_FILE, 'r') as f:
                    history_db = json.load(f)
        except Exception as e:
            logger.error(f"Error loading history database: {e}")
    
    # Get current timestamp
    current_time = int(time.time())
    
    # Prepare device snapshot
    snapshot = {
        'timestamp': current_time,
        'ip': host,
        'port': port,
        'product': device.get('product', ''),
        'version': device.get('version', ''),
        'title': device.get('title', ''),
        'org': device.get('org', ''),
        'isp': device.get('isp', ''),
        'hostnames': device.get('hostnames', []),
        'data': device.get('data', '')
    }
    
    result = {
        'device_id': device_id,
        'first_seen': current_time,
        'last_seen': current_time,
        'changes': [],
        'snapshots': []
    }
    
    # Check if device exists in history
    if device_id in history_db:
        previous = history_db[device_id]
        result['first_seen'] = previous.get('first_seen', current_time)
        result['snapshots'] = previous.get('snapshots', [])
        
        # Compare with last snapshot
        if result['snapshots']:
            last_snapshot = result['snapshots'][-1]
            
            # Check for changes
            for field in ['product', 'version', 'title', 'org', 'isp']:
                if snapshot.get(field) != last_snapshot.get(field) and snapshot.get(field) and last_snapshot.get(field):
                    result['changes'].append({
                        'field': field,
                        'old': last_snapshot.get(field),
                        'new': snapshot.get(field),
                        'timestamp': current_time
                    })
    
    # Add new snapshot
    result['snapshots'].append(snapshot)
    
    # Trim snapshots to keep only the last 10
    if len(result['snapshots']) > 10:
        result['snapshots'] = result['snapshots'][-10:]
    
    # Update history database
    history_db[device_id] = result
    
    # Save history database
    try:
        os.makedirs(os.path.dirname(HISTORY_DB_FILE), exist_ok=True)
        with open(HISTORY_DB_FILE, 'w') as f:
            json.dump(history_db, f)
    except Exception as e:
        logger.error(f"Error saving history database: {e}")
    
    return result

def analyze_network_segments(devices):
    """Analyze network segmentation based on device IP ranges"""
    if not devices:
        return []
    
    # Extract IP addresses
    ip_addresses = [device.get('ip_str', '') for device in devices if device.get('ip_str')]
    
    # Group by network segments
    networks = {}
    
    for ip in ip_addresses:
        try:
            # Extract network part (first three octets for /24 networks)
            network = '.'.join(ip.split('.')[:3]) + '.0/24'
            
            if network not in networks:
                networks[network] = []
            
            networks[network].append(ip)
        except Exception as e:
            logger.debug(f"Error processing IP {ip}: {e}")
    
    # Analyze each network segment
    results = []
    
    for network, ips in networks.items():
        # Calculate device density
        density = len(ips)
        
        # Get device types in this segment
        segment_devices = [d for d in devices if d.get('ip_str', '') in ips]
        device_types = {}
        
        for device in segment_devices:
            product = device.get('product', 'Unknown')
            if product not in device_types:
                device_types[product] = 0
            device_types[product] += 1
        
        # Check for mixing sensitive and non-sensitive devices
        has_sensitive = any(is_sensitive_device(device) for device in segment_devices)
        has_non_sensitive = any(not is_sensitive_device(device) for device in segment_devices)
        
        # Calculate risk score based on device density and mixing
        risk_score = 0
        
        # Higher density means higher risk
        if density > 20:
            risk_score += 3
        elif density > 10:
            risk_score += 2
        elif density > 5:
            risk_score += 1
        
        # Mixing sensitive and non-sensitive devices is risky
        if has_sensitive and has_non_sensitive:
            risk_score += 3
        
        # More device types means more complex security
        if len(device_types) > 5:
            risk_score += 2
        elif len(device_types) > 3:
            risk_score += 1
        
        # Calculate risk level
        risk_level = 'Low'
        if risk_score >= 6:
            risk_level = 'High'
        elif risk_score >= 3:
            risk_level = 'Medium'
        
        # Generate recommendations
        recommendations = []
        
        if has_sensitive and has_non_sensitive:
            recommendations.append("Separate sensitive and non-sensitive devices into different network segments")
        
        if density > 10:
            recommendations.append("Consider splitting this network segment into smaller subnets")
        
        if len(device_types) > 3:
            recommendations.append("Group similar device types into dedicated network segments")
        
        # Add to results
        results.append({
            'network': network,
            'device_count': density,
            'device_types': device_types,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'has_sensitive_devices': has_sensitive,
            'has_mixed_devices': has_sensitive and has_non_sensitive,
            'recommendations': recommendations
        })
    
    # Sort by risk score (descending)
    results.sort(key=lambda x: x['risk_score'], reverse=True)
    
    return results

def is_sensitive_device(device):
    """Determine if a device should be considered sensitive"""
    # Get device details
    product = (device.get('product', '') or '').lower()
    title = (device.get('title', '') or '').lower()
    port = device.get('port', 0)
    
    # List of keywords indicating sensitive devices
    sensitive_keywords = [
        'camera', 'webcam', 'medical', 'healthcare', 'patient', 'scada',
        'industrial', 'control system', 'power', 'energy', 'building',
        'access control', 'security', 'surveillance', 'firewall', 'financial',
        'payment', 'banking', 'trading', 'database', 'storage'
    ]
    
    # Check for sensitive keywords
    for keyword in sensitive_keywords:
        if keyword in product or keyword in title:
            return True
    
    # Check for sensitive ports
    sensitive_ports = [22, 23, 3389, 5900, 8443, 8080, 9443, 7547]
    if port in sensitive_ports:
        return True
    
    return False

def main():
    """Main entry point for the program"""
    # Declare globals at the beginning of the function
    global PROXY_ENABLED, HTTP_PROXY, HTTPS_PROXY, SOCKS_PROXY, MAX_PARALLEL_SCANS, PASSIVE_MODE
    
    # Configure logging
    log_file = os.path.join(LOG_DIR, "blackice.log")
    logger.setLevel(logging.INFO)
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler (only warnings and errors)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Print banner
    if COLORAMA_AVAILABLE:
        colorama.init()
        # Use colored banner
        print(f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}")
    else:
        print(BANNER)
    
    # Check for updates if enabled
    has_update = False
    latest_version = VERSION
    if AUTO_CHECK_UPDATES:
        try:
            has_update, latest_version = check_for_updates()
            if has_update:
                print(f"\nUpdate available: {VERSION} → {latest_version}")
                print(f"Visit {GITHUB_REPO}/releases to download the latest version.")
        except Exception as e:
            logger.warning(f"Failed to check for updates: {e}")
    
    # Setup argument parser
    parser = argparse.ArgumentParser(description='BlackIce - IoT Vulnerability Scanner')
    
    # Mode selection arguments
    parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive shell mode')
    parser.add_argument('--query', '-q', type=str, help='Direct search query for Shodan')
    parser.add_argument('--load', '-l', type=str, help='Load devices from a JSON file')
    
    # Search options
    parser.add_argument('--limit', type=int, default=10, help='Maximum number of results (default: 10)')
    parser.add_argument('--country', type=str, help='Filter by two-letter country code')
    parser.add_argument('--port', type=int, help='Filter by port number')
    parser.add_argument('--template', type=str, help='Use a predefined search template')
    
    # Output options
    parser.add_argument('--output', '-o', type=str, help='Output file for search results')
    parser.add_argument('--format', '-f', type=str, choices=['text', 'table', 'csv', 'json'], default='table',
                        help='Output format (default: table)')
    
    # Visualization options
    parser.add_argument('--visualize', action='store_true', help='Create visualizations for search results')
    parser.add_argument('--map', action='store_true', help='Create a map of device locations')
    parser.add_argument('--charts', action='store_true', help='Create charts of device statistics')
    parser.add_argument('--viz-dir', type=str, help='Directory to save visualization outputs')
    
    # Network analysis options
    parser.add_argument('--network-graph', action='store_true', help='Create network graph of device relationships')
    parser.add_argument('--network-map', action='store_true', help='Create map of device networks')
    
    # Security check options
    parser.add_argument('--check-vulns', action='store_true', help='Check for vulnerabilities in found devices')
    parser.add_argument('--test-credentials', action='store_true', help='Test devices for default credentials')
    parser.add_argument('--find-exploits', action='store_true', help='Search for known exploits for devices')
    parser.add_argument('--check-ssl', action='store_true', help='Check for SSL/TLS vulnerabilities')
    parser.add_argument('--track-history', action='store_true', help='Track device history over time')
    parser.add_argument('--cvss-filter', type=str, help='Filter by CVSS score or severity (LOW, MEDIUM, HIGH, CRITICAL)')
    parser.add_argument('--segment-analysis', action='store_true', help='Analyze network segmentation')
    parser.add_argument('--fingerprint', action='store_true', help='Fingerprint devices using Nmap')
    
    # Performance options
    parser.add_argument('--parallel', action='store_true', help='Enable parallel processing for operations')
    parser.add_argument('--threads', type=int, help=f'Number of parallel threads (default: {MAX_PARALLEL_SCANS})')
    parser.add_argument('--passive', action='store_true', help='Enable passive scanning mode (slower but stealthier)')
    
    # Proxy options
    parser.add_argument('--proxy', type=str, help='HTTP/HTTPS proxy to use (format: http://proxy:port)')
    parser.add_argument('--socks-proxy', type=str, help='SOCKS proxy to use (format: socks5://proxy:port)')
    
    # Update options
    parser.add_argument('--update', action='store_true', help='Check for updates to BlackIce')
    parser.add_argument('--auto-update', action='store_true', help='Automatically install updates if available')
    
    # Setup/help options
    parser.add_argument('--verbose', '-v', action='count', default=0, help='Increase verbosity level')
    parser.add_argument('--version', action='store_true', help='Show version information')
    parser.add_argument('--setup', action='store_true', help='Configure BlackIce settings')
    parser.add_argument('--check-deps', action='store_true', help='Check dependencies and installation status')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Configure logging level based on verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)
    elif args.verbose >= 1:
        logger.setLevel(logging.INFO)
        console_handler.setLevel(logging.INFO)
    
    # Apply proxy settings if specified
    if args.proxy:
        PROXY_ENABLED = True
        HTTP_PROXY = args.proxy
        HTTPS_PROXY = args.proxy
        logger.info(f"Using HTTP/HTTPS proxy: {args.proxy}")
    
    if args.socks_proxy:
        PROXY_ENABLED = True
        SOCKS_PROXY = args.socks_proxy
        logger.info(f"Using SOCKS proxy: {args.socks_proxy}")
    
    # Apply parallel processing settings
    if args.parallel:
        if args.threads:
            MAX_PARALLEL_SCANS = max(1, min(args.threads, 32))  # Limit between 1 and 32
            logger.info(f"Parallel processing enabled with {MAX_PARALLEL_SCANS} threads")
        else:
            logger.info(f"Parallel processing enabled with default threads")
    
    # Apply passive mode if specified
    if args.passive:
        PASSIVE_MODE = True
        logger.info("Passive scanning mode enabled")
    
    # Process version request
    if args.version:
        if COLORAMA_AVAILABLE:
            print(f"{Fore.CYAN}BlackIce IoT Vulnerability Scanner v{VERSION}{Style.RESET_ALL}")
        else:
            print(f"BlackIce IoT Vulnerability Scanner v{VERSION}")
        print(f"GitHub: {GITHUB_REPO}")
        print("Created by: Your Name Here")
        return
    
    # Check dependencies if requested
    if args.check_deps:
        deps = check_dependencies()
        if deps["missing_required"]:
            print("\nWARNING: Required dependencies are missing. Some functionality will not work.")
        return
    
    # Process update request
    if args.update or args.auto_update:
        has_update, latest_version = check_for_updates()
        if has_update:
            print(f"Update available: {VERSION} → {latest_version}")
            print(f"Please download the latest version from: {GITHUB_REPO}/releases/latest")
        else:
            print(f"BlackIce is up to date (version {VERSION})")
        
        if args.auto_update and has_update:
            # Here would be code to auto-update
            print("Automatic updates not yet implemented in command-line mode.")
            print(f"Please download the latest version from: {GITHUB_REPO}/releases/latest")
        return
    
    # Setup Shodan API key
    api_key = setup_api_key()
    if not api_key and not args.load:
        if COLORAMA_AVAILABLE:
            print(f"{Fore.RED}No Shodan API key provided. Cannot perform searches.{Style.RESET_ALL}")
        else:
            print("No Shodan API key provided. Cannot perform searches.")
        print("Please configure the API key using --setup or directly edit config.py")
        # Run setup mode if no key is found
        if input("Would you like to run the setup tool now? (y/n): ").lower().startswith('y'):
            args.setup = True
        else:
            return
    
    # Handle setup mode
    if args.setup:
        print("\nBlackIce Setup")
        print("=============")
        
        # API Key
        print("\n1. Shodan API Key")
        if SHODAN_API_KEY and SHODAN_API_KEY != "your_shodan_api_key_here":
            print(f"Current: {SHODAN_API_KEY[:4]}...{SHODAN_API_KEY[-4:]}")
        else:
            print("Current: Not set")
        
        choice = input("Do you want to configure the Shodan API key? (yes/no): ")
        if choice.lower() in ['yes', 'y']:
            key = input("Enter your Shodan API key: ").strip()
            
            # Validate key
            try:
                api = shodan.Shodan(key)
                info = api.info()
                print(f"API key is valid. You have {info['query_credits']} query credits remaining.")
                
                # Save key in the config file
                with open('config.py', 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Replace API key
                if "SHODAN_API_KEY = " in content:
                    pattern = r'SHODAN_API_KEY = "(.*?)"'
                    content = re.sub(pattern, f'SHODAN_API_KEY = "{key}"', content)
                    
                    with open('config.py', 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    print("API key saved in config.py file.")
                else:
                    print("Error: Could not find API key variable in config file.")
            except Exception as e:
                print(f"Error validating API key: {e}")
                
        # Proxy Configuration
        print("\n2. Proxy Settings")
        print(f"Current HTTP/HTTPS proxy: {HTTP_PROXY if HTTP_PROXY else 'Not set'}")
        print(f"Current SOCKS proxy: {SOCKS_PROXY if SOCKS_PROXY else 'Not set'}")
        
        choice = input("Do you want to configure proxy settings? (yes/no): ")
        if choice.lower() in ['yes', 'y']:
            proxy_enabled = input("Enable proxy? (yes/no): ").lower() in ['yes', 'y']
            
            if proxy_enabled:
                http_proxy = input("Enter HTTP/HTTPS proxy (format: http://host:port) or leave empty: ").strip()
                socks_proxy = input("Enter SOCKS proxy (format: socks5://host:port) or leave empty: ").strip()
                
                # Update config file
                with open('config.py', 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Replace proxy settings
                content = re.sub(r'PROXY_ENABLED = (True|False)', f'PROXY_ENABLED = {proxy_enabled}', content)
                
                if http_proxy:
                    content = re.sub(r'HTTP_PROXY = (.*)', f'HTTP_PROXY = "{http_proxy}"', content)
                    content = re.sub(r'HTTPS_PROXY = (.*)', f'HTTPS_PROXY = "{http_proxy}"', content)
                
                if socks_proxy:
                    content = re.sub(r'SOCKS_PROXY = (.*)', f'SOCKS_PROXY = "{socks_proxy}"', content)
                
                with open('config.py', 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print("Proxy settings saved in config.py file.")
            else:
                # Disable proxy in config
                with open('config.py', 'r', encoding='utf-8') as f:
                    content = f.read()
                
                content = re.sub(r'PROXY_ENABLED = (True|False)', 'PROXY_ENABLED = False', content)
                
                with open('config.py', 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print("Proxy settings disabled.")
        
        # Scanning Mode
        print("\n3. Scanning Mode")
        print(f"Current mode: {'Passive' if PASSIVE_MODE else 'Active'}")
        
        choice = input("Do you want to configure scanning mode? (yes/no): ")
        if choice.lower() in ['yes', 'y']:
            passive_mode = input("Use passive (stealthy) scanning? (yes/no): ").lower() in ['yes', 'y']
            
            # Update config file
            with open('config.py', 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Replace setting
            content = re.sub(r'PASSIVE_MODE = (True|False)', f'PASSIVE_MODE = {passive_mode}', content)
            
            with open('config.py', 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"Scanning mode set to {'passive' if passive_mode else 'active'}.")
        
        print("\nSetup complete!")
        return
    
    # No action specified, default to interactive mode if available
    if not (args.query or args.load or args.interactive):
        if CMD_AVAILABLE:
            print("No command specified, starting interactive mode.")
            shell = InteractiveShell(api_key=api_key)
            shell.cmdloop()
            return
        else:
            print("Interactive mode not available (cmd module not found).")
            parser.print_help()
            return
    
    # Handle interactive mode
    if args.interactive:
        if CMD_AVAILABLE:
            shell = InteractiveShell(api_key=api_key)
            shell.cmdloop()
        else:
            print("Interactive mode not available. Install the 'cmd' module.")
        return
    
    # Handle direct search query
    if args.query:
        # Determine if query is a template or direct query
        query = args.query
        if args.template:
            if args.template in SEARCH_TEMPLATES:
                query = SEARCH_TEMPLATES[args.template]
                print(f"Using template: {args.template} ({query})")
            else:
                print(f"Template '{args.template}' not found. Using direct query.")
        
        # Adjust query based on filters
        if args.country:
            # Replace {country} placeholder if it exists, otherwise append
            if "{country}" in query:
                query = query.replace("{country}", args.country)
            else:
                query += f" country:{args.country}"
        
        if args.port:
            query += f" port:{args.port}"
        
        # Search for devices
        devices = search_vulnerable_iot_devices(
            query, 
            limit=args.limit,
            output_format=args.format,
            output_file=args.output,
            country_filter=args.country,
            port_filter=args.port,
            check_vulns=args.check_vulns
        )
        
        # Additional actions based on results
        if devices:
            # Test credentials if requested
            if args.test_credentials:
                print("\nTesting devices for default credentials...")
                for device in devices:
                    test_device_credentials(device)
                    print(f"  {device['ip']}:{device['port']} - ", end="")
                    if device.get('credential_test', {}).get('vulnerable', False):
                        print("VULNERABLE")
                    else:
                        print("Secure")
            
            # Create visualizations if requested
            if args.visualize or args.map or args.charts:
                viz_dir = args.viz_dir or "visualizations"
                os.makedirs(viz_dir, exist_ok=True)
                
                timestamp = int(time.time())
                prefix = f"{viz_dir}/scan_{timestamp}"
                
                if args.map or args.visualize:
                    try:
                        if 'create_map' in globals():
                            map_file = create_map(devices, f"{prefix}_map.html")
                            if map_file:
                                print(f"Map created: {map_file}")
                        else:
                            print("Map creation not available: create_map function not found")
                    except Exception as e:
                        print(f"Error creating map: {str(e)}")
                
                if args.charts or args.visualize:
                    try:
                        if 'create_device_charts' in globals():
                            chart_files = create_device_charts(devices, prefix)
                            if chart_files:
                                print(f"Charts created: {', '.join(chart_files)}")
                        else:
                            print("Chart creation not available: create_device_charts function not found")
                    except Exception as e:
                        print(f"Error creating charts: {str(e)}")
                
                if args.network_graph:
                    try:
                        if 'create_network_graph' in globals():
                            graph_file = create_network_graph(devices, f"{prefix}_network.html")
                            if graph_file:
                                print(f"Network graph created: {graph_file}")
                        else:
                            print("Network graph creation not available: create_network_graph function not found")
                    except Exception as e:
                        print(f"Error creating network graph: {str(e)}")
                
                # Create a comprehensive vulnerability report
                if args.check_vulns:
                    try:
                        if 'display_vulnerability_report' in globals():
                            report_file = args.output or f"vulnerability_report_{int(time.time())}.txt"
                            display_vulnerability_report(devices, report_file)
                        else:
                            print("Vulnerability report not available: display_vulnerability_report function not found")
                    except Exception as e:
                        print(f"Error creating vulnerability report: {str(e)}")
            
            print(f"\nFound {len(devices)} devices matching your query.")
        else:
            print("No devices found matching your query.")
        
        return
    
    # Handle loading from file
    if args.load:
        if os.path.exists(args.load):
            try:
                with open(args.load, 'r') as f:
                    devices = json.load(f)
                
                print(f"Loaded {len(devices)} devices from {args.load}")
                
                # Process loaded devices similar to direct search
                # ... (similar code as above)
                
            except Exception as e:
                print(f"Error loading file: {e}")
        else:
            print(f"File not found: {args.load}")
        return
    
    # If we get here, no valid action was specified
    print("No devices to process. Use --query to search or --load to load from a file.")
    print("Use --help to see all available options.")
    
    return

def handle_error(message, exception, exit_code=None):
    """
    Handle errors in a consistent way throughout the application
    
    Args:
        message: A human-readable error message
        exception: The exception object
        exit_code: If provided, exit the program with this code
    """
    # Get additional exception info
    exc_type = type(exception).__name__
    exc_msg = str(exception)
    
    # Log the error
    logger.error(f"{message}: {exc_type} - {exc_msg}")
    logger.debug("Exception details:", exc_info=True)
    
    # Display user-friendly message
    if COLORAMA_AVAILABLE:
        print(f"{Fore.RED}ERROR: {message}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Details: {exc_type} - {exc_msg}{Style.RESET_ALL}")
    else:
        print(f"ERROR: {message}")
        print(f"Details: {exc_type} - {exc_msg}")
    
    # Print additional help for specific error types
    if isinstance(exception, ConnectionError):
        print("\nThis appears to be a network connection issue. Please check:")
        print("- Your internet connection is working")
        print("- Any proxy settings are correct")
        print("- The target service is available")
    elif isinstance(exception, PermissionError):
        print("\nThis appears to be a permissions issue. Please check:")
        print("- You have the necessary permissions to access the resource")
        print("- The file or directory is not locked by another process")
    elif "api key" in str(exception).lower() or "apikey" in str(exception).lower():
        print("\nThis appears to be an API key issue. Please check:")
        print("- You have provided a valid Shodan API key")
        print("- Your API key has sufficient credits")
        print("- Run 'BlackIce.py --setup' to configure your API key")
    
    # Exit if requested
    if exit_code is not None:
        sys.exit(exit_code)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        handle_error("Unhandled error", e, exit_code=1)

def create_device_charts(devices, output_prefix=None):
    """Create charts to visualize device statistics"""
    if not NETWORK_AVAILABLE or not PANDAS_AVAILABLE:
        logger.error("Matplotlib or Pandas not installed. Cannot create charts.")
        return []
    
    # Default output prefix if not provided
    if not output_prefix:
        timestamp = int(time.time())
        output_prefix = f"device_charts_{timestamp}"
    
    chart_files = []
    
    try:
        # Extract device attributes
        countries = [device.get('location', {}).get('country_name', 'Unknown') for device in devices]
        countries = [c if c else 'Unknown' for c in countries]
        
        orgs = [device.get('org', 'Unknown') for device in devices]
        orgs = [o if o else 'Unknown' for o in orgs]
        
        products = [device.get('product', 'Unknown') for device in devices]
        products = [p if p else 'Unknown' for p in products]
        
        ports = [device.get('port', 0) for device in devices]
        
        # Count vulnerabilities per device
        vuln_counts = []
        for device in devices:
            if device.get('_vulns'):
                vuln_counts.append(len(device['_vulns']))
            else:
                vuln_counts.append(0)
        
        # Create country chart
        plt.figure(figsize=(12, 8))
        country_counter = Counter(countries)
        top_countries = dict(country_counter.most_common(10))
        
        plt.bar(top_countries.keys(), top_countries.values(), color='skyblue')
        plt.title('Top 10 Countries')
        plt.xlabel('Country')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        country_chart = f"{output_prefix}_country.png"
        plt.savefig(country_chart)
        plt.close()
        chart_files.append(country_chart)
        
        # Create organization chart
        plt.figure(figsize=(12, 8))
        org_counter = Counter(orgs)
        top_orgs = dict(org_counter.most_common(10))
        
        plt.bar(top_orgs.keys(), top_orgs.values(), color='lightgreen')
        plt.title('Top 10 Organizations')
        plt.xlabel('Organization')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        org_chart = f"{output_prefix}_org.png"
        plt.savefig(org_chart)
        plt.close()
        chart_files.append(org_chart)
        
        # Create product chart
        plt.figure(figsize=(12, 8))
        product_counter = Counter(products)
        top_products = dict(product_counter.most_common(10))
        
        plt.bar(top_products.keys(), top_products.values(), color='salmon')
        plt.title('Top 10 Products')
        plt.xlabel('Product')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        product_chart = f"{output_prefix}_product.png"
        plt.savefig(product_chart)
        plt.close()
        chart_files.append(product_chart)
        
        logger.info(f"Charts saved with prefix {output_prefix}")
        return chart_files
    except Exception as e:
        logger.error(f"Error creating charts: {e}")
        return chart_files

def generate_html_report(devices, chart_files, map_file, output_file):
    """Generate an HTML report with all visualizations"""
    try:
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>BlackIce - IoT Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; color: #333; }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
                h1, h2, h3 {{ margin-top: 30px; }}
                .section {{ margin-bottom: 40px; }}
                .stats {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }}
                .stat-box {{ background-color: #f8f9fa; border-radius: 5px; padding: 15px; flex: 1; 
                          min-width: 200px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .chart {{ margin: 20px 0; text-align: center; }}
                .chart img {{ max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 5px; }}
                .map-container {{ height: 600px; margin: 20px 0; }}
                iframe {{ border: none; width: 100%; height: 100%; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .vulnerable {{ color: #e74c3c; }}
                .footer {{ margin-top: 40px; text-align: center; font-size: 0.8em; color: #777; }}
            </style>
        </head>
        <body>
            <header>
                <h1>BlackIce - IoT Security Report</h1>
                <p>Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </header>
            
            <div class="container">
                <div class="section">
                    <h2>Summary</h2>
                    <div class="stats">
                        <div class="stat-box">
                            <h3>Devices Found</h3>
                            <p>{len(devices)}</p>
                        </div>
                        <div class="stat-box">
                            <h3>Countries</h3>
                            <p>{len(set(d.get('location', {}).get('country_name', 'Unknown') for d in devices))}</p>
                        </div>
                        <div class="stat-box">
                            <h3>Organizations</h3>
                            <p>{len(set(d.get('org', 'Unknown') for d in devices))}</p>
                        </div>
                        <div class="stat-box">
                            <h3>Products</h3>
                            <p>{len(set(d.get('product', 'Unknown') for d in devices))}</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Device Map</h2>
                    <div class="map-container">
        """
        
        # Add map if available
        if map_file and os.path.exists(map_file):
            map_rel_path = os.path.relpath(map_file, os.path.dirname(output_file))
            html_content += f'<iframe src="{map_rel_path}"></iframe>'
        else:
            html_content += '<p>Map not available</p>'
        
        html_content += """
                    </div>
                </div>
                
                <div class="section">
                    <h2>Device Statistics</h2>
        """
        
        # Add charts if available
        for chart_file in chart_files:
            if os.path.exists(chart_file):
                chart_name = os.path.basename(chart_file).replace('.png', '').replace('_', ' ').title()
                chart_rel_path = os.path.relpath(chart_file, os.path.dirname(output_file))
                html_content += f'''
                <div class="chart">
                    <h3>{chart_name}</h3>
                    <img src="{chart_rel_path}" alt="{chart_name}">
                </div>
                '''
        
        # Add vulnerability statistics
        vuln_devices = sum(1 for d in devices if d.get('_vulns'))
        html_content += f"""
                <div class="stats">
                    <div class="stat-box">
                        <h3>Vulnerable Devices</h3>
                        <p>{vuln_devices} ({vuln_devices/len(devices)*100:.1f}%)</p>
                    </div>
        """
        
        # Add credential test statistics if available
        cred_tested = sum(1 for d in devices if d.get('credential_test'))
        cred_vuln = sum(1 for d in devices if d.get('credential_test', {}).get('vulnerable', False))
        if cred_tested > 0:
            html_content += f'''
                    <div class="stat-box">
                        <h3>Default Credential Tests</h3>
                        <p>{cred_tested} devices tested, {cred_vuln} vulnerable ({cred_vuln/cred_tested*100:.1f}% if tested)</p>
                    </div>
            '''
        
        # Add SSL/TLS statistics if available
        ssl_tested = sum(1 for d in devices if d.get('ssl_check'))
        ssl_vuln = sum(1 for d in devices if d.get('ssl_check', {}).get('vulnerable', False))
        if ssl_tested > 0:
            html_content += f'''
                    <div class="stat-box">
                        <h3>SSL/TLS Vulnerabilities</h3>
                        <p>{ssl_vuln} devices vulnerable ({ssl_vuln/ssl_tested*100:.1f}% if tested)</p>
                    </div>
            '''
        
        html_content += """
                </div>
                </div>
                
                <div class="section">
                    <h2>Device List</h2>
                    <table>
                        <tr>
                            <th>IP Address</th>
                            <th>Port</th>
                            <th>Product</th>
                            <th>Organization</th>
                            <th>Country</th>
                            <th>Vulnerabilities</th>
                        </tr>
        """
        
        # Add device rows
        for device in devices:
            ip = device.get('ip_str', 'Unknown')
            port = device.get('port', 'Unknown')
            product = f"{device.get('product', 'Unknown')} {device.get('version', '')}"
            org = device.get('org', 'Unknown')
            country = device.get('location', {}).get('country_name', 'Unknown')
            
            vuln_count = len(device.get('_vulns', []))
            vuln_class = ' class="vulnerable"' if vuln_count > 0 else ''
            
            html_content += f'''
                        <tr{vuln_class}>
                            <td>{ip}</td>
                            <td>{port}</td>
                            <td>{product}</td>
                            <td>{org}</td>
                            <td>{country}</td>
                            <td>{vuln_count}</td>
                        </tr>
            '''
        
        html_content += """
                    </table>
                </div>
                
                <div class="footer">
                    <p>Generated by BlackIce IoT Vulnerability Scanner</p>
                    <p>This report contains sensitive security information. Handle with care.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated at {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Error generating HTML report: {e}")
        return None

def create_network_graph(devices, output_file):
    """Create a network graph visualization showing connections between devices"""
    if not NETWORK_AVAILABLE:
        logger.error("NetworkX and matplotlib not installed. Cannot create network graph.")
        return None
    
    try:
        # Create a new graph
        G = nx.Graph()
        
        # Extract organizations and countries
        orgs = {}
        countries = {}
        
        for device in devices:
            ip = device.get('ip_str', 'Unknown')
            org = device.get('org', 'Unknown')
            country = device.get('location', {}).get('country_name', 'Unknown')
            product = device.get('product', 'Unknown')
            
            # Add device node
            node_label = f"{ip}\n{product}"
            G.add_node(ip, label=node_label, type='device')
            
            # Add organization node if not exists
            if org and org != 'Unknown':
                if org not in orgs:
                    orgs[org] = org
                    G.add_node(org, label=org, type='org')
                G.add_edge(ip, org)
            
            # Add country node if not exists
            if country and country != 'Unknown':
                if country not in countries:
                    countries[country] = country
                    G.add_node(country, label=country, type='country')
                G.add_edge(ip, country)
        
        # Define node colors
        node_colors = []
        for node in G.nodes():
            node_type = G.nodes[node].get('type')
            if node_type == 'device':
                node_colors.append('skyblue')
            elif node_type == 'org':
                node_colors.append('lightgreen')
            elif node_type == 'country':
                node_colors.append('salmon')
        
        # Create the plot
        plt.figure(figsize=(16, 12))
        pos = nx.spring_layout(G, seed=42)
        nx.draw_networkx_nodes(G, pos, node_size=500, node_color=node_colors, alpha=0.8)
        nx.draw_networkx_edges(G, pos, alpha=0.3)
        
        # Add labels with custom font sizes
        labels = {node: G.nodes[node]['label'] for node in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)
        
        plt.title("Network Device Relationships")
        plt.axis('off')
        plt.tight_layout()
        
        # Save to file
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Network graph saved to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Error creating network graph: {e}")
        return None

def create_map(devices, output_file=None):
    """Create a map visualization of device locations"""
    if not FOLIUM_AVAILABLE:
        logger.error("Folium not installed. Cannot create map.")
        return None
    
    # Default output file if not provided
    if not output_file:
        timestamp = int(time.time())
        output_file = f"device_map_{timestamp}.html"
    
    try:
        # Create map centered at the world
        m = folium.Map(location=[0, 0], zoom_start=2, tiles="OpenStreetMap")
        
        # Create marker cluster for better performance with many points
        marker_cluster = MarkerCluster().add_to(m)
        
        # Track countries for summary
        countries = Counter()
        
        # Add markers for each device with location data
        for device in devices:
            # Get location data
            lat = device.get('location', {}).get('latitude')
            lon = device.get('location', {}).get('longitude')
            country = device.get('location', {}).get('country_name', 'Unknown')
            
            if lat is not None and lon is not None:
                # Create popup content
                ip = device.get('ip_str', 'Unknown')
                org = device.get('org', 'Unknown')
                product = device.get('product', 'Unknown')
                port = device.get('port', 'Unknown')
                
                # Determine color based on vulnerability status
                color = 'red' if device.get('_vulns') else 'blue'
                
                # Check for credential test results
                creds_note = ""
                if device.get('credential_test', {}).get('vulnerable', False):
                    color = 'darkred'  # More severe red for credential issues
                    creds = device['credential_test'].get('working_credentials', [])
                    if creds:
                        cred_items = ", ".join([f"{c.get('username')}:{c.get('password')}" for c in creds[:3]])
                        if len(creds) > 3:
                            cred_items += f" and {len(creds)-3} more"
                        creds_note = f"<br><b>Default Credentials Found:</b> {cred_items}"
                
                # Check for SSL/TLS issues
                ssl_note = ""
                if device.get('ssl_check', {}).get('vulnerable', False):
                    issues = device['ssl_check'].get('issues', [])
                    if issues:
                        ssl_note = f"<br><b>SSL/TLS Issues:</b> {', '.join(issues[:3])}"
                        if len(issues) > 3:
                            ssl_note += f" and {len(issues)-3} more"
                
                # Create popup with HTML
                popup_html = f"""
                <div style="width: 300px;">
                    <h3>{product}</h3>
                    <b>IP:</b> {ip}<br>
                    <b>Port:</b> {port}<br>
                    <b>Organization:</b> {org}<br>
                    <b>Country:</b> {country}<br>
                    <b>Vulnerabilities:</b> {len(device.get('_vulns', []))} found
                    {creds_note}
                    {ssl_note}
                </div>
                """
                
                # Add marker to cluster
                folium.Marker(
                    location=[lat, lon],
                    popup=folium.Popup(popup_html, max_width=350),
                    icon=folium.Icon(color=color, icon='server', prefix='fa'),
                ).add_to(marker_cluster)
                
                # Track countries
                if country:
                    countries[country] += 1
        
        # Add country summary to map
        country_summary = "<h3>Devices by Country</h3><ul>"
        for country, count in countries.most_common(10):
            country_summary += f"<li>{country}: {count}</li>"
        country_summary += "</ul>"
        
        folium.LayerControl().add_to(m)
        
        # Add legend to map
        legend_html = f"""
        <div style="position: fixed; 
                    bottom: 50px; left: 50px; width: 250px; height: auto;
                    border:2px solid grey; z-index:9999; background-color:white;
                    padding: 10px; font-size: 14px;">
        <h4>Legend</h4>
        <div><i style="background: blue; width: 15px; height: 15px; display: inline-block;"></i> Secure Device</div>
        <div><i style="background: red; width: 15px; height: 15px; display: inline-block;"></i> Vulnerable Device</div>
        <div><i style="background: darkred; width: 15px; height: 15px; display: inline-block;"></i> Default Credentials</div>
        <div style="margin-top: 10px;">
            {country_summary}
        </div>
        </div>
        """
        m.get_root().html.add_child(folium.Element(legend_html))
        
        # Save to file
        m.save(output_file)
        
        logger.info(f"Map saved to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Error creating map: {e}")
        return None

def create_clustered_map(devices, output_file=None):
    """
    Create a map visualization of devices clustered by network segments
    
    Args:
        devices: List of device dictionaries
        output_file: Path to save the HTML map (optional)
        
    Returns:
        Path to the saved map file or None if an error occurred
    """
    if not FOLIUM_AVAILABLE:
        logger.error("Folium not installed. Cannot create clustered map.")
        return None
    
    # Default output file if not provided
    if not output_file:
        timestamp = int(time.time())
        output_file = f"network_map_{timestamp}.html"
    
    try:
        # Group devices by network segments
        network_segments = {}
        
        for device in devices:
            ip = device.get('ip_str')
            if not ip:
                continue
                
            try:
                # Extract network part (first three octets for /24 networks)
                network = '.'.join(ip.split('.')[:3]) + '.0/24'
                
                if network not in network_segments:
                    network_segments[network] = []
                
                network_segments[network].append(device)
            except Exception as e:
                logger.debug(f"Error processing IP {ip}: {e}")
        
        # Analyze risk for each network segment
        for network, devices_in_network in network_segments.items():
            # Calculate device density
            density = len(devices_in_network)
            
            # Check for mixing sensitive and non-sensitive devices
            has_sensitive = any(is_sensitive_device(device) for device in devices_in_network)
            has_non_sensitive = any(not is_sensitive_device(device) for device in devices_in_network)
            
            # Calculate risk score based on device density and mixing
            risk_score = 0
            
            # Higher density means higher risk
            if density > 20:
                risk_score += 3
            elif density > 10:
                risk_score += 2
            elif density > 5:
                risk_score += 1
            
            # Mixing sensitive and non-sensitive devices is risky
            if has_sensitive and has_non_sensitive:
                risk_score += 3
            
            # More device types means more complex security
            device_types = set()
            for device in devices_in_network:
                device_types.add(device.get('product', 'Unknown'))
                
            if len(device_types) > 5:
                risk_score += 2
            elif len(device_types) > 3:
                risk_score += 1
            
            # Calculate risk level
            if risk_score >= 6:
                risk_level = 'High'
                color = 'red'
            elif risk_score >= 3:
                risk_level = 'Medium'
                color = 'orange'
            else:
                risk_level = 'Low'
                color = 'green'
                
            # Store segment metadata
            for device in devices_in_network:
                if not device.get('network_segment'):
                    device['network_segment'] = {
                        'network': network,
                        'risk_score': risk_score,
                        'risk_level': risk_level,
                        'color': color,
                        'device_count': density
                    }
        
        # Create map centered at the world
        m = folium.Map(location=[0, 0], zoom_start=2, tiles="OpenStreetMap")
        
        # Create a separate layer group for each risk level
        high_risk_group = folium.FeatureGroup(name="High Risk Networks")
        medium_risk_group = folium.FeatureGroup(name="Medium Risk Networks")
        low_risk_group = folium.FeatureGroup(name="Low Risk Networks")
        
        # Add markers for each device with location data
        for device in devices:
            # Get location data
            lat = device.get('location', {}).get('latitude')
            lon = device.get('location', {}).get('longitude')
            
            if lat is not None and lon is not None:
                # Create popup content
                ip = device.get('ip_str', 'Unknown')
                network_data = device.get('network_segment', {})
                network = network_data.get('network', 'Unknown')
                risk_level = network_data.get('risk_level', 'Unknown')
                device_count = network_data.get('device_count', 0)
                
                # Create popup with HTML
                popup_html = f"""
                <div style="width: 300px;">
                    <h3>Network: {network}</h3>
                    <b>Risk Level:</b> {risk_level}<br>
                    <b>Devices in Network:</b> {device_count}<br>
                    <b>This Device:</b> {ip}<br>
                    <b>Product:</b> {device.get('product', 'Unknown')}<br>
                    <b>Organization:</b> {device.get('org', 'Unknown')}<br>
                    <b>Vulnerabilities:</b> {len(device.get('_vulns', []))} found
                </div>
                """
                
                # Determine which layer to add to based on risk level
                if risk_level == 'High':
                    icon_color = 'red'
                    feature_group = high_risk_group
                elif risk_level == 'Medium':
                    icon_color = 'orange'
                    feature_group = medium_risk_group
                else:
                    icon_color = 'green'
                    feature_group = low_risk_group
                
                # Add marker to appropriate group
                folium.Marker(
                    location=[lat, lon],
                    popup=folium.Popup(popup_html, max_width=350),
                    icon=folium.Icon(color=icon_color, icon='sitemap', prefix='fa'),
                ).add_to(feature_group)
        
        # Add all groups to map
        high_risk_group.add_to(m)
        medium_risk_group.add_to(m)
        low_risk_group.add_to(m)
        
        # Add layer control to toggle risk levels
        folium.LayerControl().add_to(m)
        
        # Add legend to map
        legend_html = """
        <div style="position: fixed; 
                    bottom: 50px; left: 50px; width: 250px; height: auto;
                    border:2px solid grey; z-index:9999; background-color:white;
                    padding: 10px; font-size: 14px;">
        <h4>Network Risk Levels</h4>
        <div><i style="background: green; width: 15px; height: 15px; display: inline-block;"></i> Low Risk Network</div>
        <div><i style="background: orange; width: 15px; height: 15px; display: inline-block;"></i> Medium Risk Network</div>
        <div><i style="background: red; width: 15px; height: 15px; display: inline-block;"></i> High Risk Network</div>
        <div style="margin-top: 10px;">
            <p><b>High Risk Factors:</b></p>
            <ul>
                <li>Many devices in same network</li>
                <li>Mix of sensitive and non-sensitive devices</li>
                <li>Many different device types</li>
            </ul>
        </div>
        </div>
        """
        m.get_root().html.add_child(folium.Element(legend_html))
        
        # Save to file
        m.save(output_file)
        
        logger.info(f"Network map saved to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Error creating network map: {e}")
        return None

def parallel_execution(items, func, max_workers=10, desc="Processing"):
    """
    Execute a function on a list of items in parallel using ThreadPoolExecutor
    
    Args:
        items: List of items to process
        func: Function to execute for each item
        max_workers: Maximum number of parallel threads
        desc: Description for the progress bar
    
    Returns:
        List of results
    """
    results = []
    
    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_item = {executor.submit(func, item): item for item in items}
        
        # Process results as they complete
        if TQDM_AVAILABLE:
            # Use tqdm for progress bar if available
            for future in tqdm(as_completed(future_to_item), total=len(items), desc=desc):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error in parallel execution: {e}")
        else:
            # Simple progress output
            for i, future in enumerate(as_completed(future_to_item)):
                try:
                    print(f"{desc}: {i+1}/{len(items)}")
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error in parallel execution: {e}")
    
    return results

def load_cache(cache_file):
    """
    Load data from a cache file
    
    Args:
        cache_file: Path to the cache file
        
    Returns:
        Cached data or empty dict if file doesn't exist or can't be read
    """
    try:
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading cache file {cache_file}: {e}")
    
    return {}

def save_cache(cache_file, data):
    """
    Save data to a cache file
    
    Args:
        cache_file: Path to the cache file
        data: Data to save (must be JSON serializable)
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        
        # Save to file
        with open(cache_file, 'w') as f:
            json.dump(data, f)
            
        logger.debug(f"Cache saved to {cache_file}")
    except Exception as e:
        logger.error(f"Error saving cache to {cache_file}: {e}")

def fingerprint_device_with_nmap(host, port, passive=False):
    """
    Fingerprint a device using Nmap to get OS, services, and vulnerability information
    
    Args:
        host: Device IP address
        port: Device port
        passive: Whether to use passive scanning mode
    
    Returns:
        Dictionary with device information or None if fingerprinting failed
    """
    try:
        # Use Nmap to fingerprint the device
        nmap_args = ["-sV", "--script=vulners", "--script-args=mincvss=7", "--script-args=maxcvss=10"]
        if passive:
            nmap_args.append("--script-updatedb")
        
        result = nmap.scan(host, ports=str(port), arguments=' '.join(nmap_args))
        
        if 'scan' in result and 'hosts' in result['scan'] and host in result['scan']['hosts']:
            host_data = result['scan']['hosts'][host]
            
            if 'ports' in host_data:
                services = []
                for port_data in host_data['ports'].values():
                    if 'service' in port_data:
                        services.append(port_data['service'])
                
                return {
                    'os': [os_match['name'] for os_match in host_data['osmatch']],
                    'services': services,
                    'ports': {port: port_data['state'] for port, port_data in host_data['ports'].items()},
                    'scripts': {script['id']: script['output'] for script in host_data['script']}
                }
        
        return None
    except Exception as e:
        logger.error(f"Error fingerprinting device {host}:{port}: {e}")
        return None

def calculate_cvss_score(base_vector, temporal_vector=None, env_vector=None, use_colors=True):
    """
    Calculate CVSS v3.1 score from vector strings and provide interpretation
    
    Args:
        base_vector (str): CVSS base vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        temporal_vector (str): Optional temporal vector string
        env_vector (str): Optional environmental vector string
        use_colors (bool): Whether to use terminal colors in output
        
    Returns:
        dict: Complete vulnerability assessment with scores, explanation, and recommendations
    """
    if not base_vector or not base_vector.startswith("CVSS:3"):
        logger.warning("Invalid CVSS vector format")
        return None
    
    # Parse base vector
    metrics = {}
    vector_parts = base_vector.split('/')
    
    # Extract base metrics
    for part in vector_parts:
        if ':' in part:
            metric, value = part.split(':')
            metrics[metric] = value
    
    # Extract temporal metrics if provided
    if temporal_vector:
        temporal_parts = temporal_vector.split('/')
        for part in temporal_parts:
            if ':' in part:
                metric, value = part.split(':')
                metrics[metric] = value
    
    # Calculate base score
    # This is a simplified calculation - CVSS has a complex formula
    base_score = 0
    
    # Attack Vector (AV)
    if 'AV' in metrics:
        if metrics['AV'] in CVSS_BASE_METRICS['AV']:
            base_score += CVSS_BASE_METRICS['AV'][metrics['AV']]
    
    # Attack Complexity (AC)
    if 'AC' in metrics:
        if metrics['AC'] in CVSS_BASE_METRICS['AC']:
            base_score += CVSS_BASE_METRICS['AC'][metrics['AC']]
    
    # Privileges Required (PR)
    if 'PR' in metrics:
        if metrics['PR'] in CVSS_BASE_METRICS['PR']:
            base_score += CVSS_BASE_METRICS['PR'][metrics['PR']]
    
    # User Interaction (UI)
    if 'UI' in metrics:
        if metrics['UI'] in CVSS_BASE_METRICS['UI']:
            base_score += CVSS_BASE_METRICS['UI'][metrics['UI']]
    
    # Impact metrics (C, I, A)
    impact_score = 0
    if 'C' in metrics and metrics['C'] in CVSS_BASE_METRICS['C']:
        impact_score += CVSS_BASE_METRICS['C'][metrics['C']]
    if 'I' in metrics and metrics['I'] in CVSS_BASE_METRICS['I']:
        impact_score += CVSS_BASE_METRICS['I'][metrics['I']]
    if 'A' in metrics and metrics['A'] in CVSS_BASE_METRICS['A']:
        impact_score += CVSS_BASE_METRICS['A'][metrics['A']]
    
    # Add impact score with higher weight
    base_score += (impact_score * 1.5)
    
    # Scope change can increase the score
    if 'S' in metrics and metrics['S'] == 'C':
        base_score *= 1.2
    
    # Cap base score at 10.0
    base_score = min(round(base_score, 1), 10.0)
    
    # Calculate temporal score if metrics available
    temporal_score = base_score
    if all(m in metrics for m in ['E', 'RL', 'RC']):
        temporal_factor = 1.0
        if metrics['E'] in CVSS_TEMPORAL_METRICS['E']:
            temporal_factor *= CVSS_TEMPORAL_METRICS['E'][metrics['E']]
        if metrics['RL'] in CVSS_TEMPORAL_METRICS['RL']:
            temporal_factor *= CVSS_TEMPORAL_METRICS['RL'][metrics['RL']]
        if metrics['RC'] in CVSS_TEMPORAL_METRICS['RC']:
            temporal_factor *= CVSS_TEMPORAL_METRICS['RC'][metrics['RC']]
        
        temporal_score = round(base_score * temporal_factor, 1)
    
    # Determine severity
    severity = "NONE"
    for level, threshold in sorted(CVSS_THRESHOLDS.items(), key=lambda x: x[1]):
        if base_score <= threshold:
            severity = level
            break
    
    # Apply color if requested
    severity_display = severity
    if use_colors and COLORAMA_AVAILABLE:
        color_code = CVSS_COLORS.get(severity, "")
        severity_display = f"{color_code}{severity}{Style.RESET_ALL}"
    
    # Prepare interpretation
    interpretation = {
        "base_score": base_score,
        "temporal_score": temporal_score,
        "severity": severity,
        "severity_display": severity_display,
        "vector": base_vector,
        "temporal_vector": temporal_vector,
        "metrics": metrics,
        "scan_frequency": SCAN_FREQUENCY.get(severity, "Unknown")
    }
    
    # Add detailed explanations
    explanation = []
    
    if 'AV' in metrics:
        av_explanations = {
            'N': "The vulnerability can be exploited remotely over the network.",
            'A': "The vulnerability can be exploited from an adjacent network (e.g., same subnet).",
            'L': "The vulnerability requires local access to exploit.",
            'P': "The vulnerability requires physical access to exploit."
        }
        if metrics['AV'] in av_explanations:
            explanation.append(av_explanations[metrics['AV']])
    
    if 'AC' in metrics:
        ac_explanations = {
            'L': "The vulnerability is easy to exploit with no special conditions required.",
            'H': "The vulnerability is difficult to exploit and requires specific conditions."
        }
        if metrics['AC'] in ac_explanations:
            explanation.append(ac_explanations[metrics['AC']])
    
    # IoT-specific recommendations based on the vulnerability
    recommendations = []
    
    # Network-exploitable vulnerabilities
    if 'AV' in metrics and metrics['AV'] == 'N':
        recommendations.append("Isolate the device on a separate network segment.")
        recommendations.append("Implement network-level filtering to restrict access.")
    
    # Authentication/authorization issues
    if 'PR' in metrics and metrics['PR'] == 'N':
        recommendations.append("Implement strong authentication mechanisms.")
        recommendations.append("Change default credentials if present.")
        recommendations.append("Use unique credentials per device.")
    
    # High impact vulnerabilities
    if (('C' in metrics and metrics['C'] == 'H') or 
        ('I' in metrics and metrics['I'] == 'H') or 
        ('A' in metrics and metrics['A'] == 'H')):
        recommendations.append("Prioritize patching or updating firmware.")
        recommendations.append("Consider replacing the device if no patches are available.")
        recommendations.append("Monitor device behavior for indicators of compromise.")
    
    # Add explanation and recommendations to the interpretation
    interpretation["explanation"] = explanation
    interpretation["recommendations"] = recommendations
    
    # Return the complete assessment
    return interpretation

def get_vulnerability_details(vuln_id, extended=False):
    """
    Get detailed information about a vulnerability with enhanced CVSS scoring
    
    Args:
        vuln_id (str): Vulnerability ID (CVE, etc.)
        extended (bool): Whether to include extended details
        
    Returns:
        dict: Vulnerability details with enhanced scoring
    """
    details = {}
    
    try:
        # Check if vuln_id is a CVE
        if vuln_id.startswith("CVE-"):
            # Query NVD API
            params = {
                "cveId": vuln_id
            }
            
            response = cached_request(NVD_API_URL, params=params)
            
            if response and 'vulnerabilities' in response:
                for vuln in response['vulnerabilities']:
                    cve = vuln.get('cve', {})
                    
                    details = {
                        'id': vuln_id,
                        'description': '',
                        'references': [],
                        'cvss_v3': {},
                        'cvss_v2': {},
                        'published': '',
                        'last_modified': ''
                    }
                    
                    # Get descriptions
                    if 'descriptions' in cve:
                        for desc in cve['descriptions']:
                            if desc.get('lang') == 'en':
                                details['description'] = desc.get('value', '')
                                break
                    
                    # Get references
                    if 'references' in cve:
                        details['references'] = [ref.get('url', '') for ref in cve['references']]
                    
                    # Get CVSS metrics
                    metrics = cve.get('metrics', {})
                    
                    # CVSS v3.1 processing with enhanced scoring
                    if 'cvssMetricV31' in metrics:
                        cvss_v3 = metrics['cvssMetricV31'][0]
                        cvss_data = cvss_v3.get('cvssData', {})
                        
                        # Get the CVSS vector string
                        vector = cvss_data.get('vectorString', '')
                        
                        # Calculate enhanced score and interpretation
                        if vector:
                            details['enhanced_scoring'] = calculate_cvss_score(vector)
                        
                        # Store the original CVSS data
                        details['cvss_v3'] = {
                            'vector': vector,
                            'base_score': cvss_data.get('baseScore', 0),
                            'impact_score': cvss_data.get('impactScore', 0),
                            'exploitability_score': cvss_data.get('exploitabilityScore', 0),
                            'base_severity': cvss_data.get('baseSeverity', 'UNKNOWN')
                        }
                    
                    # CVSS v2 data (if available)
                    if 'cvssMetricV2' in metrics:
                        cvss_v2 = metrics['cvssMetricV2'][0]
                        cvss_data = cvss_v2.get('cvssData', {})
                        
                        details['cvss_v2'] = {
                            'vector': cvss_data.get('vectorString', ''),
                            'base_score': cvss_data.get('baseScore', 0),
                            'impact_score': cvss_data.get('impactScore', 0),
                            'exploitability_score': cvss_data.get('exploitabilityScore', 0),
                            'base_severity': cvss_data.get('baseSeverity', 'UNKNOWN')
                        }
                    
                    # Publication and modification dates
                    details['published'] = cve.get('published', '')
                    details['last_modified'] = cve.get('lastModified', '')
                    
                    # Check for IoT-specific terms to apply custom prioritization
                    iot_keywords = ['iot', 'internet of things', 'firmware', 'embedded', 'router', 
                                    'camera', 'webcam', 'smart home', 'smart device', 'connected device']
                    
                    description_lower = details['description'].lower()
                    
                    # Apply custom prioritization
                    if any(keyword in description_lower for keyword in iot_keywords):
                        if details.get('enhanced_scoring', {}).get('severity') == 'CRITICAL':
                            details['custom_priority'] = 'CRITICAL_IOT'
                            details['priority_score'] = VULNERABILITY_PRIORITY['CRITICAL_IOT']
                    
                    if 'default' in description_lower and ('password' in description_lower or 'credential' in description_lower):
                        details['custom_priority'] = 'DEFAULT_CREDS'
                        details['priority_score'] = VULNERABILITY_PRIORITY['DEFAULT_CREDS']
                    
                    if 'exploit' in description_lower or 'poc' in description_lower or 'proof of concept' in description_lower:
                        details['custom_priority'] = 'KNOWN_EXPLOIT'
                        details['priority_score'] = VULNERABILITY_PRIORITY['KNOWN_EXPLOIT']
                    
        return details
    
    except Exception as e:
        logger.error(f"Error getting vulnerability details for {vuln_id}: {str(e)}")
        return details

def display_vulnerability_assessment(vuln_details, verbose=False):
    """
    Display detailed vulnerability assessment with enhanced CVSS scoring
    
    Args:
        vuln_details (dict): Vulnerability details from get_vulnerability_details
        verbose (bool): Whether to show detailed information
    """
    if not vuln_details or not vuln_details.get('id'):
        print("No vulnerability details available")
        return
    
    # Get the enhanced scoring if available
    enhanced = vuln_details.get('enhanced_scoring', {})
    
    # CVSS version and scores
    print("\n" + "=" * 80)
    print(f"VULNERABILITY ASSESSMENT: {vuln_details['id']}")
    print("=" * 80)
    
    # Basic description
    print(f"\nDescription: {vuln_details.get('description', 'No description available')}")
    
    # Display custom priority if available
    if 'custom_priority' in vuln_details:
        priority = vuln_details['custom_priority']
        if COLORAMA_AVAILABLE:
            priority = f"{Fore.MAGENTA}{priority}{Style.RESET_ALL}"
        print(f"\nBlackIce Priority: {priority}")
    
    # CVSS scores
    print("\nScoring:")
    
    # CVSS v3 score
    cvss_v3 = vuln_details.get('cvss_v3', {})
    if cvss_v3:
        base_score = cvss_v3.get('base_score', 'N/A')
        severity = cvss_v3.get('base_severity', 'UNKNOWN')
        
        # Apply coloring to severity if available
        if COLORAMA_AVAILABLE:
            color = CVSS_COLORS.get(severity, "")
            severity = f"{color}{severity}{Style.RESET_ALL}"
            
        print(f"  CVSS v3: {base_score}/10.0 ({severity})")
        
        if enhanced:
            temporal_score = enhanced.get('temporal_score', 'N/A')
            print(f"  Temporal Score: {temporal_score}/10.0")
            
            # Display recommended scanning frequency
            scan_freq = enhanced.get('scan_frequency', 'Unknown')
            print(f"  Recommended Scanning: {scan_freq}")
    
    # CVSS v2 score (if available)
    cvss_v2 = vuln_details.get('cvss_v2', {})
    if cvss_v2:
        print(f"  CVSS v2: {cvss_v2.get('base_score', 'N/A')}/10.0")
    
    # Enhanced explanation of vulnerability
    if enhanced and enhanced.get('explanation'):
        print("\nVulnerability Analysis:")
        for item in enhanced['explanation']:
            print(f"  • {item}")
    
    # IoT-specific recommendations
    if enhanced and enhanced.get('recommendations'):
        print("\nRecommendations:")
        for item in enhanced['recommendations']:
            print(f"  • {item}")
    
    # Technical details for verbose mode
    if verbose:
        print("\nTechnical Details:")
        
        # Display vector string
        if cvss_v3.get('vector'):
            print(f"  Vector: {cvss_v3['vector']}")
        
        # Impact scores
        if 'impact_score' in cvss_v3:
            print(f"  Impact Score: {cvss_v3['impact_score']}")
        if 'exploitability_score' in cvss_v3:
            print(f"  Exploitability Score: {cvss_v3['exploitability_score']}")
        
        # Publication details
        if vuln_details.get('published'):
            published = vuln_details['published'].split('T')[0] if 'T' in vuln_details['published'] else vuln_details['published']
            print(f"  Published: {published}")
        if vuln_details.get('last_modified'):
            modified = vuln_details['last_modified'].split('T')[0] if 'T' in vuln_details['last_modified'] else vuln_details['last_modified']
            print(f"  Last Modified: {modified}")
        
        # References
        if vuln_details.get('references'):
            print("\nReferences:")
            for ref in vuln_details['references'][:5]:  # Limit to 5 references
                print(f"  • {ref}")
            
            remaining = len(vuln_details['references']) - 5
            if remaining > 0:
                print(f"  • And {remaining} more reference(s)...")
    
    print("\n" + "-" * 80)

def display_vulnerability_report(devices, output_file=None):
    """
    Generate and display a comprehensive vulnerability report for scanned devices
    
    Args:
        devices (list): List of device dictionaries
        output_file (str): Optional file to save the report
    """
    # Count vulnerabilities by severity
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "NONE": 0
    }
    
    # Count devices with vulnerabilities
    vulnerable_devices = 0
    total_vulns = 0
    
    # Process devices
    for device in devices:
        device_vulns = device.get('vulns', {})
        
        if device_vulns:
            vulnerable_devices += 1
            total_vulns += len(device_vulns)
            
            # Count by severity
            for vuln_id, vuln_info in device_vulns.items():
                # If we have enhanced scoring
                if isinstance(vuln_info, dict) and 'enhanced_scoring' in vuln_info:
                    severity = vuln_info['enhanced_scoring'].get('severity', 'UNKNOWN')
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                # Otherwise use the base severity if available
                elif isinstance(vuln_info, dict) and 'cvss' in vuln_info:
                    cvss = float(vuln_info['cvss'])
                    # Determine severity based on CVSS thresholds
                    for level, threshold in sorted(CVSS_THRESHOLDS.items(), key=lambda x: x[1]):
                        if cvss <= threshold:
                            severity_counts[level] += 1
                            break
                # Fallback case
                else:
                    severity_counts["UNKNOWN"] = severity_counts.get("UNKNOWN", 0) + 1
    
    # Create the report header
    report = []
    report.append("=" * 80)
    report.append("VULNERABILITY ASSESSMENT REPORT")
    report.append("=" * 80)
    report.append("")
    
    # Summary statistics
    report.append(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Total Devices Scanned: {len(devices)}")
    report.append(f"Vulnerable Devices: {vulnerable_devices} ({(vulnerable_devices/len(devices)*100):.1f}%)")
    report.append(f"Total Vulnerabilities: {total_vulns}")
    report.append("")
    
    # Severity distribution
    report.append("Vulnerability Severity Distribution:")
    for severity, count in severity_counts.items():
        if count > 0:
            # Add coloring for terminal output
            if COLORAMA_AVAILABLE:
                color = CVSS_COLORS.get(severity, "")
                severity_display = f"{color}{severity}{Style.RESET_ALL}"
            else:
                severity_display = severity
                
            # Calculate percentage
            percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
            report.append(f"  • {severity_display}: {count} ({percentage:.1f}%)")
    
    report.append("")
    
    # Top vulnerability types (if we have enhanced data)
    vuln_types = {}
    
    for device in devices:
        for vuln_id, vuln_info in device.get('vulns', {}).items():
            if isinstance(vuln_info, dict) and 'description' in vuln_info:
                # Extract vulnerability type from description (basic approach)
                description = vuln_info['description'].lower()
                
                # Common vulnerability categories
                categories = {
                    'XSS': ['cross-site scripting', 'xss'],
                    'SQL Injection': ['sql injection', 'sqli'],
                    'Command Injection': ['command injection', 'cmdi', 'os command'],
                    'Default Credentials': ['default credential', 'default password'],
                    'Authentication Bypass': ['auth bypass', 'authentication bypass'],
                    'Buffer Overflow': ['buffer overflow', 'buffer overrun', 'stack overflow'],
                    'Information Disclosure': ['information disclosure', 'information leak'],
                    'Privilege Escalation': ['privilege escalation', 'priv esc'],
                    'Denial of Service': ['denial of service', 'dos'],
                    'Outdated Component': ['outdated', 'out of date', 'old version'],
                    'Firmware': ['firmware']
                }
                
                for category, keywords in categories.items():
                    if any(keyword in description for keyword in keywords):
                        vuln_types[category] = vuln_types.get(category, 0) + 1
                        break
    
    # Display top vulnerability types
    if vuln_types:
        report.append("Top Vulnerability Categories:")
        for category, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            report.append(f"  • {category}: {count}")
        
        report.append("")
    
    # Critical vulnerabilities section
    critical_vulns = []
    
    for device in devices:
        device_ip = device.get('ip', 'Unknown')
        device_port = device.get('port', 'Unknown')
        
        for vuln_id, vuln_info in device.get('vulns', {}).items():
            # If we have enhanced scoring
            if isinstance(vuln_info, dict) and 'enhanced_scoring' in vuln_info:
                if vuln_info['enhanced_scoring'].get('severity') == 'CRITICAL':
                    critical_vulns.append({
                        'id': vuln_id,
                        'device': f"{device_ip}:{device_port}",
                        'description': vuln_info.get('description', 'No description'),
                        'score': vuln_info['enhanced_scoring'].get('base_score', 'N/A')
                    })
            # Check for high CVSS score
            elif isinstance(vuln_info, dict) and 'cvss' in vuln_info:
                if float(vuln_info['cvss']) >= 9.0:
                    critical_vulns.append({
                        'id': vuln_id,
                        'device': f"{device_ip}:{device_port}",
                        'description': vuln_info.get('description', 'No description'),
                        'score': vuln_info['cvss']
                    })
    
    # Display critical vulnerabilities
    if critical_vulns:
        report.append("Critical Vulnerabilities (Immediate Action Required):")
        for vuln in critical_vulns:
            report.append(f"  • {vuln['id']} ({vuln['score']}/10.0) on {vuln['device']}")
            # Truncate description if too long
            if len(vuln['description']) > 100:
                report.append(f"    {vuln['description'][:100]}...")
            else:
                report.append(f"    {vuln['description']}")
        
        report.append("")
    
    # Recommendations section
    report.append("General Recommendations:")
    
    # Based on found vulnerabilities
    if severity_counts.get('CRITICAL', 0) > 0:
        report.append("  • URGENT: Address critical vulnerabilities immediately")
        report.append("  • Consider temporarily isolating affected devices until patched")
    
    if severity_counts.get('HIGH', 0) > 0:
        report.append("  • Prioritize patching high severity vulnerabilities")
        report.append("  • Implement network segmentation for vulnerable devices")
    
    if vuln_types.get('Default Credentials', 0) > 0:
        report.append("  • Change all default credentials immediately")
        report.append("  • Implement password policy with strong, unique passwords")
    
    if vuln_types.get('Outdated Component', 0) > 0 or vuln_types.get('Firmware', 0) > 0:
        report.append("  • Establish a regular firmware/software update process")
        report.append("  • Subscribe to vendor security notifications")
    
    # Add scanning recommendation
    highest_severity = "NONE"
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_counts.get(severity, 0) > 0:
            highest_severity = severity
            break
    
    report.append(f"  • Recommended scanning frequency: {SCAN_FREQUENCY.get(highest_severity, 'Monthly')}")
    
    # Join the report and print
    report_text = "\n".join(report)
    print(report_text)
    
    # Save to file if requested
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report_text)
        print(f"\nReport saved to {output_file}")
    
    return report_text
