#!/usr/bin/env python3
"""
BlackIce Configuration

This file contains all the configuration variables and settings for the BlackIce IoT scanner.
Edit this file to customize your setup and API keys.
"""

# API Keys (replace with your actual keys)
SHODAN_API_KEY = "QMF4fyJhnPZnCyWELcKy5JkHdfsOZXDG"

# Version Information
VERSION = "1.0.0"
GITHUB_REPO = "https://github.com/yourusername/blackice"
USER_AGENT = f"BlackIce-Scanner/{VERSION}"

# Auto-update configuration
AUTO_CHECK_UPDATES = True  # Whether to check for updates on startup

# API Endpoints
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_API_URL = "https://www.exploit-db.com/search?q="  # Web scraping fallback
EXPLOITDB_CSV_URL = "https://github.com/offensive-security/exploitdb/raw/master/files_exploits.csv"
SHODAN_EXPLOITS_URL = "https://exploits.shodan.io/api/search"
VULNERS_API_URL = "https://vulners.com/api/v3/search/id/"

# File Paths and Directories
import os
CACHE_DIR = os.path.expanduser("~/.blackice/cache")
LOG_DIR = os.path.expanduser("~/.blackice/logs")
HISTORY_DB_FILE = os.path.expanduser("~/.blackice/device_history.json")
EXPLOITDB_CACHE_FILE = os.path.join(CACHE_DIR, "exploitdb_cache.json")
NVD_CACHE_FILE = os.path.join(CACHE_DIR, "nvd_cache.json")
SHODAN_CACHE_FILE = os.path.join(CACHE_DIR, "shodan_cache.json")

# Cache Configuration
CACHE_TIMEOUT = 24 * 60 * 60  # 24 hours (in seconds)

# CVSS Scoring System Configuration
# Common Vulnerability Scoring System (CVSS) is a free and open industry standard for 
# assessing the severity of security vulnerabilities

# Basic severity thresholds (CVSS v3.1)
CVSS_THRESHOLDS = {
    "NONE": 0.0,      # No impact
    "LOW": 3.9,       # Low severity (0.1-3.9)
    "MEDIUM": 6.9,    # Medium severity (4.0-6.9)
    "HIGH": 8.9,      # High severity (7.0-8.9)
    "CRITICAL": 10.0   # Critical severity (9.0-10.0)
}

# Terminal color codes for severity levels
CVSS_COLORS = {
    "NONE": "\033[37m",      # White
    "LOW": "\033[34m",       # Blue
    "MEDIUM": "\033[33m",    # Yellow
    "HIGH": "\033[31m",      # Red
    "CRITICAL": "\033[35m"   # Magenta
}

# CVSS v3.1 Base Metrics
CVSS_BASE_METRICS = {
    # Attack Vector (AV) - Context by which vulnerability exploitation is possible
    "AV": {
        "N": 0.85,  # Network - Remotely exploitable
        "A": 0.62,  # Adjacent - Adjacent network exploitable
        "L": 0.55,  # Local - Local access required
        "P": 0.2    # Physical - Physical access required
    },
    # Attack Complexity (AC) - Conditions beyond the attacker's control that must exist to exploit
    "AC": {
        "L": 0.77,  # Low - No specialized conditions needed
        "H": 0.44   # High - Specialized conditions needed
    },
    # Privileges Required (PR) - Level of privileges an attacker must possess
    "PR": {
        "N": 0.85,  # None - No privileges required
        "L": 0.62,  # Low - Low privileges required
        "H": 0.27   # High - High privileges required
    },
    # User Interaction (UI) - Whether the vulnerability can be exploited without user interaction
    "UI": {
        "N": 0.85,  # None - No user interaction required
        "R": 0.62   # Required - User interaction required
    },
    # Scope (S) - Whether a vulnerability in one component impacts resources beyond its security scope
    "S": {
        "U": False, # Unchanged - Impact limited to scope
        "C": True   # Changed - Impact extends beyond scope
    },
    # Confidentiality Impact (C) - Impact on confidentiality of information
    "C": {
        "N": 0.0,   # None - No impact
        "L": 0.22,  # Low - Limited impact
        "H": 0.56   # High - High impact
    },
    # Integrity Impact (I) - Impact on integrity of information
    "I": {
        "N": 0.0,   # None - No impact
        "L": 0.22,  # Low - Limited impact
        "H": 0.56   # High - High impact
    },
    # Availability Impact (A) - Impact on availability of the impacted component
    "A": {
        "N": 0.0,   # None - No impact
        "L": 0.22,  # Low - Limited impact
        "H": 0.56   # High - High impact
    }
}

# CVSS v3.1 Temporal Metrics (these affect the score over time)
CVSS_TEMPORAL_METRICS = {
    # Exploit Code Maturity (E)
    "E": {
        "X": 1.0,   # Not Defined
        "H": 1.0,   # High - Functional autonomous code exists
        "F": 0.97,  # Functional - Functional exploit code exists
        "P": 0.94,  # Proof-of-Concept - PoC exploit code exists
        "U": 0.91   # Unproven - No exploit code is available
    },
    # Remediation Level (RL)
    "RL": {
        "X": 1.0,   # Not Defined
        "U": 1.0,   # Unavailable - No solution available
        "W": 0.97,  # Workaround - Unofficial, non-vendor solution
        "T": 0.96,  # Temporary Fix - Official but temporary fix
        "O": 0.95   # Official Fix - Complete vendor solution
    },
    # Report Confidence (RC)
    "RC": {
        "X": 1.0,   # Not Defined
        "C": 1.0,   # Confirmed - Acknowledged by vendor
        "R": 0.96,  # Reasonable - Based on reproducible details
        "U": 0.92   # Unknown - Reports exist, but unconfirmed
    }
}

# Prioritization scoring (custom metric for BlackIce)
VULNERABILITY_PRIORITY = {
    "CRITICAL_IOT": 10.0,    # Critical vulnerabilities in IoT devices
    "HIGH_EXPOSURE": 9.0,    # High severity + public internet exposure
    "DEFAULT_CREDS": 8.5,    # Default credentials still enabled
    "KNOWN_EXPLOIT": 8.0,    # Known exploits available
    "NO_PATCH": 7.5,         # No patch available from vendor
    "WEAK_CRYPTO": 7.0,      # Weak cryptography implementation
    "OUTDATED_FIRMWARE": 6.5, # Significantly outdated firmware
    "INFORMATION_LEAKAGE": 5.0 # Information leakage
}

# Scoring weight customization
SCORING_WEIGHTS = {
    "CVSS_BASE": 0.6,        # Weight for CVSS base score
    "TEMPORAL": 0.15,        # Weight for temporal factors
    "EXPOSURE": 0.15,        # Weight for exposure level
    "BUSINESS_IMPACT": 0.1   # Weight for business impact
}

# Scanning frequency recommendations based on severity
SCAN_FREQUENCY = {
    "CRITICAL": "Daily",
    "HIGH": "Weekly",
    "MEDIUM": "Monthly",
    "LOW": "Quarterly",
    "NONE": "Annually"
}

# Proxy Configuration
PROXY_ENABLED = False
HTTP_PROXY = None
HTTPS_PROXY = None
SOCKS_PROXY = None
PROXY_USERNAME = None
PROXY_PASSWORD = None

# Scanning Configuration
PASSIVE_MODE = False
SCAN_DELAY_MIN = 1   # Minimum delay between requests in seconds
SCAN_DELAY_MAX = 5   # Maximum delay between requests in seconds
NMAP_ARGS_PASSIVE = "-sL -Pn"  # List scan, no ping
NMAP_ARGS_ACTIVE = "-sS -sV -O --script vulners,http-title,http-headers,ssl-cert"  # SYN scan with service/OS detection
MAX_PARALLEL_SCANS = 5  # Default number of parallel scans

# Default Credential List for Testing
DEFAULT_CREDENTIALS = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "1234"},
    {"username": "admin", "password": "12345"},
    {"username": "admin", "password": ""},
    {"username": "root", "password": "root"},
    {"username": "root", "password": ""},
    {"username": "root", "password": "admin"},
    {"username": "user", "password": "user"},
    {"username": "guest", "password": "guest"}
]

# Common device types and their search queries
SEARCH_TEMPLATES = {
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

# Search templates for common IoT devices (for backwards compatibility)
SEARCH_TEMPLATES = {
    "webcams": "webcam has_screenshot:true",
    "routers": "router port:80 title:\"router\"",
    "smart_tvs": "\"smart tv\" port:80",
    "ip_cameras": "title:\"IP Camera\" country:{country}",
    "home_automation": "home automation device port:80",
    "open_telnet": "port:23 -filtered",
    "open_mqtt": "port:1883 -authentication",
    "default_credentials": "default password",
    "mikrotik": "port:8291 product:\"MikroTik\"",
    "hikvision": "product:\"Hikvision\"",
    "dlink": "product:\"D-Link\"",
    "iot_dashboard": "title:\"IoT Dashboard\"",
    "iot_gateway": "title:\"IoT Gateway\"",
    "smart_plugs": "\"smart plug\" OR \"smart socket\"",
    "industrial_control": "scada OR plc OR hmi port:502"
}

# Create necessary directories
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True) 