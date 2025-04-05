# BlackIce - IoT Vulnerability Scanner

<div align="center">

![BlackIce Logo](https://via.placeholder.com/200x200?text=BlackIce)

[![Python 3.6+](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)](https://github.com/yourusername/blackice/commits/main)
[![Release](https://img.shields.io/badge/Release-v1.0.0-orange.svg)](https://github.com/yourusername/blackice/releases)

</div>

A comprehensive tool for finding, analyzing, and assessing security vulnerabilities in Internet of Things (IoT) devices using the Shodan API and other security tools.

> ⚠️ **Disclaimer**: This tool is for educational and authorized security testing only. Unauthorized scanning may be illegal.

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Vulnerability Scoring](#-vulnerability-scoring)
- [Advanced Features](#-advanced-features)
- [Screenshots](#-screenshots)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

- 🔍 **IoT Device Discovery**: Leverage Shodan API to find internet-connected devices
- 🛡️ **Vulnerability Assessment**: Complete CVSS v3.1 scoring and analysis
- 🔑 **Default Credential Testing**: Check devices for common default passwords
- 🌐 **Network Analysis**: Segmentation analysis and relationship mapping
- 🔒 **SSL/TLS Security**: Check for encryption vulnerabilities
- 💥 **Exploit Integration**: Connect with ExploitDB and Vulners databases
- 👣 **Device Fingerprinting**: Identify devices using Nmap
- 📊 **Visualization**: Create maps, charts, and network graphs
- 📝 **Historical Tracking**: Monitor devices for changes over time
- 🕵️ **Anonymous Mode**: Proxy support for stealth scanning
- 🎨 **Terminal UI**: Colorful, interactive console interface
- ⚡ **Performance**: Parallel processing for faster scanning

## 🚀 Installation

### Requirements

- Python 3.6+
- Shodan API key ([Get one here](https://account.shodan.io/register))
- Dependencies listed in `requirements.txt`

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/blackice.git
cd blackice

# Install dependencies
pip install -r requirements.txt

# Check dependency status
python BlackIce_fixed.py --check-deps
```

### Docker (Alternative)

```bash
# Build the Docker image
docker build -t blackice .

# Run BlackIce in a container
docker run -it --rm blackice
```

## ⚙️ Configuration

BlackIce uses a separate `config.py` file for all settings, making it easy to manage API keys and preferences.

### Setting Up Your API Key

You can configure your API key in one of these ways:

1. **Using the setup assistant**:
```bash
python BlackIce_fixed.py --setup
```

2. **Editing config.py directly**:
```python
# In config.py
SHODAN_API_KEY = "your_shodan_api_key_here"
```

3. **Using environment variables**:
```bash
export SHODAN_API_KEY="your_api_key_here"
```

### Configuration Options

The `config.py` file contains settings for:

- API keys and endpoints
- Cache and file paths
- CVSS scoring parameters
- Proxy configuration
- Scanning modes and limits
- Default credential lists

## 📖 Usage

### Interactive Shell Mode

```bash
python BlackIce_fixed.py --interactive
```

This launches a command shell with various commands for exploration:

```
BlackIce> help
BlackIce> search webcam country:US limit:10
BlackIce> test_credentials
BlackIce> visualize
```

### Command Line Mode

#### Basic Search

```bash
python BlackIce_fixed.py --query "webcam" --limit 50
```

#### Using Search Templates

```bash
python BlackIce_fixed.py --template ip_cameras --country JP
```

Available templates include:
- `ip_cameras`, `routers`, `smart_tvs`, `printers`
- `industrial_control`, `medical_devices`
- `default_credentials`, `vulnerable_ssh`

#### Vulnerability Assessment

```bash
python BlackIce_fixed.py --query "router port:80" --check-vulns
```

#### Creating Visualizations

```bash
# All visualizations
python BlackIce_fixed.py --query "webcam" --visualize

# Specific types
python BlackIce_fixed.py --query "industrial_control" --map --charts
```

### Help & Options

```bash
python BlackIce_fixed.py --help
```

## 📊 Vulnerability Scoring

BlackIce uses the Common Vulnerability Scoring System (CVSS) v3.1 with IoT-specific enhancements.

### Severity Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| **Critical** | 9.0-10.0 | Severe vulnerability, immediate action required |
| **High** | 7.0-8.9 | Serious vulnerability, prioritize remediation |
| **Medium** | 4.0-6.9 | Significant concern, should be addressed |
| **Low** | 0.1-3.9 | Minimal impact, limited concern |
| **None** | 0.0 | No impact |

### IoT-Specific Prioritization

BlackIce enhances standard CVSS with IoT-specific considerations:

- **Critical IoT**: Vulnerabilities affecting critical IoT infrastructure
- **High Exposure**: Internet-exposed vulnerable devices
- **Default Credentials**: Devices using factory passwords
- **Known Exploit**: Vulnerabilities with available exploits
- **Weak Crypto**: Cryptographic implementation flaws
- **Outdated Firmware**: Significantly outdated systems

## 🛠️ Advanced Features

### Proxy Support

For anonymous scanning:

```bash
python BlackIce_fixed.py --proxy "http://proxyserver:port" --query "webcam"
```

### Passive Scanning Mode

For stealthier operation:

```bash
python BlackIce_fixed.py --passive --query "router"
```

### Credential Testing

Test devices for default passwords:

```bash
python BlackIce_fixed.py --query "router" --test-credentials
```

### Output Formats

```bash
# Export as JSON
python BlackIce_fixed.py --query "webcam" --format json --output results.json

# Export as CSV
python BlackIce_fixed.py --query "webcam" --format csv --output results.csv
```

## 📸 Screenshots

<div align="center">
  <img src="https://via.placeholder.com/800x450?text=BlackIce+Dashboard" alt="BlackIce Dashboard" width="80%"/>
  <p><em>BlackIce Dashboard</em></p>
  
  <img src="https://via.placeholder.com/800x450?text=Vulnerability+Report" alt="Vulnerability Report" width="80%"/>
  <p><em>Vulnerability Assessment Report</em></p>
  
  <img src="https://via.placeholder.com/800x450?text=Device+Map" alt="Device Map" width="80%"/>
  <p><em>Global Device Map</em></p>
</div>

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and follow the code style.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <p>Made with ❤️ for the security research community</p>
  <p>© 2023 BlackIce Project</p>
</div> 