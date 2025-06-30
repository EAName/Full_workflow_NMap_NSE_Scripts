#Full-Featured Nmap + NSE + NetworkMaps Workflow

[![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/) 
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) 

---

## ⚡️ Summary

**This** is a powerful, open-source workflow for network discovery, vulnerability scanning, and dynamic topology visualization. It combines Nmap + NSE scripts with NetworkMaps for real-time, interactive network mapping—delivering functionality similar to Morpheus Map, but fully under your control.

- **Automated discovery, scanning, and mapping**
- **Customizable scan profiles and scripts**
- **Beautiful, interactive reports and topology maps**
- **Open-source, extensible, and easy to use**

> **Full setup and usage instructions:** See [`SETUP_AND_USAGE.md`](SETUP_AND_USAGE.md)

---

# Full-Featured Nmap + NSE + NetworkMaps Workflow

A comprehensive open-source solution for network discovery, vulnerability scanning, and dynamic topology visualization - similar to Morpheus Map but fully under your control.

## 🎯 Overview

This workflow combines:
- **Nmap + NSE Scripts**: Advanced network discovery and vulnerability scanning
- **NetworkMaps**: Dynamic topology visualization with real-time updates
- **Automated Workflows**: Streamlined scanning and mapping processes
- **Custom Scripts**: Enhanced discovery and security assessment capabilities

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Discovery     │    │   Vulnerability │    │   Visualization │
│   Phase         │───▶│   Assessment    │───▶│   & Mapping     │
│                 │    │                 │    │                 │
│ • Host Discovery│    │ • NSE Scripts   │    │ • NetworkMaps   │
│ • Port Scanning │    │ • CVE Detection │    │ • Topology View │
│ • Service Enum  │    │ • Risk Scoring  │    │ • Real-time     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
```bash
# Install required tools
sudo apt-get update
sudo apt-get install -y nmap python3 python3-pip git

# Install Python dependencies
pip3 install -r requirements.txt

# Install NetworkMaps (if not already installed)
git clone https://github.com/networkmaps/networkmaps.git
cd networkmaps && npm install
```

### Basic Usage
```bash
# Run complete workflow
python3 main.py --target 192.168.1.0/24 --output results/

# Run discovery only
python3 discovery_scanner.py --target 192.168.1.0/24

# Run vulnerability assessment
python3 vulnerability_scanner.py --hosts discovered_hosts.txt

# Generate topology map
python3 topology_mapper.py --input scan_results.json
```

## 📁 Project Structure

```
Full_workflow_NMap_NSE_Scripts/
├── main.py                      # Main workflow orchestrator
├── discovery_scanner.py         # Host and service discovery
├── vulnerability_scanner.py     # NSE-based vulnerability scanning
├── topology_mapper.py          # Network topology visualization
├── custom_scripts/             # Custom NSE scripts
│   ├── enhanced-discovery.nse
│   ├── service-enum.nse
│   └── vulnerability-detect.nse
├── config/                     # Configuration files
│   ├── scan_profiles.json
│   ├── nse_scripts.json
│   └── networkmaps_config.json
├── templates/                  # Report and visualization templates
│   ├── html_report.html
│   ├── json_schema.json
│   └── networkmap_template.js
├── utils/                      # Utility functions
│   ├── parser.py
│   ├── reporter.py
│   └── visualizer.py
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## 🔧 Features

### 1. Advanced Discovery
- **Host Discovery**: Multiple discovery methods (ping, ARP, TCP SYN)
- **Port Scanning**: Comprehensive port enumeration
- **Service Detection**: Accurate service and version identification
- **OS Detection**: Operating system fingerprinting

### 2. Vulnerability Assessment
- **NSE Scripts**: Extensive vulnerability detection
- **CVE Mapping**: Automatic CVE correlation
- **Risk Scoring**: Prioritized vulnerability assessment
- **Custom Scripts**: Enhanced detection capabilities

### 3. Dynamic Visualization
- **Real-time Updates**: Live topology changes
- **Interactive Maps**: Clickable network elements
- **Multiple Views**: Physical, logical, and security views
- **Export Options**: PNG, SVG, PDF formats

### 4. Automation & Integration
- **Workflow Automation**: End-to-end scanning process
- **API Integration**: RESTful API for external tools
- **Scheduling**: Automated periodic scans
- **Alerting**: Real-time notifications

## 📊 Scan Profiles

### Quick Scan
```bash
python3 main.py --profile quick --target 192.168.1.0/24
```
- Host discovery only
- Common ports (top 100)
- Basic service detection

### Standard Scan
```bash
python3 main.py --profile standard --target 192.168.1.0/24
```
- Full port scan
- Service enumeration
- Basic vulnerability assessment

### Comprehensive Scan
```bash
python3 main.py --profile comprehensive --target 192.168.1.0/24
```
- All ports
- Advanced NSE scripts
- Full vulnerability assessment
- OS detection

### Stealth Scan
```bash
python3 main.py --profile stealth --target 192.168.1.0/24
```
- Slow, quiet scanning
- Evasion techniques
- Minimal network impact

## 🔍 Custom NSE Scripts

### Enhanced Discovery Script
```lua
-- custom_scripts/enhanced-discovery.nse
description = "Enhanced network discovery with service correlation"
author = "Your Name"
license = "Same as Nmap"

local nmap = require "nmap"
local stdnse = require "stdnse"

-- Implementation for advanced discovery
```

### Service Enumeration Script
```lua
-- custom_scripts/service-enum.nse
description = "Comprehensive service enumeration"
author = "Your Name"
license = "Same as Nmap"

-- Implementation for detailed service enumeration
```

## 📈 Output Formats

### JSON Output
```json
{
  "scan_info": {
    "target": "192.168.1.0/24",
    "start_time": "2024-01-15T10:30:00Z",
    "end_time": "2024-01-15T11:45:00Z"
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "ports": [
        {
          "port": 80,
          "service": "http",
          "version": "nginx/1.18.0",
          "vulnerabilities": []
        }
      ]
    }
  ]
}
```

### HTML Report
- Interactive web-based reports
- Filterable results
- Exportable data
- Visual charts and graphs

### NetworkMaps Integration
- Real-time topology updates
- Interactive network visualization
- Custom node and edge styling
- Export to various formats

## 🔒 Security Considerations

### Legal Compliance
- Always obtain proper authorization
- Respect network policies
- Follow responsible disclosure
- Document all scanning activities

### Best Practices
- Use appropriate scan profiles
- Implement rate limiting
- Monitor network impact
- Secure result storage

## 🛠️ Configuration

### Scan Profiles Configuration
```json
{
  "quick": {
    "ports": "top-100",
    "scripts": ["default"],
    "timing": 3,
    "max_retries": 2
  },
  "comprehensive": {
    "ports": "all",
    "scripts": ["default", "vuln", "auth", "discovery"],
    "timing": 1,
    "max_retries": 3
  }
}
```

### NSE Scripts Configuration
```json
{
  "discovery": [
    "broadcast-dhcp-discover",
    "broadcast-dns-service-discovery",
    "broadcast-netbios-master-browser"
  ],
  "vulnerability": [
    "vuln",
    "auth",
    "default"
  ]
}
```

## 📝 Usage Examples

### Enterprise Network Scan
```bash
# Scan enterprise network with comprehensive profile
python3 main.py \
  --target 10.0.0.0/8 \
  --profile comprehensive \
  --output enterprise_scan_$(date +%Y%m%d) \
  --exclude 10.0.0.1,10.0.0.254 \
  --rate-limit 1000
```

### Continuous Monitoring
```bash
# Set up automated scanning
crontab -e

# Add this line for daily scans
0 2 * * * /usr/bin/python3 /path/to/main.py --target 192.168.1.0/24 --profile standard --output /var/log/scans/
```

### API Integration
```bash
# Start API server
python3 api_server.py --port 8080

# Use API for scanning
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24", "profile": "standard"}'
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your custom NSE scripts
4. Update documentation
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Nmap Security Scanner
- NetworkMaps Project
- NSE Script Community
- Open Source Security Tools

## 📞 Support

For issues and questions:
- Create an issue on GitHub
- Check the documentation
- Review example configurations
- Join the community discussions 