# EAName: Full-Featured Nmap + NSE + NetworkMaps Workflow

A powerful, open-source workflow for network discovery, vulnerability scanning, and dynamic topology visualization. Inspired by Morpheus Map, but fully under your control.

---

## 🚀 Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/EAName.git
cd EAName
```

### 2. Install System Dependencies
- **Nmap** (with NSE support)
- **Python 3.7+**
- **Node.js & npm** (for NetworkMaps visualization)

#### On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y nmap python3 python3-pip git nodejs npm
```

#### On macOS (with Homebrew):
```bash
brew install nmap python3 node
```

### 3. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### 4. (Optional) Install NetworkMaps
```bash
git clone https://github.com/networkmaps/networkmaps.git
cd networkmaps
npm install
cd ..
```

### 5. Permissions
Some scans require root/administrator privileges. Use `sudo` if needed:
```bash
sudo python3 main.py --target 192.168.1.0/24
```

---

## 🛠️ Usage Instructions

### Basic Workflow
Run the main orchestrator to perform discovery, vulnerability scanning, and visualization:
```bash
python3 main.py --target 192.168.1.0/24 --output results/
```

### Scan Profiles
Choose a scan profile for different levels of depth and stealth:
```bash
python3 main.py --target 192.168.1.0/24 --profile quick
python3 main.py --target 192.168.1.0/24 --profile standard
python3 main.py --target 192.168.1.0/24 --profile comprehensive
python3 main.py --target 192.168.1.0/24 --profile stealth
```

### Exclude Hosts
```bash
python3 main.py --target 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
```

### Rate Limiting
```bash
python3 main.py --target 192.168.1.0/24 --rate-limit 500
```

### Output
- Results are saved in the specified output directory (default: `results/`).
- Reports are generated in HTML, JSON, and text formats.
- Topology maps are generated as interactive HTML files.

### Custom NSE Scripts
- Place your custom NSE scripts in the `custom_scripts/` directory.
- Reference them in `config/nse_scripts.json` under the `custom` category.

### Advanced: Run Individual Phases
- **Discovery only:**
  ```bash
  python3 discovery_scanner.py --target 192.168.1.0/24
  ```
- **Vulnerability scan only:**
  ```bash
  python3 vulnerability_scanner.py --hosts discovered_hosts.txt
  ```
- **Topology mapping only:**
  ```bash
  python3 topology_mapper.py --input scan_results.json
  ```

### Scheduling (Automated Scans)
Use `cron` or Task Scheduler to automate scans:
```bash
crontab -e
# Add this line for daily scans at 2am
0 2 * * * /usr/bin/python3 /path/to/main.py --target 192.168.1.0/24 --profile standard --output /var/log/scans/
```

### API Integration (Optional)
Start the API server (if implemented):
```bash
python3 api_server.py --port 8080
```
Send scan requests:
```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24", "profile": "standard"}'
```

---

## 📁 Project Structure

```
EAName/
├── main.py
├── discovery_scanner.py
├── vulnerability_scanner.py
├── topology_mapper.py
├── custom_scripts/
│   ├── enhanced-discovery.nse
│   ├── service-enum.nse
│   └── vulnerability-detect.nse
├── config/
│   ├── scan_profiles.json
│   ├── nse_scripts.json
│   └── networkmaps_config.json
├── templates/
│   └── html_report.html
├── utils/
│   ├── parser.py
│   └── reporter.py
├── requirements.txt
├── README.md
└── SETUP_AND_USAGE.md
```

---

## 📝 Notes
- **Legal:** Only scan networks you own or have explicit permission to test.
- **Performance:** Large networks may take significant time/resources.
- **Customization:** Tweak config files and scripts to fit your environment.

---

## 🙋 Need Help?
- Open an issue on GitHub
- Check the README and this guide
- Join the open-source security community 