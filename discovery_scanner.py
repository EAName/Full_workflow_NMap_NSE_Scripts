#!/usr/bin/env python3
"""
Discovery Scanner Module
Handles network discovery, host enumeration, and initial port scanning
"""

import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional


class DiscoveryScanner:
    """Handles network discovery and host enumeration"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.nmap_path = self._find_nmap()
    
    def _find_nmap(self) -> str:
        """Find nmap executable path"""
        try:
            result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        # Common nmap locations
        common_paths = ['/usr/bin/nmap', '/usr/local/bin/nmap', '/opt/nmap/bin/nmap']
        for path in common_paths:
            if Path(path).exists():
                return path
        
        raise FileNotFoundError("Nmap not found. Please install nmap first.")
    
    def run_discovery(self, config: Dict) -> Dict:
        """Run network discovery scan"""
        self.logger.info(f"Starting discovery scan for {config['target']}")
        
        # Build nmap command
        cmd = self._build_discovery_command(config)
        
        # Execute scan
        start_time = time.time()
        result = self._execute_nmap_scan(cmd, config)
        end_time = time.time()
        
        return {
            "command": cmd,
            "execution_time": end_time - start_time,
            "success": result["success"],
            "output_file": config["output"],
            "error": result.get("error")
        }
    
    def _build_discovery_command(self, config: Dict) -> List[str]:
        """Build nmap discovery command"""
        cmd = [self.nmap_path]
        
        # Basic options
        cmd.extend([
            "-sS",  # SYN scan
            "-sU",  # UDP scan
            "-Pn",  # Skip host discovery (we'll do it separately)
            "-n",   # No DNS resolution
            "-oX", config["output"]  # XML output
        ])
        
        # Port selection based on profile
        profile = config["profile"]
        if profile["ports"] == "top-100":
            cmd.extend(["--top-ports", "100"])
        elif profile["ports"] == "top-1000":
            cmd.extend(["--top-ports", "1000"])
        elif profile["ports"] == "all":
            cmd.extend(["-p-"])
        else:
            cmd.extend(["-p", profile["ports"]])
        
        # Timing template
        timing_map = {1: "T0", 2: "T1", 3: "T2", 4: "T3", 5: "T4"}
        cmd.extend([f"-{timing_map.get(profile['timing'], 'T3')}"])
        
        # Retries
        cmd.extend([f"--max-retries", str(profile["max_retries"])])
        
        # OS detection
        if profile.get("os_detection", False):
            cmd.extend(["-O"])
        
        # Scripts
        if "scripts" in profile and profile["scripts"]:
            scripts = ",".join(profile["scripts"])
            cmd.extend([f"--script={scripts}"])
        
        # Rate limiting
        if config.get("rate_limit"):
            cmd.extend([f"--min-rate", str(config["rate_limit"])])
        
        # Exclude hosts
        if config.get("exclude"):
            cmd.extend([f"--exclude", config["exclude"]])
        
        # Target
        cmd.append(config["target"])
        
        return cmd
    
    def _execute_nmap_scan(self, cmd: List[str], config: Dict) -> Dict:
        """Execute nmap scan with proper error handling"""
        try:
            self.logger.info(f"Executing: {' '.join(cmd)}")
            
            # Run nmap process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitor progress
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.logger.info("Discovery scan completed successfully")
                return {"success": True}
            else:
                error_msg = stderr.strip() if stderr else "Unknown error"
                self.logger.error(f"Discovery scan failed: {error_msg}")
                return {"success": False, "error": error_msg}
                
        except Exception as e:
            self.logger.error(f"Error executing discovery scan: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def run_host_discovery(self, target: str, exclude: Optional[str] = None) -> Dict:
        """Run host discovery only (ping sweep)"""
        self.logger.info(f"Running host discovery for {target}")
        
        cmd = [self.nmap_path, "-sn", "-n", "-oX", "-"]
        
        if exclude:
            cmd.extend(["--exclude", exclude])
        
        cmd.append(target)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse XML output to extract hosts
                hosts = self._parse_host_discovery_xml(result.stdout)
                return {
                    "success": True,
                    "hosts": hosts,
                    "count": len(hosts)
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _parse_host_discovery_xml(self, xml_output: str) -> List[str]:
        """Parse host discovery XML output"""
        hosts = []
        
        # Simple XML parsing for host discovery
        lines = xml_output.split('\n')
        for line in lines:
            if '<address addr=' in line and 'addrtype="ipv4"' in line:
                # Extract IP address
                start = line.find('addr="') + 6
                end = line.find('"', start)
                if start > 5 and end > start:
                    ip = line[start:end]
                    hosts.append(ip)
        
        return hosts
    
    def run_service_discovery(self, hosts: List[str], config: Dict) -> Dict:
        """Run service discovery on discovered hosts"""
        self.logger.info(f"Running service discovery on {len(hosts)} hosts")
        
        if not hosts:
            return {"success": False, "error": "No hosts provided"}
        
        # Create host list file
        hosts_file = Path("temp_hosts.txt")
        with open(hosts_file, 'w') as f:
            for host in hosts:
                f.write(f"{host}\n")
        
        try:
            # Build service discovery command
            cmd = [self.nmap_path, "-sS", "-sV", "-n", "-oX", config["output"]]
            
            # Add timing and other options
            timing_map = {1: "T0", 2: "T1", 3: "T2", 4: "T3", 5: "T4"}
            cmd.extend([f"-{timing_map.get(config['profile']['timing'], 'T3')}"])
            
            # Add scripts
            if "scripts" in config["profile"] and config["profile"]["scripts"]:
                scripts = ",".join(config["profile"]["scripts"])
                cmd.extend([f"--script={scripts}"])
            
            # Add host list
            cmd.extend(["-iL", str(hosts_file)])
            
            # Execute scan
            result = self._execute_nmap_scan(cmd, config)
            
            return result
            
        finally:
            # Clean up temporary file
            if hosts_file.exists():
                hosts_file.unlink()
    
    def get_scan_statistics(self, xml_file: str) -> Dict:
        """Get statistics from nmap XML output"""
        try:
            with open(xml_file, 'r') as f:
                content = f.read()
            
            stats = {
                "hosts_up": 0,
                "hosts_down": 0,
                "total_ports": 0,
                "open_ports": 0,
                "services": set()
            }
            
            lines = content.split('\n')
            for line in lines:
                if '<status state="up"' in line:
                    stats["hosts_up"] += 1
                elif '<status state="down"' in line:
                    stats["hosts_down"] += 1
                elif '<port ' in line:
                    stats["total_ports"] += 1
                    if 'state="open"' in line:
                        stats["open_ports"] += 1
                elif '<service name=' in line:
                    # Extract service name
                    start = line.find('name="') + 6
                    end = line.find('"', start)
                    if start > 5 and end > start:
                        service = line[start:end]
                        stats["services"].add(service)
            
            # Convert set to list for JSON serialization
            stats["services"] = list(stats["services"])
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error parsing scan statistics: {str(e)}")
            return {}


def main():
    """Test discovery scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Discovery Scanner")
    parser.add_argument("--target", required=True, help="Target network")
    parser.add_argument("--output", default="discovery_results.xml", help="Output file")
    parser.add_argument("--profile", default="standard", help="Scan profile")
    
    args = parser.parse_args()
    
    scanner = DiscoveryScanner()
    
    config = {
        "target": args.target,
        "output": args.output,
        "profile": {
            "ports": "top-100",
            "scripts": ["default"],
            "timing": 3,
            "max_retries": 2,
            "os_detection": False
        }
    }
    
    result = scanner.run_discovery(config)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main() 