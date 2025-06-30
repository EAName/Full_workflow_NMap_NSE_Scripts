#!/usr/bin/env python3
"""
Nmap XML Parser Utility
Parses Nmap XML output into structured data
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional


class NmapParser:
    """Parses Nmap XML output into structured data"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_nmap_xml(self, xml_file: str) -> Dict:
        """Parse Nmap XML file into structured data"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Extract scan information
            scan_info = self._parse_scan_info(root)
            
            # Extract hosts
            hosts = self._parse_hosts(root)
            
            return {
                "scan_info": scan_info,
                "hosts": hosts,
                "summary": self._generate_summary(hosts)
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing XML file {xml_file}: {str(e)}")
            return {"error": str(e)}
    
    def _parse_scan_info(self, root: ET.Element) -> Dict:
        """Parse scan information from XML root"""
        scan_info = {
            "scanner": "nmap",
            "version": "",
            "start_time": "",
            "end_time": "",
            "args": "",
            "targets": []
        }
        
        # Extract nmaprun attributes
        nmaprun = root.find('.')
        if nmaprun is not None:
            scan_info["scanner"] = nmaprun.get("scanner", "nmap")
            scan_info["version"] = nmaprun.get("version", "")
            scan_info["start_time"] = nmaprun.get("start", "")
            scan_info["end_time"] = nmaprun.get("end", "")
            scan_info["args"] = nmaprun.get("args", "")
        
        # Extract targets
        for target in root.findall(".//target"):
            scan_info["targets"].append(target.get("spec", ""))
        
        return scan_info
    
    def _parse_hosts(self, root: ET.Element) -> List[Dict]:
        """Parse host information from XML"""
        hosts = []
        
        for host in root.findall(".//host"):
            host_data = self._parse_single_host(host)
            if host_data:
                hosts.append(host_data)
        
        return hosts
    
    def _parse_single_host(self, host: ET.Element) -> Optional[Dict]:
        """Parse a single host element"""
        host_data = {
            "ip": "",
            "hostname": "",
            "status": "unknown",
            "os": {},
            "ports": [],
            "vulnerabilities": []
        }
        
        # Parse address
        address = host.find("address")
        if address is not None and address.get("addrtype") == "ipv4":
            host_data["ip"] = address.get("addr", "")
        
        # Parse hostname
        hostname = host.find("hostnames/hostname")
        if hostname is not None:
            host_data["hostname"] = hostname.get("name", "")
        
        # Parse status
        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "unknown")
        
        # Parse OS information
        os_info = host.find("os")
        if os_info is not None:
            host_data["os"] = self._parse_os_info(os_info)
        
        # Parse ports
        ports = host.findall("ports/port")
        for port in ports:
            port_data = self._parse_port(port)
            if port_data:
                host_data["ports"].append(port_data)
        
        # Parse vulnerabilities from scripts
        host_data["vulnerabilities"] = self._parse_vulnerabilities(host)
        
        return host_data if host_data["ip"] else None
    
    def _parse_os_info(self, os_element: ET.Element) -> Dict:
        """Parse OS information"""
        os_info = {
            "name": "",
            "version": "",
            "accuracy": "",
            "cpe": ""
        }
        
        # Get best OS match
        osmatch = os_element.find("osmatch")
        if osmatch is not None:
            os_info["name"] = osmatch.get("name", "")
            os_info["accuracy"] = osmatch.get("accuracy", "")
        
        # Get OS version
        osversion = os_element.find("osversion")
        if osversion is not None:
            os_info["version"] = osversion.get("version", "")
        
        # Get CPE
        cpe = os_element.find("cpe")
        if cpe is not None:
            os_info["cpe"] = cpe.text or ""
        
        return os_info
    
    def _parse_port(self, port: ET.Element) -> Optional[Dict]:
        """Parse port information"""
        port_data = {
            "port": "",
            "protocol": "",
            "state": "",
            "service": {},
            "scripts": []
        }
        
        port_data["port"] = port.get("portid", "")
        port_data["protocol"] = port.get("protocol", "")
        
        # Parse state
        state = port.find("state")
        if state is not None:
            port_data["state"] = state.get("state", "")
        
        # Parse service
        service = port.find("service")
        if service is not None:
            port_data["service"] = {
                "name": service.get("name", ""),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "extrainfo": service.get("extrainfo", ""),
                "cpe": service.get("cpe", "")
            }
        
        # Parse scripts
        scripts = port.findall("script")
        for script in scripts:
            script_data = self._parse_script(script)
            if script_data:
                port_data["scripts"].append(script_data)
        
        return port_data if port_data["port"] else None
    
    def _parse_script(self, script: ET.Element) -> Optional[Dict]:
        """Parse script output"""
        script_data = {
            "id": "",
            "output": "",
            "elements": {}
        }
        
        script_data["id"] = script.get("id", "")
        script_data["output"] = script.get("output", "")
        
        # Parse script elements
        for elem in script.findall("elem"):
            key = elem.get("key", "")
            value = elem.text or ""
            script_data["elements"][key] = value
        
        return script_data if script_data["id"] else None
    
    def _parse_vulnerabilities(self, host: ET.Element) -> List[Dict]:
        """Parse vulnerabilities from host scripts"""
        vulnerabilities = []
        
        # Check host scripts
        host_scripts = host.find("hostscript")
        if host_scripts is not None:
            for script in host_scripts.findall("script"):
                vuln = self._extract_vulnerability_from_script(script, "host")
                if vuln:
                    vulnerabilities.append(vuln)
        
        # Check port scripts
        for port in host.findall("ports/port"):
            port_id = port.get("portid", "")
            for script in port.findall("script"):
                vuln = self._extract_vulnerability_from_script(script, port_id)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_vulnerability_from_script(self, script: ET.Element, context: str) -> Optional[Dict]:
        """Extract vulnerability information from script output"""
        script_id = script.get("id", "")
        output = script.get("output", "")
        
        # Check if script output indicates vulnerability
        if self._is_vulnerability_script(script_id, output):
            return {
                "script_id": script_id,
                "context": context,
                "output": output,
                "severity": self._determine_vulnerability_severity(script_id, output),
                "cve_references": self._extract_cve_references(output)
            }
        
        return None
    
    def _is_vulnerability_script(self, script_id: str, output: str) -> bool:
        """Check if script indicates vulnerability"""
        vuln_indicators = [
            'vuln', 'auth', 'exploit', 'weak', 'default', 'anonymous',
            'backdoor', 'malware', 'trojan', 'cve-', 'vulnerable'
        ]
        
        # Check script ID
        if any(indicator in script_id.lower() for indicator in vuln_indicators):
            return True
        
        # Check output
        output_lower = output.lower()
        return any(indicator in output_lower for indicator in vuln_indicators)
    
    def _determine_vulnerability_severity(self, script_id: str, output: str) -> str:
        """Determine vulnerability severity"""
        output_lower = output.lower()
        
        # High severity indicators
        high_indicators = ['critical', 'high', 'cve-', 'exploit', 'backdoor', 'malware']
        if any(indicator in output_lower for indicator in high_indicators):
            return "high"
        
        # Medium severity indicators
        medium_indicators = ['medium', 'weak', 'default', 'anonymous']
        if any(indicator in output_lower for indicator in medium_indicators):
            return "medium"
        
        # Low severity indicators
        low_indicators = ['low', 'info', 'disclosure']
        if any(indicator in output_lower for indicator in low_indicators):
            return "low"
        
        return "info"
    
    def _extract_cve_references(self, output: str) -> List[str]:
        """Extract CVE references from output"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return re.findall(cve_pattern, output, re.IGNORECASE)
    
    def _generate_summary(self, hosts: List[Dict]) -> Dict:
        """Generate summary statistics"""
        summary = {
            "total_hosts": len(hosts),
            "hosts_up": sum(1 for host in hosts if host.get("status") == "up"),
            "hosts_down": sum(1 for host in hosts if host.get("status") == "down"),
            "total_ports": 0,
            "open_ports": 0,
            "services": set(),
            "vulnerabilities": 0,
            "os_distribution": {},
            "port_distribution": {}
        }
        
        for host in hosts:
            # Count ports
            for port in host.get("ports", []):
                summary["total_ports"] += 1
                if port.get("state") == "open":
                    summary["open_ports"] += 1
                
                # Count services
                service_name = port.get("service", {}).get("name", "")
                if service_name:
                    summary["services"].add(service_name)
                
                # Port distribution
                port_num = port.get("port", "")
                if port_num:
                    summary["port_distribution"][port_num] = summary["port_distribution"].get(port_num, 0) + 1
            
            # Count vulnerabilities
            summary["vulnerabilities"] += len(host.get("vulnerabilities", []))
            
            # OS distribution
            os_name = host.get("os", {}).get("name", "Unknown")
            summary["os_distribution"][os_name] = summary["os_distribution"].get(os_name, 0) + 1
        
        # Convert set to list for JSON serialization
        summary["services"] = list(summary["services"])
        
        return summary
    
    def parse_quick_scan(self, xml_file: str) -> Dict:
        """Parse quick scan results (host discovery only)"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            hosts = []
            for host in root.findall(".//host"):
                address = host.find("address")
                if address is not None and address.get("addrtype") == "ipv4":
                    status = host.find("status")
                    host_data = {
                        "ip": address.get("addr", ""),
                        "status": status.get("state", "unknown") if status is not None else "unknown"
                    }
                    hosts.append(host_data)
            
            return {
                "hosts": hosts,
                "total_hosts": len(hosts),
                "hosts_up": sum(1 for host in hosts if host.get("status") == "up")
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing quick scan: {str(e)}")
            return {"error": str(e)}
    
    def export_to_json(self, xml_file: str, output_file: str) -> bool:
        """Export parsed XML to JSON file"""
        try:
            parsed_data = self.parse_nmap_xml(xml_file)
            
            with open(output_file, 'w') as f:
                json.dump(parsed_data, f, indent=2)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {str(e)}")
            return False
    
    def get_host_details(self, xml_file: str, target_ip: str) -> Optional[Dict]:
        """Get detailed information for a specific host"""
        try:
            parsed_data = self.parse_nmap_xml(xml_file)
            
            for host in parsed_data.get("hosts", []):
                if host.get("ip") == target_ip:
                    return host
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting host details: {str(e)}")
            return None


def main():
    """Test parser"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Nmap XML Parser")
    parser.add_argument("--input", required=True, help="Input XML file")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--host", help="Get details for specific host")
    
    args = parser.parse_args()
    
    nmap_parser = NmapParser()
    
    if args.host:
        # Get specific host details
        host_details = nmap_parser.get_host_details(args.input, args.host)
        if host_details:
            print(json.dumps(host_details, indent=2))
        else:
            print(f"Host {args.host} not found")
    else:
        # Parse entire file
        parsed_data = nmap_parser.parse_nmap_xml(args.input)
        
        if args.output:
            nmap_parser.export_to_json(args.input, args.output)
            print(f"Exported to {args.output}")
        else:
            print(json.dumps(parsed_data, indent=2))


if __name__ == "__main__":
    main() 