#!/usr/bin/env python3
"""
Full-Featured Nmap + NSE + NetworkMaps Workflow
Main orchestrator for network discovery, vulnerability scanning, and topology visualization
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Import our modules
from discovery_scanner import DiscoveryScanner
from vulnerability_scanner import VulnerabilityScanner
from topology_mapper import TopologyMapper
from utils.parser import NmapParser
from utils.reporter import ReportGenerator
from utils.visualizer import NetworkVisualizer


class WorkflowOrchestrator:
    """Main orchestrator for the complete Nmap + NSE + NetworkMaps workflow"""
    
    def __init__(self, config_path: str = "config/scan_profiles.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.setup_logging()
        
        # Initialize components
        self.discovery_scanner = DiscoveryScanner()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.topology_mapper = TopologyMapper()
        self.parser = NmapParser()
        self.reporter = ReportGenerator()
        self.visualizer = NetworkVisualizer()
        
        self.logger = logging.getLogger(__name__)
    
    def _load_config(self) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"Config file {self.config_path} not found, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Return default configuration"""
        return {
            "profiles": {
                "quick": {
                    "ports": "top-100",
                    "scripts": ["default"],
                    "timing": 3,
                    "max_retries": 2,
                    "os_detection": False
                },
                "standard": {
                    "ports": "all",
                    "scripts": ["default", "discovery"],
                    "timing": 2,
                    "max_retries": 2,
                    "os_detection": True
                },
                "comprehensive": {
                    "ports": "all",
                    "scripts": ["default", "vuln", "auth", "discovery"],
                    "timing": 1,
                    "max_retries": 3,
                    "os_detection": True
                },
                "stealth": {
                    "ports": "top-1000",
                    "scripts": ["default"],
                    "timing": 5,
                    "max_retries": 1,
                    "os_detection": False
                }
            }
        }
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('workflow.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def run_workflow(self, args: argparse.Namespace) -> Dict:
        """Execute the complete workflow"""
        start_time = datetime.now()
        self.logger.info(f"Starting workflow for target: {args.target}")
        
        # Create output directory
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        results = {
            "workflow_info": {
                "target": args.target,
                "profile": args.profile,
                "start_time": start_time.isoformat(),
                "excluded_hosts": args.exclude.split(',') if args.exclude else []
            },
            "phases": {}
        }
        
        try:
            # Phase 1: Discovery
            self.logger.info("Phase 1: Network Discovery")
            discovery_results = self._run_discovery_phase(args, output_dir)
            results["phases"]["discovery"] = discovery_results
            
            if not discovery_results["hosts_found"]:
                self.logger.warning("No hosts discovered, ending workflow")
                return results
            
            # Phase 2: Vulnerability Assessment
            self.logger.info("Phase 2: Vulnerability Assessment")
            vuln_results = self._run_vulnerability_phase(args, discovery_results, output_dir)
            results["phases"]["vulnerability"] = vuln_results
            
            # Phase 3: Topology Mapping
            self.logger.info("Phase 3: Topology Mapping")
            topology_results = self._run_topology_phase(args, results, output_dir)
            results["phases"]["topology"] = topology_results
            
            # Phase 4: Report Generation
            self.logger.info("Phase 4: Report Generation")
            report_results = self._generate_reports(args, results, output_dir)
            results["phases"]["reporting"] = report_results
            
        except Exception as e:
            self.logger.error(f"Workflow failed: {str(e)}")
            results["error"] = str(e)
        
        end_time = datetime.now()
        results["workflow_info"]["end_time"] = end_time.isoformat()
        results["workflow_info"]["duration"] = str(end_time - start_time)
        
        # Save complete results
        results_file = output_dir / "workflow_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"Workflow completed. Results saved to {results_file}")
        return results
    
    def _run_discovery_phase(self, args: argparse.Namespace, output_dir: Path) -> Dict:
        """Execute discovery phase"""
        discovery_output = output_dir / "discovery_results.xml"
        
        discovery_config = {
            "target": args.target,
            "output": str(discovery_output),
            "profile": self.config["profiles"][args.profile],
            "exclude": args.exclude,
            "rate_limit": args.rate_limit
        }
        
        discovery_results = self.discovery_scanner.run_discovery(discovery_config)
        
        # Parse discovery results
        parsed_discovery = self.parser.parse_nmap_xml(str(discovery_output))
        
        return {
            "config": discovery_config,
            "raw_output": str(discovery_output),
            "parsed_results": parsed_discovery,
            "hosts_found": len(parsed_discovery.get("hosts", [])),
            "summary": {
                "total_hosts": len(parsed_discovery.get("hosts", [])),
                "open_ports": sum(len(host.get("ports", [])) for host in parsed_discovery.get("hosts", [])),
                "services_found": len(set(port.get("service", "") for host in parsed_discovery.get("hosts", []) for port in host.get("ports", [])))
            }
        }
    
    def _run_vulnerability_phase(self, args: argparse.Namespace, discovery_results: Dict, output_dir: Path) -> Dict:
        """Execute vulnerability assessment phase"""
        vuln_output = output_dir / "vulnerability_results.xml"
        
        # Extract discovered hosts
        discovered_hosts = [host["ip"] for host in discovery_results["parsed_results"].get("hosts", [])]
        
        if not discovered_hosts:
            return {"error": "No hosts to scan for vulnerabilities"}
        
        vuln_config = {
            "hosts": discovered_hosts,
            "output": str(vuln_output),
            "profile": self.config["profiles"][args.profile],
            "rate_limit": args.rate_limit
        }
        
        vuln_results = self.vulnerability_scanner.run_vulnerability_scan(vuln_config)
        
        # Parse vulnerability results
        parsed_vuln = self.parser.parse_nmap_xml(str(vuln_output))
        
        return {
            "config": vuln_config,
            "raw_output": str(vuln_output),
            "parsed_results": parsed_vuln,
            "vulnerabilities_found": self._count_vulnerabilities(parsed_vuln),
            "summary": {
                "hosts_scanned": len(discovered_hosts),
                "vulnerabilities": self._count_vulnerabilities(parsed_vuln),
                "high_risk": self._count_high_risk_vulns(parsed_vuln)
            }
        }
    
    def _run_topology_phase(self, args: argparse.Namespace, results: Dict, output_dir: Path) -> Dict:
        """Execute topology mapping phase"""
        topology_output = output_dir / "topology_map.html"
        
        # Combine discovery and vulnerability data
        combined_data = self._combine_scan_data(results)
        
        topology_config = {
            "data": combined_data,
            "output": str(topology_output),
            "format": "html",
            "interactive": True
        }
        
        topology_results = self.topology_mapper.generate_topology(topology_config)
        
        return {
            "config": topology_config,
            "output": str(topology_output),
            "nodes": len(combined_data.get("nodes", [])),
            "edges": len(combined_data.get("edges", [])),
            "visualization_type": "interactive_network_map"
        }
    
    def _generate_reports(self, args: argparse.Namespace, results: Dict, output_dir: Path) -> Dict:
        """Generate comprehensive reports"""
        report_config = {
            "data": results,
            "output_dir": str(output_dir),
            "formats": ["html", "json", "pdf"],
            "templates": ["comprehensive", "executive", "technical"]
        }
        
        report_results = self.reporter.generate_reports(report_config)
        
        return {
            "config": report_config,
            "generated_reports": report_results,
            "report_files": list(output_dir.glob("*.html")) + list(output_dir.glob("*.pdf"))
        }
    
    def _combine_scan_data(self, results: Dict) -> Dict:
        """Combine discovery and vulnerability data for topology mapping"""
        combined = {
            "nodes": [],
            "edges": [],
            "metadata": {
                "scan_info": results["workflow_info"],
                "statistics": {}
            }
        }
        
        # Add nodes from discovery
        for host in results["phases"]["discovery"]["parsed_results"].get("hosts", []):
            node = {
                "id": host["ip"],
                "type": "host",
                "ip": host["ip"],
                "hostname": host.get("hostname", ""),
                "os": host.get("os", {}),
                "ports": host.get("ports", []),
                "services": [port.get("service", "") for port in host.get("ports", [])]
            }
            combined["nodes"].append(node)
        
        # Add vulnerability data
        for host in results["phases"]["vulnerability"]["parsed_results"].get("hosts", []):
            # Find corresponding node and add vulnerability info
            for node in combined["nodes"]:
                if node["id"] == host["ip"]:
                    node["vulnerabilities"] = host.get("vulnerabilities", [])
                    node["risk_score"] = self._calculate_risk_score(host)
                    break
        
        # Add edges (network connections)
        combined["edges"] = self._generate_network_edges(combined["nodes"])
        
        return combined
    
    def _calculate_risk_score(self, host: Dict) -> int:
        """Calculate risk score for a host based on vulnerabilities"""
        score = 0
        for vuln in host.get("vulnerabilities", []):
            severity = vuln.get("severity", "medium")
            if severity == "high":
                score += 10
            elif severity == "medium":
                score += 5
            elif severity == "low":
                score += 1
        return min(score, 100)  # Cap at 100
    
    def _generate_network_edges(self, nodes: List[Dict]) -> List[Dict]:
        """Generate network edges between hosts"""
        edges = []
        # Simple edge generation - can be enhanced with traceroute data
        for i, node1 in enumerate(nodes):
            for j, node2 in enumerate(nodes[i+1:], i+1):
                # Check if hosts are in same subnet
                if self._same_subnet(node1["ip"], node2["ip"]):
                    edge = {
                        "source": node1["id"],
                        "target": node2["id"],
                        "type": "network",
                        "weight": 1
                    }
                    edges.append(edge)
        return edges
    
    def _same_subnet(self, ip1: str, ip2: str) -> bool:
        """Check if two IPs are in the same /24 subnet"""
        try:
            parts1 = ip1.split('.')
            parts2 = ip2.split('.')
            return parts1[:3] == parts2[:3]
        except:
            return False
    
    def _count_vulnerabilities(self, parsed_results: Dict) -> int:
        """Count total vulnerabilities found"""
        count = 0
        for host in parsed_results.get("hosts", []):
            count += len(host.get("vulnerabilities", []))
        return count
    
    def _count_high_risk_vulns(self, parsed_results: Dict) -> int:
        """Count high-risk vulnerabilities"""
        count = 0
        for host in parsed_results.get("hosts", []):
            for vuln in host.get("vulnerabilities", []):
                if vuln.get("severity") == "high":
                    count += 1
        return count


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Full-Featured Nmap + NSE + NetworkMaps Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --target 192.168.1.0/24 --profile standard
  python3 main.py --target 10.0.0.0/8 --profile comprehensive --output enterprise_scan
  python3 main.py --target 172.16.0.0/16 --profile stealth --exclude 172.16.0.1,172.16.0.254
        """
    )
    
    parser.add_argument("--target", required=True, help="Target network (CIDR notation)")
    parser.add_argument("--profile", default="standard", 
                       choices=["quick", "standard", "comprehensive", "stealth"],
                       help="Scan profile to use")
    parser.add_argument("--output", default="results", help="Output directory")
    parser.add_argument("--exclude", help="Comma-separated list of hosts to exclude")
    parser.add_argument("--rate-limit", type=int, default=1000, 
                       help="Maximum packets per second")
    parser.add_argument("--config", default="config/scan_profiles.json",
                       help="Configuration file path")
    
    args = parser.parse_args()
    
    # Validate target format
    if not args.target or '/' not in args.target:
        print("Error: Target must be in CIDR notation (e.g., 192.168.1.0/24)")
        sys.exit(1)
    
    # Initialize and run workflow
    orchestrator = WorkflowOrchestrator(args.config)
    results = orchestrator.run_workflow(args)
    
    # Print summary
    print("\n" + "="*60)
    print("WORKFLOW SUMMARY")
    print("="*60)
    print(f"Target: {args.target}")
    print(f"Profile: {args.profile}")
    print(f"Duration: {results['workflow_info']['duration']}")
    
    if "phases" in results:
        discovery = results["phases"].get("discovery", {})
        vuln = results["phases"].get("vulnerability", {})
        
        print(f"Hosts Discovered: {discovery.get('hosts_found', 0)}")
        print(f"Vulnerabilities Found: {vuln.get('vulnerabilities_found', 0)}")
        print(f"High Risk Vulns: {vuln.get('summary', {}).get('high_risk', 0)}")
    
    print(f"Results saved to: {args.output}")
    print("="*60)


if __name__ == "__main__":
    main() 