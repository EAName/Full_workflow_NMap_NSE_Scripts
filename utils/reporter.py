#!/usr/bin/env python3
"""
Report Generator Utility
Generates comprehensive reports from scan results
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class ReportGenerator:
    """Generates comprehensive reports from scan results"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict:
        """Load report templates"""
        try:
            with open("templates/html_report.html", 'r') as f:
                return {"html": f.read()}
        except FileNotFoundError:
            return self._get_default_templates()
    
    def _get_default_templates(self) -> Dict:
        """Return default report templates"""
        return {
            "html": """
<!DOCTYPE html>
<html>
<head>
    <title>Network Security Scan Report</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .content { padding: 30px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }
        .stat-card h3 { margin: 0 0 10px 0; color: #333; }
        .stat-card .number { font-size: 2em; font-weight: bold; color: #667eea; }
        .host-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .host-table th, .host-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .host-table th { background: #f8f9fa; font-weight: bold; }
        .host-table tr:hover { background: #f5f5f5; }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
        .vulnerability-list { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .vuln-item { padding: 8px; margin: 5px 0; border-radius: 3px; border-left: 4px solid; }
        .vuln-high { background: #ffebee; border-left-color: #dc3545; }
        .vuln-medium { background: #fff3e0; border-left-color: #ffc107; }
        .vuln-low { background: #e8f5e8; border-left-color: #28a745; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; border-top: 1px solid #ddd; }
        .chart-container { margin: 20px 0; height: 300px; }
        .service-tag { background: #667eea; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; margin: 2px; display: inline-block; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Network Security Scan Report</h1>
            <p>Generated on {{timestamp}}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Hosts</h3>
                        <div class="number">{{total_hosts}}</div>
                    </div>
                    <div class="stat-card">
                        <h3>High Risk</h3>
                        <div class="number risk-high">{{high_risk_count}}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Vulnerabilities</h3>
                        <div class="number">{{total_vulnerabilities}}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Services</h3>
                        <div class="number">{{total_services}}</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Risk Distribution</h2>
                <div class="chart-container">
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
            
            <div class="section">
                <h2>Host Details</h2>
                <table class="host-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Hostname</th>
                            <th>OS</th>
                            <th>Risk Score</th>
                            <th>Open Ports</th>
                            <th>Services</th>
                            <th>Vulnerabilities</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{host_rows}}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>Vulnerability Details</h2>
                {{vulnerability_details}}
            </div>
            
            <div class="section">
                <h2>Service Distribution</h2>
                <div class="chart-container">
                    <canvas id="serviceChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by Nmap + NSE + NetworkMaps Workflow</p>
            <p>Scan duration: {{scan_duration}}</p>
        </div>
    </div>
    
    <script>
        // Risk distribution chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'],
                datasets: [{
                    data: [{{risk_distribution.low}}, {{risk_distribution.medium}}, {{risk_distribution.high}}, {{risk_distribution.critical}}],
                    backgroundColor: ['#28a745', '#ffc107', '#fd7e14', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // Service distribution chart
        const serviceCtx = document.getElementById('serviceChart').getContext('2d');
        new Chart(serviceCtx, {
            type: 'bar',
            data: {
                labels: {{service_labels}},
                datasets: [{
                    label: 'Number of Hosts',
                    data: {{service_data}},
                    backgroundColor: '#667eea'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    </script>
</body>
</html>
            """
        }
    
    def generate_reports(self, config: Dict) -> Dict:
        """Generate comprehensive reports"""
        self.logger.info("Generating comprehensive reports")
        
        results = {
            "generated_reports": [],
            "errors": []
        }
        
        data = config["data"]
        output_dir = Path(config["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate each requested format
        for format_type in config["formats"]:
            try:
                if format_type == "html":
                    report_result = self._generate_html_report(data, output_dir, config)
                    results["generated_reports"].append(report_result)
                elif format_type == "json":
                    report_result = self._generate_json_report(data, output_dir)
                    results["generated_reports"].append(report_result)
                elif format_type == "pdf":
                    report_result = self._generate_pdf_report(data, output_dir)
                    results["generated_reports"].append(report_result)
                    
            except Exception as e:
                error_msg = f"Error generating {format_type} report: {str(e)}"
                self.logger.error(error_msg)
                results["errors"].append(error_msg)
        
        return results
    
    def _generate_html_report(self, data: Dict, output_dir: Path, config: Dict) -> Dict:
        """Generate HTML report"""
        report_file = output_dir / "security_report.html"
        
        # Prepare data for template
        template_data = self._prepare_html_template_data(data)
        
        # Generate HTML content
        html_content = self.templates["html"]
        
        # Replace template variables
        for key, value in template_data.items():
            placeholder = f"{{{{{key}}}}}"
            html_content = html_content.replace(placeholder, str(value))
        
        # Write HTML file
        with open(report_file, 'w') as f:
            f.write(html_content)
        
        return {
            "type": "html",
            "file": str(report_file),
            "size": report_file.stat().st_size if report_file.exists() else 0
        }
    
    def _prepare_html_template_data(self, data: Dict) -> Dict:
        """Prepare data for HTML template"""
        workflow_info = data.get("workflow_info", {})
        phases = data.get("phases", {})
        
        # Extract statistics
        discovery_phase = phases.get("discovery", {})
        vuln_phase = phases.get("vulnerability", {})
        
        # Calculate totals
        total_hosts = discovery_phase.get("hosts_found", 0)
        total_vulnerabilities = vuln_phase.get("vulnerabilities_found", 0)
        
        # Calculate risk distribution
        risk_distribution = self._calculate_risk_distribution(data)
        
        # Generate host rows
        host_rows = self._generate_host_rows(data)
        
        # Generate vulnerability details
        vulnerability_details = self._generate_vulnerability_details(data)
        
        # Service distribution
        service_distribution = self._calculate_service_distribution(data)
        
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_hosts": total_hosts,
            "high_risk_count": risk_distribution["high"] + risk_distribution["critical"],
            "total_vulnerabilities": total_vulnerabilities,
            "total_services": len(service_distribution),
            "risk_distribution": risk_distribution,
            "host_rows": host_rows,
            "vulnerability_details": vulnerability_details,
            "service_labels": json.dumps(list(service_distribution.keys())),
            "service_data": json.dumps(list(service_distribution.values())),
            "scan_duration": workflow_info.get("duration", "Unknown")
        }
    
    def _calculate_risk_distribution(self, data: Dict) -> Dict:
        """Calculate risk distribution from scan data"""
        risk_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        # Extract hosts from discovery phase
        discovery_phase = data.get("phases", {}).get("discovery", {})
        hosts = discovery_phase.get("parsed_results", {}).get("hosts", [])
        
        for host in hosts:
            risk_score = host.get("risk_score", 0)
            if risk_score >= 70:
                risk_distribution["critical"] += 1
            elif risk_score >= 40:
                risk_distribution["high"] += 1
            elif risk_score >= 20:
                risk_distribution["medium"] += 1
            else:
                risk_distribution["low"] += 1
        
        return risk_distribution
    
    def _generate_host_rows(self, data: Dict) -> str:
        """Generate HTML table rows for hosts"""
        discovery_phase = data.get("phases", {}).get("discovery", {})
        hosts = discovery_phase.get("parsed_results", {}).get("hosts", [])
        
        rows = []
        for host in hosts:
            ip = host.get("ip", "")
            hostname = host.get("hostname", "N/A")
            os_name = host.get("os", {}).get("name", "Unknown")
            risk_score = host.get("risk_score", 0)
            ports = host.get("ports", [])
            services = [port.get("service", {}).get("name", "") for port in ports if port.get("service", {}).get("name")]
            vulnerabilities = host.get("vulnerabilities", [])
            
            # Risk class
            risk_class = "risk-low"
            if risk_score >= 70:
                risk_class = "risk-high"
            elif risk_score >= 40:
                risk_class = "risk-medium"
            
            # Services tags
            service_tags = " ".join([f'<span class="service-tag">{service}</span>' for service in services[:5]])
            if len(services) > 5:
                service_tags += f' <span class="service-tag">+{len(services)-5} more</span>'
            
            row = f"""
                <tr>
                    <td>{ip}</td>
                    <td>{hostname}</td>
                    <td>{os_name}</td>
                    <td class="{risk_class}">{risk_score}</td>
                    <td>{len(ports)}</td>
                    <td>{service_tags}</td>
                    <td>{len(vulnerabilities)}</td>
                </tr>
            """
            rows.append(row)
        
        return "\n".join(rows)
    
    def _generate_vulnerability_details(self, data: Dict) -> str:
        """Generate vulnerability details section"""
        vuln_phase = data.get("phases", {}).get("vulnerability", {})
        hosts = vuln_phase.get("parsed_results", {}).get("hosts", [])
        
        if not hosts:
            return "<p>No vulnerabilities detected.</p>"
        
        details = []
        for host in hosts:
            vulnerabilities = host.get("vulnerabilities", [])
            if vulnerabilities:
                details.append(f'<h3>Host: {host.get("ip", "")}</h3>')
                for vuln in vulnerabilities:
                    severity = vuln.get("severity", "info")
                    output = vuln.get("output", "")
                    details.append(f'<div class="vuln-item vuln-{severity}">{output}</div>')
        
        return "\n".join(details) if details else "<p>No vulnerabilities detected.</p>"
    
    def _calculate_service_distribution(self, data: Dict) -> Dict:
        """Calculate service distribution"""
        discovery_phase = data.get("phases", {}).get("discovery", {})
        hosts = discovery_phase.get("parsed_results", {}).get("hosts", [])
        
        service_count = {}
        for host in hosts:
            for port in host.get("ports", []):
                service_name = port.get("service", {}).get("name", "")
                if service_name:
                    service_count[service_name] = service_count.get(service_name, 0) + 1
        
        # Sort by count and take top 10
        sorted_services = sorted(service_count.items(), key=lambda x: x[1], reverse=True)[:10]
        return dict(sorted_services)
    
    def _generate_json_report(self, data: Dict, output_dir: Path) -> Dict:
        """Generate JSON report"""
        report_file = output_dir / "security_report.json"
        
        # Create structured JSON report
        json_report = {
            "report_info": {
                "generated_at": datetime.now().isoformat(),
                "tool": "Nmap + NSE + NetworkMaps Workflow",
                "version": "1.0"
            },
            "scan_summary": self._create_scan_summary(data),
            "hosts": self._extract_host_data(data),
            "vulnerabilities": self._extract_vulnerability_data(data),
            "recommendations": self._generate_recommendations(data)
        }
        
        with open(report_file, 'w') as f:
            json.dump(json_report, f, indent=2)
        
        return {
            "type": "json",
            "file": str(report_file),
            "size": report_file.stat().st_size if report_file.exists() else 0
        }
    
    def _create_scan_summary(self, data: Dict) -> Dict:
        """Create scan summary"""
        workflow_info = data.get("workflow_info", {})
        phases = data.get("phases", {})
        
        discovery = phases.get("discovery", {})
        vuln = phases.get("vulnerability", {})
        
        return {
            "target": workflow_info.get("target", ""),
            "scan_duration": workflow_info.get("duration", ""),
            "total_hosts": discovery.get("hosts_found", 0),
            "vulnerabilities_found": vuln.get("vulnerabilities_found", 0),
            "high_risk_hosts": 0,  # Calculate from data
            "scan_profile": workflow_info.get("profile", "")
        }
    
    def _extract_host_data(self, data: Dict) -> List[Dict]:
        """Extract host data for JSON report"""
        discovery_phase = data.get("phases", {}).get("discovery", {})
        hosts = discovery_phase.get("parsed_results", {}).get("hosts", [])
        
        return [{
            "ip": host.get("ip", ""),
            "hostname": host.get("hostname", ""),
            "os": host.get("os", {}),
            "ports": host.get("ports", []),
            "services": [port.get("service", {}).get("name", "") for port in host.get("ports", []) if port.get("service", {}).get("name")],
            "risk_score": host.get("risk_score", 0)
        } for host in hosts]
    
    def _extract_vulnerability_data(self, data: Dict) -> List[Dict]:
        """Extract vulnerability data for JSON report"""
        vuln_phase = data.get("phases", {}).get("vulnerability", {})
        hosts = vuln_phase.get("parsed_results", {}).get("hosts", [])
        
        vulnerabilities = []
        for host in hosts:
            for vuln in host.get("vulnerabilities", []):
                vulnerabilities.append({
                    "host": host.get("ip", ""),
                    "script_id": vuln.get("script_id", ""),
                    "severity": vuln.get("severity", ""),
                    "output": vuln.get("output", ""),
                    "cve_references": vuln.get("cve_references", [])
                })
        
        return vulnerabilities
    
    def _generate_recommendations(self, data: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Analyze data and generate recommendations
        vuln_phase = data.get("phases", {}).get("vulnerability", {})
        hosts = vuln_phase.get("parsed_results", {}).get("hosts", [])
        
        high_risk_count = sum(1 for host in hosts if host.get("risk_score", 0) >= 40)
        total_vulns = sum(len(host.get("vulnerabilities", [])) for host in hosts)
        
        if high_risk_count > 0:
            recommendations.append(f"Immediate attention required for {high_risk_count} high-risk hosts")
        
        if total_vulns > 0:
            recommendations.append(f"Address {total_vulns} identified vulnerabilities")
        
        # Add more specific recommendations based on findings
        for host in hosts:
            for vuln in host.get("vulnerabilities", []):
                if "default" in vuln.get("output", "").lower():
                    recommendations.append("Change default credentials on affected systems")
                    break
        
        if not recommendations:
            recommendations.append("No immediate security concerns detected")
        
        return recommendations
    
    def _generate_pdf_report(self, data: Dict, output_dir: Path) -> Dict:
        """Generate PDF report (placeholder)"""
        # This would require additional libraries like reportlab or weasyprint
        # For now, we'll create a simple text-based report
        report_file = output_dir / "security_report.txt"
        
        with open(report_file, 'w') as f:
            f.write("Network Security Scan Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {data.get('workflow_info', {}).get('target', 'Unknown')}\n\n")
            
            # Add summary
            discovery = data.get("phases", {}).get("discovery", {})
            vuln = data.get("phases", {}).get("vulnerability", {})
            
            f.write(f"Total Hosts: {discovery.get('hosts_found', 0)}\n")
            f.write(f"Vulnerabilities: {vuln.get('vulnerabilities_found', 0)}\n\n")
            
            # Add host details
            f.write("Host Details:\n")
            f.write("-" * 20 + "\n")
            hosts = discovery.get("parsed_results", {}).get("hosts", [])
            for host in hosts:
                f.write(f"IP: {host.get('ip', '')}\n")
                f.write(f"  OS: {host.get('os', {}).get('name', 'Unknown')}\n")
                f.write(f"  Risk Score: {host.get('risk_score', 0)}\n")
                f.write(f"  Open Ports: {len(host.get('ports', []))}\n\n")
        
        return {
            "type": "text",
            "file": str(report_file),
            "size": report_file.stat().st_size if report_file.exists() else 0
        }


def main():
    """Test report generator"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Report Generator")
    parser.add_argument("--input", required=True, help="Input JSON data file")
    parser.add_argument("--output", default="reports", help="Output directory")
    parser.add_argument("--formats", default="html,json", help="Output formats (comma-separated)")
    
    args = parser.parse_args()
    
    generator = ReportGenerator()
    
    # Load data
    with open(args.input, 'r') as f:
        data = json.load(f)
    
    config = {
        "data": data,
        "output_dir": args.output,
        "formats": args.formats.split(','),
        "templates": ["comprehensive"]
    }
    
    results = generator.generate_reports(config)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main() 