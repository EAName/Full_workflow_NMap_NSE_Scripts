#!/usr/bin/env python3
"""
Topology Mapper Module
Generates dynamic network topology visualizations using NetworkMaps
"""

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional


class TopologyMapper:
    """Handles network topology visualization and mapping"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.networkmaps_path = self._find_networkmaps()
        self.templates = self._load_templates()
    
    def _find_networkmaps(self) -> Optional[str]:
        """Find NetworkMaps installation"""
        try:
            # Check if NetworkMaps is installed globally
            result = subprocess.run(['which', 'networkmaps'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        # Check common installation paths
        common_paths = [
            '/usr/local/bin/networkmaps',
            '/opt/networkmaps/bin/networkmaps',
            './node_modules/.bin/networkmaps'
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        # If not found, we'll use our own implementation
        self.logger.warning("NetworkMaps not found, using built-in visualization")
        return None
    
    def _load_templates(self) -> Dict:
        """Load visualization templates"""
        try:
            with open("templates/networkmap_template.js", 'r') as f:
                return {"javascript": f.read()}
        except FileNotFoundError:
            return self._get_default_templates()
    
    def _get_default_templates(self) -> Dict:
        """Return default visualization templates"""
        return {
            "javascript": """
// Default NetworkMaps visualization template
function createNetworkMap(data) {
    const container = document.getElementById('network-map');
    
    // Create D3.js visualization
    const width = 1200;
    const height = 800;
    
    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Create force simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.edges).id(d => d.id))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2));
    
    // Create links
    const links = svg.append('g')
        .selectAll('line')
        .data(data.edges)
        .enter().append('line')
        .attr('stroke', '#999')
        .attr('stroke-width', 2);
    
    // Create nodes
    const nodes = svg.append('g')
        .selectAll('circle')
        .data(data.nodes)
        .enter().append('circle')
        .attr('r', d => Math.max(5, d.risk_score / 10))
        .attr('fill', d => getNodeColor(d.risk_score))
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));
    
    // Add tooltips
    nodes.append('title')
        .text(d => `${d.ip}\\nRisk: ${d.risk_score}\\nServices: ${d.services.join(', ')}`);
    
    // Update positions
    simulation.on('tick', () => {
        links
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        
        nodes
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
    });
    
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    
    function getNodeColor(riskScore) {
        if (riskScore >= 70) return '#ff4444';
        if (riskScore >= 40) return '#ffaa00';
        if (riskScore >= 20) return '#ffff00';
        return '#44ff44';
    }
}
            """,
            "html": """
<!DOCTYPE html>
<html>
<head>
    <title>Network Topology Map</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 20px; }
        .stats { display: flex; justify-content: space-around; margin-bottom: 20px; }
        .stat-box { background: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; }
        #network-map { border: 1px solid #ddd; border-radius: 5px; }
        .legend { margin-top: 20px; text-align: center; }
        .legend-item { display: inline-block; margin: 0 10px; }
        .legend-color { display: inline-block; width: 20px; height: 20px; border-radius: 50%; margin-right: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Network Topology Visualization</h1>
            <p>Generated on {{timestamp}}</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>Total Hosts</h3>
                <p>{{total_hosts}}</p>
            </div>
            <div class="stat-box">
                <h3>High Risk</h3>
                <p>{{high_risk_count}}</p>
            </div>
            <div class="stat-box">
                <h3>Vulnerabilities</h3>
                <p>{{total_vulnerabilities}}</p>
            </div>
            <div class="stat-box">
                <h3>Services</h3>
                <p>{{total_services}}</p>
            </div>
        </div>
        
        <div id="network-map"></div>
        
        <div class="legend">
            <div class="legend-item">
                <span class="legend-color" style="background: #44ff44;"></span>
                Low Risk (0-19)
            </div>
            <div class="legend-item">
                <span class="legend-color" style="background: #ffff00;"></span>
                Medium Risk (20-39)
            </div>
            <div class="legend-item">
                <span class="legend-color" style="background: #ffaa00;"></span>
                High Risk (40-69)
            </div>
            <div class="legend-item">
                <span class="legend-color" style="background: #ff4444;"></span>
                Critical Risk (70+)
            </div>
        </div>
    </div>
    
    <script>
        {{javascript_code}}
        
        // Load and display data
        fetch('{{data_file}}')
            .then(response => response.json())
            .then(data => {
                createNetworkMap(data);
            })
            .catch(error => {
                console.error('Error loading data:', error);
                document.getElementById('network-map').innerHTML = 
                    '<p style="text-align: center; color: red;">Error loading network data</p>';
            });
    </script>
</body>
</html>
            """
        }
    
    def generate_topology(self, config: Dict) -> Dict:
        """Generate network topology visualization"""
        self.logger.info("Generating network topology visualization")
        
        # Prepare data for visualization
        visualization_data = self._prepare_visualization_data(config["data"])
        
        # Generate output based on format
        if config["format"] == "html":
            return self._generate_html_visualization(visualization_data, config)
        elif config["format"] == "json":
            return self._generate_json_visualization(visualization_data, config)
        elif config["format"] == "svg":
            return self._generate_svg_visualization(visualization_data, config)
        else:
            return self._generate_html_visualization(visualization_data, config)
    
    def _prepare_visualization_data(self, data: Dict) -> Dict:
        """Prepare data for visualization"""
        nodes = []
        edges = []
        
        # Process nodes
        for node_data in data.get("nodes", []):
            node = {
                "id": node_data["ip"],
                "ip": node_data["ip"],
                "hostname": node_data.get("hostname", ""),
                "os": node_data.get("os", {}),
                "services": node_data.get("services", []),
                "ports": node_data.get("ports", []),
                "vulnerabilities": node_data.get("vulnerabilities", []),
                "risk_score": node_data.get("risk_score", 0),
                "type": "host"
            }
            nodes.append(node)
        
        # Process edges
        for edge_data in data.get("edges", []):
            edge = {
                "source": edge_data["source"],
                "target": edge_data["target"],
                "type": edge_data.get("type", "network"),
                "weight": edge_data.get("weight", 1)
            }
            edges.append(edge)
        
        # Calculate statistics
        stats = self._calculate_network_statistics(nodes)
        
        return {
            "nodes": nodes,
            "edges": edges,
            "statistics": stats,
            "metadata": data.get("metadata", {})
        }
    
    def _calculate_network_statistics(self, nodes: List[Dict]) -> Dict:
        """Calculate network statistics"""
        total_hosts = len(nodes)
        high_risk_count = sum(1 for node in nodes if node.get("risk_score", 0) >= 40)
        total_vulnerabilities = sum(len(node.get("vulnerabilities", [])) for node in nodes)
        total_services = len(set(service for node in nodes for service in node.get("services", [])))
        
        # Service distribution
        service_distribution = {}
        for node in nodes:
            for service in node.get("services", []):
                service_distribution[service] = service_distribution.get(service, 0) + 1
        
        # Risk distribution
        risk_distribution = {
            "low": sum(1 for node in nodes if node.get("risk_score", 0) < 20),
            "medium": sum(1 for node in nodes if 20 <= node.get("risk_score", 0) < 40),
            "high": sum(1 for node in nodes if 40 <= node.get("risk_score", 0) < 70),
            "critical": sum(1 for node in nodes if node.get("risk_score", 0) >= 70)
        }
        
        return {
            "total_hosts": total_hosts,
            "high_risk_count": high_risk_count,
            "total_vulnerabilities": total_vulnerabilities,
            "total_services": total_services,
            "service_distribution": service_distribution,
            "risk_distribution": risk_distribution
        }
    
    def _generate_html_visualization(self, data: Dict, config: Dict) -> Dict:
        """Generate HTML-based visualization"""
        output_path = Path(config["output"])
        output_dir = output_path.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save data as JSON
        data_file = output_dir / "network_data.json"
        with open(data_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Generate HTML
        html_content = self.templates["html"].replace(
            "{{javascript_code}}", self.templates["javascript"]
        ).replace(
            "{{data_file}}", "network_data.json"
        ).replace(
            "{{timestamp}}", time.strftime("%Y-%m-%d %H:%M:%S")
        ).replace(
            "{{total_hosts}}", str(data["statistics"]["total_hosts"])
        ).replace(
            "{{high_risk_count}}", str(data["statistics"]["high_risk_count"])
        ).replace(
            "{{total_vulnerabilities}}", str(data["statistics"]["total_vulnerabilities"])
        ).replace(
            "{{total_services}}", str(data["statistics"]["total_services"])
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return {
            "success": True,
            "output_file": str(output_path),
            "data_file": str(data_file),
            "format": "html",
            "nodes": len(data["nodes"]),
            "edges": len(data["edges"])
        }
    
    def _generate_json_visualization(self, data: Dict, config: Dict) -> Dict:
        """Generate JSON visualization data"""
        output_path = Path(config["output"])
        output_dir = output_path.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return {
            "success": True,
            "output_file": str(output_path),
            "format": "json",
            "nodes": len(data["nodes"]),
            "edges": len(data["edges"])
        }
    
    def _generate_svg_visualization(self, data: Dict, config: Dict) -> Dict:
        """Generate SVG visualization"""
        # This would require a more complex implementation
        # For now, we'll generate HTML and convert to SVG if needed
        return self._generate_html_visualization(data, config)
    
    def generate_interactive_map(self, data: Dict, output_dir: str) -> Dict:
        """Generate interactive network map with real-time updates"""
        output_path = Path(output_dir) / "interactive_map.html"
        
        # Enhanced template for interactive features
        interactive_template = self._get_interactive_template()
        
        # Prepare enhanced data
        enhanced_data = self._enhance_data_for_interactivity(data)
        
        # Generate interactive HTML
        html_content = interactive_template.replace(
            "{{network_data}}", json.dumps(enhanced_data)
        ).replace(
            "{{timestamp}}", time.strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return {
            "success": True,
            "output_file": str(output_path),
            "type": "interactive",
            "features": ["real-time", "filtering", "search", "details"]
        }
    
    def _get_interactive_template(self) -> str:
        """Get enhanced interactive template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Interactive Network Topology Map</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f0f0f0; }
        .container { max-width: 1600px; margin: 0 auto; background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 20px; }
        .controls { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .search-box { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 200px; }
        .filter-buttons button { margin: 0 5px; padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; }
        .filter-buttons .active { background: #007bff; color: white; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-box h3 { margin: 0 0 10px 0; font-size: 14px; }
        .stat-box p { margin: 0; font-size: 24px; font-weight: bold; }
        #network-map { border: 1px solid #ddd; border-radius: 8px; background: white; }
        .details-panel { position: fixed; right: 20px; top: 20px; width: 300px; background: white; border: 1px solid #ddd; border-radius: 8px; padding: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); display: none; }
        .node-details h4 { margin: 0 0 10px 0; color: #333; }
        .vulnerability-list { max-height: 200px; overflow-y: auto; }
        .vulnerability-item { padding: 5px; margin: 2px 0; border-radius: 3px; font-size: 12px; }
        .vuln-high { background: #ffebee; color: #c62828; }
        .vuln-medium { background: #fff3e0; color: #ef6c00; }
        .vuln-low { background: #e8f5e8; color: #2e7d32; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Interactive Network Topology Map</h1>
            <p>Generated on {{timestamp}}</p>
        </div>
        
        <div class="controls">
            <div>
                <input type="text" class="search-box" placeholder="Search hosts..." id="searchBox">
            </div>
            <div class="filter-buttons">
                <button class="active" data-filter="all">All</button>
                <button data-filter="high-risk">High Risk</button>
                <button data-filter="vulnerable">Vulnerable</button>
                <button data-filter="services">By Service</button>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>Total Hosts</h3>
                <p id="totalHosts">0</p>
            </div>
            <div class="stat-box">
                <h3>High Risk</h3>
                <p id="highRisk">0</p>
            </div>
            <div class="stat-box">
                <h3>Vulnerabilities</h3>
                <p id="totalVulns">0</p>
            </div>
            <div class="stat-box">
                <h3>Services</h3>
                <p id="totalServices">0</p>
            </div>
        </div>
        
        <div id="network-map"></div>
    </div>
    
    <div class="details-panel" id="detailsPanel">
        <div class="node-details">
            <h4 id="nodeTitle">Host Details</h4>
            <div id="nodeInfo"></div>
            <div class="vulnerability-list" id="vulnList"></div>
        </div>
    </div>
    
    <script>
        const networkData = {{network_data}};
        
        // Initialize visualization
        let simulation, nodes, links;
        let filteredData = networkData;
        
        function initVisualization() {
            const container = document.getElementById('network-map');
            const width = container.clientWidth || 1200;
            const height = 600;
            
            const svg = d3.select(container)
                .append('svg')
                .attr('width', width)
                .attr('height', height);
            
            // Create force simulation
            simulation = d3.forceSimulation(filteredData.nodes)
                .force('link', d3.forceLink(filteredData.edges).id(d => d.id))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2));
            
            // Create links
            links = svg.append('g')
                .selectAll('line')
                .data(filteredData.edges)
                .enter().append('line')
                .attr('stroke', '#999')
                .attr('stroke-width', 2);
            
            // Create nodes
            nodes = svg.append('g')
                .selectAll('circle')
                .data(filteredData.nodes)
                .enter().append('circle')
                .attr('r', d => Math.max(5, d.risk_score / 10))
                .attr('fill', d => getNodeColor(d.risk_score))
                .attr('stroke', '#fff')
                .attr('stroke-width', 2)
                .on('click', showNodeDetails)
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended));
            
            // Add tooltips
            nodes.append('title')
                .text(d => `${d.ip}\\nRisk: ${d.risk_score}\\nServices: ${d.services.join(', ')}`);
            
            // Update positions
            simulation.on('tick', () => {
                links
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
                
                nodes
                    .attr('cx', d => d.x)
                    .attr('cy', d => d.y);
            });
            
            updateStats();
        }
        
        function getNodeColor(riskScore) {
            if (riskScore >= 70) return '#ff4444';
            if (riskScore >= 40) return '#ffaa00';
            if (riskScore >= 20) return '#ffff00';
            return '#44ff44';
        }
        
        function showNodeDetails(event, d) {
            const panel = document.getElementById('detailsPanel');
            const title = document.getElementById('nodeTitle');
            const info = document.getElementById('nodeInfo');
            const vulnList = document.getElementById('vulnList');
            
            title.textContent = d.ip;
            info.innerHTML = `
                <p><strong>Hostname:</strong> ${d.hostname || 'N/A'}</p>
                <p><strong>Risk Score:</strong> ${d.risk_score}</p>
                <p><strong>Services:</strong> ${d.services.join(', ') || 'None'}</p>
                <p><strong>Open Ports:</strong> ${d.ports.length}</p>
            `;
            
            if (d.vulnerabilities && d.vulnerabilities.length > 0) {
                vulnList.innerHTML = '<h5>Vulnerabilities:</h5>';
                d.vulnerabilities.forEach(vuln => {
                    const severity = vuln.severity || 'info';
                    vulnList.innerHTML += `
                        <div class="vulnerability-item vuln-${severity}">
                            ${vuln.output}
                        </div>
                    `;
                });
            } else {
                vulnList.innerHTML = '<p>No vulnerabilities detected</p>';
            }
            
            panel.style.display = 'block';
        }
        
        function updateStats() {
            document.getElementById('totalHosts').textContent = filteredData.nodes.length;
            document.getElementById('highRisk').textContent = filteredData.nodes.filter(n => n.risk_score >= 40).length;
            document.getElementById('totalVulns').textContent = filteredData.nodes.reduce((sum, n) => sum + (n.vulnerabilities ? n.vulnerabilities.length : 0), 0);
            document.getElementById('totalServices').textContent = new Set(filteredData.nodes.flatMap(n => n.services)).size;
        }
        
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
        
        // Initialize
        initVisualization();
        
        // Close details panel when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('#detailsPanel') && !e.target.closest('circle')) {
                document.getElementById('detailsPanel').style.display = 'none';
            }
        });
    </script>
</body>
</html>
        """
    
    def _enhance_data_for_interactivity(self, data: Dict) -> Dict:
        """Enhance data for interactive features"""
        enhanced_data = data.copy()
        
        # Add additional properties for interactivity
        for node in enhanced_data["nodes"]:
            node["display_name"] = node.get("hostname") or node["ip"]
            node["tooltip"] = f"IP: {node['ip']}\\nRisk: {node.get('risk_score', 0)}\\nServices: {', '.join(node.get('services', []))}"
            
            # Categorize vulnerabilities
            if node.get("vulnerabilities"):
                node["vuln_categories"] = {}
                for vuln in node["vulnerabilities"]:
                    severity = vuln.get("severity", "info")
                    if severity not in node["vuln_categories"]:
                        node["vuln_categories"][severity] = []
                    node["vuln_categories"][severity].append(vuln)
        
        return enhanced_data


def main():
    """Test topology mapper"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Topology Mapper")
    parser.add_argument("--input", required=True, help="Input JSON data file")
    parser.add_argument("--output", default="topology_map.html", help="Output file")
    parser.add_argument("--format", default="html", choices=["html", "json", "svg"], help="Output format")
    
    args = parser.parse_args()
    
    mapper = TopologyMapper()
    
    # Load sample data
    with open(args.input, 'r') as f:
        data = json.load(f)
    
    config = {
        "data": data,
        "output": args.output,
        "format": args.format,
        "interactive": True
    }
    
    result = mapper.generate_topology(config)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main() 