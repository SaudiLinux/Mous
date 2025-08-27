#!/usr/bin/env python3
"""
Report Generator for Mous Scanner
Author: SayerLinux
"""

import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import jinja2
import os


class ReportGenerator:
    """Generate vulnerability scan reports in multiple formats"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment for HTML templates
        template_dir = Path(__file__).parent / "templates"
        template_dir.mkdir(exist_ok=True)
        
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Create default templates if they don't exist
        self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default HTML report templates"""
        template_dir = Path(__file__).parent / "templates"
        
        # Default HTML template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mous Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .summary { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .vulnerability { background: white; margin: 10px 0; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #ff6b6b; }
        .severity-critical { border-left-color: #d32f2f; }
        .severity-high { border-left-color: #f57c00; }
        .severity-medium { border-left-color: #fbc02d; }
        .severity-low { border-left-color: #388e3c; }
        .severity-info { border-left-color: #1976d2; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background-color: #f8f9fa; }
        .logo { font-size: 1.5em; font-weight: bold; margin-bottom: 10px; }
        .footer { text-align: center; margin-top: 40px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🔍 Mous Security Scanner</div>
        <h1>Vulnerability Scan Report</h1>
        <p>Generated on {{ scan_date }} | Target: {{ target_url }}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{{ total_vulnerabilities }}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ critical_count }}</div>
                <div>Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ high_count }}</div>
                <div>High</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ medium_count }}</div>
                <div>Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ low_count }}</div>
                <div>Low</div>
            </div>
        </div>
    </div>

    <div class="summary">
        <h2>Scan Details</h2>
        <p><strong>Scan Duration:</strong> {{ scan_duration }} seconds</p>
        <p><strong>Total Requests:</strong> {{ total_requests }}</p>
        <p><strong>Scan Types:</strong> {{ scan_types|join(", ") }}</p>
    </div>

    <div class="summary">
        <h2>Vulnerabilities Found</h2>
        {% for vuln in vulnerabilities %}
        <div class="vulnerability severity-{{ vuln.severity.lower() }}">
            <h3>{{ vuln.name }}</h3>
            <p><strong>Severity:</strong> <span style="color: {{ vuln.severity_color }}">{{ vuln.severity }}</span></p>
            <p><strong>Type:</strong> {{ vuln.type }}</p>
            <p><strong>URL:</strong> <code>{{ vuln.url }}</code></p>
            <p><strong>Description:</strong> {{ vuln.description }}</p>
            {% if vuln.evidence %}
            <p><strong>Evidence:</strong></p>
            <pre>{{ vuln.evidence }}</pre>
            {% endif %}
            {% if vuln.remediation %}
            <p><strong>Remediation:</strong> {{ vuln.remediation }}</p>
            {% endif %}
            {% if vuln.cve_id %}
            <p><strong>CVE:</strong> <a href="https://nvd.nist.gov/vuln/detail/{{ vuln.cve_id }}" target="_blank">{{ vuln.cve_id }}</a></p>
            {% endif %}
        </div>
        {% endfor %}
    </div>

    <div class="footer">
        <p>Generated by Mous Security Scanner</p>
        <p>Author: SayerLinux | <a href="https://github.com/SaudiLinux">https://github.com/SaudiLinux</a></p>
        <p>Email: SayerLinux@gmail.com</p>
    </div>
</body>
</html>
"""
        
        with open(template_dir / "default.html", "w") as f:
            f.write(html_template)
    
    def generate_report(self, scan_results: Dict[str, Any], format_type: str = "html", 
                       output_file: str = None) -> str:
        """Generate report in specified format"""
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"mous_scan_report_{timestamp}.{format_type}"
        
        output_path = self.output_dir / output_file
        
        if format_type.lower() == "html":
            return self._generate_html_report(scan_results, str(output_path))
        elif format_type.lower() == "csv":
            return self._generate_csv_report(scan_results, str(output_path))
        elif format_type.lower() == "xml":
            return self._generate_xml_report(scan_results, str(output_path))
        elif format_type.lower() == "json":
            return self._generate_json_report(scan_results, str(output_path))
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _generate_html_report(self, scan_results: Dict[str, Any], output_path: str) -> str:
        """Generate HTML report"""
        
        # Prepare data for template
        template_data = self._prepare_template_data(scan_results)
        
        # Get template
        template = self.jinja_env.get_template("default.html")
        
        # Render HTML
        html_content = template.render(**template_data)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _generate_csv_report(self, scan_results: Dict[str, Any], output_path: str) -> str:
        """Generate CSV report"""
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'name', 'type', 'severity', 'url', 'description', 
                'evidence', 'remediation', 'cve_id', 'scan_type', 'timestamp'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for vuln in vulnerabilities:
                writer.writerow({
                    'name': vuln.get('name', ''),
                    'type': vuln.get('type', ''),
                    'severity': vuln.get('severity', ''),
                    'url': vuln.get('url', ''),
                    'description': vuln.get('description', ''),
                    'evidence': vuln.get('evidence', ''),
                    'remediation': vuln.get('remediation', ''),
                    'cve_id': vuln.get('cve_id', ''),
                    'scan_type': vuln.get('scan_type', ''),
                    'timestamp': vuln.get('timestamp', '')
                })
        
        return output_path
    
    def _generate_xml_report(self, scan_results: Dict[str, Any], output_path: str) -> str:
        """Generate XML report"""
        
        # Create root element
        root = ET.Element("mous_scan_report")
        root.set("version", "1.0")
        root.set("generated", datetime.now().isoformat())
        
        # Add scan metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "target_url").text = scan_results.get('target_url', '')
        ET.SubElement(metadata, "scan_date").text = scan_results.get('scan_date', '')
        ET.SubElement(metadata, "scan_duration").text = str(scan_results.get('scan_duration', 0))
        ET.SubElement(metadata, "total_requests").text = str(scan_results.get('total_requests', 0))
        
        # Add summary
        summary = ET.SubElement(root, "summary")
        summary_data = scan_results.get('summary', {})
        ET.SubElement(summary, "total_vulnerabilities").text = str(summary_data.get('total', 0))
        ET.SubElement(summary, "critical_count").text = str(summary_data.get('critical', 0))
        ET.SubElement(summary, "high_count").text = str(summary_data.get('high', 0))
        ET.SubElement(summary, "medium_count").text = str(summary_data.get('medium', 0))
        ET.SubElement(summary, "low_count").text = str(summary_data.get('low', 0))
        
        # Add vulnerabilities
        vulnerabilities = ET.SubElement(root, "vulnerabilities")
        
        for vuln in scan_results.get('vulnerabilities', []):
            vuln_elem = ET.SubElement(vulnerabilities, "vulnerability")
            vuln_elem.set("severity", vuln.get('severity', ''))
            vuln_elem.set("type", vuln.get('type', ''))
            
            ET.SubElement(vuln_elem, "name").text = vuln.get('name', '')
            ET.SubElement(vuln_elem, "url").text = vuln.get('url', '')
            ET.SubElement(vuln_elem, "description").text = vuln.get('description', '')
            
            if vuln.get('evidence'):
                ET.SubElement(vuln_elem, "evidence").text = vuln.get('evidence')
            
            if vuln.get('remediation'):
                ET.SubElement(vuln_elem, "remediation").text = vuln.get('remediation')
            
            if vuln.get('cve_id'):
                ET.SubElement(vuln_elem, "cve_id").text = vuln.get('cve_id')
        
        # Write XML to file
        tree = ET.ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        
        return output_path
    
    def _generate_json_report(self, scan_results: Dict[str, Any], output_path: str) -> str:
        """Generate JSON report"""
        
        # Add metadata
        report_data = {
            "mous_version": "1.0.0",
            "generated_by": "Mous Security Scanner",
            "author": "SayerLinux",
            "github": "https://github.com/SaudiLinux",
            "email": "SayerLinux@gmail.com",
            "generated_at": datetime.now().isoformat(),
            "scan_results": scan_results
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        return output_path
    
    def _prepare_template_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for HTML template"""
        
        # Count vulnerabilities by severity
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Map severity colors
        severity_colors = {
            'critical': '#d32f2f',
            'high': '#f57c00',
            'medium': '#fbc02d',
            'low': '#388e3c',
            'info': '#1976d2'
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            vuln['severity_color'] = severity_colors.get(severity, '#666')
        
        return {
            'scan_date': scan_results.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'target_url': scan_results.get('target_url', 'Unknown'),
            'scan_duration': scan_results.get('scan_duration', 0),
            'total_requests': scan_results.get('total_requests', 0),
            'scan_types': scan_results.get('scan_types', []),
            'total_vulnerabilities': len(vulnerabilities),
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low'],
            'vulnerabilities': vulnerabilities
        }
    
    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """Generate executive summary text"""
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary = f"""
Mous Security Scan Executive Summary
=====================================

Target: {scan_results.get('target_url', 'Unknown')}
Scan Date: {scan_results.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
Scan Duration: {scan_results.get('scan_duration', 0)} seconds
Total Vulnerabilities Found: {len(vulnerabilities)}

Severity Distribution:
"""
        
        for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
            summary += f"  {severity}: {count}\n"
        
        summary += f"""

Recommendations:
1. Address all Critical and High severity vulnerabilities immediately
2. Review Medium severity vulnerabilities within 30 days
3. Implement security headers and proper configuration
4. Regular security assessments recommended

Generated by Mous Security Scanner
Author: SayerLinux
GitHub: https://github.com/SaudiLinux
Email: SayerLinux@gmail.com
"""
        
        return summary
    
    def create_comparison_report(self, scan_results_list: List[Dict[str, Any]], 
                               output_file: str = None) -> str:
        """Create comparison report for multiple scans"""
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"mous_comparison_report_{timestamp}.html"
        
        output_path = self.output_dir / output_file
        
        # Prepare comparison data
        comparison_data = {
            'scans': scan_results_list,
            'generated_at': datetime.now().isoformat()
        }
        
        # Generate comparison HTML
        comparison_html = self._generate_comparison_html(comparison_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(comparison_html)
        
        return str(output_path)
    
    def _generate_comparison_html(self, comparison_data: Dict[str, Any]) -> str:
        """Generate comparison HTML"""
        
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mous Comparison Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .scan-card { background: white; margin: 15px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .comparison-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .comparison-table th, .comparison-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .comparison-table th { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Mous Security Scan Comparison Report</h1>
        <p>Generated on {generated_at}</p>
    </div>

    <div class="scan-card">
        <h2>Scan Comparison</h2>
        <table class="comparison-table">
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Date</th>
                    <th>Total Vulns</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                </tr>
            </thead>
            <tbody>
                {scan_rows}
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p>Generated by Mous Security Scanner | Author: SayerLinux</p>
        <p>GitHub: <a href="https://github.com/SaudiLinux">https://github.com/SaudiLinux</a></p>
    </div>
</body>
</html>
"""
        
        # Generate scan rows
        scan_rows = ""
        for scan in comparison_data['scans']:
            vulns = scan.get('vulnerabilities', [])
            severity_counts = {}
            for vuln in vulns:
                severity = vuln.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            scan_rows += f"""
                <tr>
                    <td>{scan.get('target_url', 'Unknown')}</td>
                    <td>{scan.get('scan_date', 'Unknown')}</td>
                    <td>{len(vulns)}</td>
                    <td>{severity_counts.get('Critical', 0)}</td>
                    <td>{severity_counts.get('High', 0)}</td>
                    <td>{severity_counts.get('Medium', 0)}</td>
                    <td>{severity_counts.get('Low', 0)}</td>
                </tr>
            """
        
        return html.format(
            generated_at=comparison_data['generated_at'],
            scan_rows=scan_rows
        )