#!/usr/bin/env python3
"""
Report Generation Module
Handles HTML, JSON, CSV, and Markdown report generation with enhanced visuals
"""

import json
import csv
import logging
from datetime import datetime
from pathlib import Path
from cve_checker import EnhancedCVEChecker

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.cve_checker = EnhancedCVEChecker()
    
    def generate_html(self, scan_results, filename="network_scan_report.html"):
        """Generate enhanced HTML report with charts and color coding"""
        
        # Get CVE statistics for charts
        stats = self.cve_checker.get_statistics(scan_results)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Scan Report</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .scan-info {{
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 2px solid #e9ecef;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-top: 4px solid #007bff;
        }}
        
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
        }}
        
        .chart-container {{
            width: 300px;
            height: 300px;
            margin: 20px auto;
        }}
        
        .host-section {{
            margin: 30px;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .host-header {{
            background: #343a40;
            color: white;
            padding: 15px 20px;
            font-size: 1.2em;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .services-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .services-table th {{
            background: #007bff;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        
        .services-table td {{
            padding: 12px;
            border-bottom: 1px solid #e9ecef;
            vertical-align: top;
        }}
        
        .services-table tr:hover {{
            background: #f8f9fa;
        }}
        
        .cve-item {{
            margin: 5px 0;
            padding: 8px 12px;
            border-radius: 5px;
            border-left: 4px solid;
            font-size: 0.9em;
        }}
        
        .cve-critical {{
            background: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }}
        
        .cve-high {{
            background: #ffeaa7;
            border-color: #fd7e14;
            color: #856404;
        }}
        
        .cve-medium {{
            background: #fff3cd;
            border-color: #ffc107;
            color: #664d03;
        }}
        
        .cve-low {{
            background: #d1edff;
            border-color: #28a745;
            color: #155724;
        }}
        
        .weak-config {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 5px;
            padding: 8px;
            margin: 5px 0;
            color: #664d03;
        }}
        
        .no-issues {{
            color: #28a745;
            font-weight: bold;
        }}
        
        .port-badge {{
            background: #007bff;
            color: white;
            padding: 4px 8px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        
        .service-badge {{
            background: #6c757d;
            color: white;
            padding: 3px 6px;
            border-radius: 3px;
            font-size: 0.7em;
            text-transform: uppercase;
        }}
        
        .banner-text {{
            font-family: monospace;
            background: #f8f9fa;
            padding: 5px;
            border-radius: 3px;
            font-size: 0.8em;
            word-break: break-all;
        }}
        
        .footer {{
            background: #343a40;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                margin: 10px;
                border-radius: 10px;
            }}
            
            .header h1 {{
                font-size: 1.8em;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ NetGuard - Enterprise Network Security Scanner v2.0</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="scan-info">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{len(scan_results)}</div>
                    <div>Active Hosts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{sum(len(host.get('services', [])) for host in scan_results)}</div>
                    <div>Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['total_cves']}</div>
                    <div>Total CVEs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['unique_cves']}</div>
                    <div>Unique CVEs</div>
                </div>
            </div>
            
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        
        <div class="content">"""
        
        # Generate host sections
        for host in scan_results:
            host_cve_count = sum(len(service.get('cves', [])) for service in host.get('services', []))
            os_info = host.get('os', 'Unknown')
            
            html_content += f"""
            <div class="host-section">
                <div class="host-header">
                    <span>🖥️ Host: {host['ip']}</span>
                    <span>OS: {os_info} | CVEs: {host_cve_count}</span>
                </div>
                
                <table class="services-table">
                    <thead>
                        <tr>
                            <th>Port/Service</th>
                            <th>Banner</th>
                            <th>Security Issues</th>
                        </tr>
                    </thead>
                    <tbody>"""
            
            services = host.get('services', [])
            if services:
                for service in services:
                    port = service['port']
                    service_name = service['service']
                    banner = service.get('banner', 'N/A')
                    cves = service.get('cves', [])
                    weak_configs = service.get('weak_configs', [])
                    
                    # Truncate long banners
                    display_banner = banner[:100] + "..." if len(banner) > 100 else banner
                    
                    html_content += f"""
                        <tr>
                            <td>
                                <span class="port-badge">{port}</span>
                                <span class="service-badge">{service_name}</span>
                            </td>
                            <td>
                                <div class="banner-text">{display_banner}</div>
                            </td>
                            <td>"""
                    
                    # Add CVEs
                    if cves:
                        for cve in cves:
                            severity = cve.get('severity', 'Unknown').lower()
                            emoji = self.cve_checker.get_severity_emoji(cve.get('severity', 'Unknown'))
                            cvss = cve.get('cvss_score', 0.0)
                            
                            html_content += f"""
                                <div class="cve-item cve-{severity}">
                                    {emoji} <strong>{cve['cve_id']}</strong> (CVSS: {cvss})<br>
                                    {cve['description']}<br>
                                    <small>📍 Source: {cve.get('source', 'Unknown')}</small>
                                </div>"""
                    
                    # Add weak configurations
                    if weak_configs:
                        for config in weak_configs:
                            html_content += f"""
                                <div class="weak-config">
                                    ⚠️ {config}
                                </div>"""
                    
                    # No issues found
                    if not cves and not weak_configs:
                        html_content += '<span class="no-issues">✅ No known issues</span>'
                    
                    html_content += "</td></tr>"
            else:
                html_content += '<tr><td colspan="3">No open ports found</td></tr>'
            
            html_content += """
                    </tbody>
                </table>
            </div>"""
        
        # Chart JavaScript and footer
        html_content += f"""
        </div>
        
        <div class="footer">
            Report generated by 🛡️ NetGuard - Enterprise Network Security Scanner v2.0<br>
            Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
    
    <script>
        // Severity distribution chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{stats['by_severity']['Critical']}, {stats['by_severity']['High']}, {stats['by_severity']['Medium']}, {stats['by_severity']['Low']}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    title: {{
                        display: true,
                        text: 'CVE Severity Distribution'
                    }},
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        # Save the report
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved: {filename}")
    
    def generate_json(self, scan_results, filename="scan_results.json"):
        """Generate JSON report"""
        report_data = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "scanner": "Advanced Network Scanner v2.0",
                "total_hosts": len(scan_results),
                "total_open_ports": sum(len(host.get('services', [])) for host in scan_results)
            },
            "statistics": self.cve_checker.get_statistics(scan_results),
            "scan_results": scan_results
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=4, default=str)
        
        logger.info(f"JSON report saved: {filename}")
    
    def generate_csv(self, scan_results, filename="scan_results.csv"):
        """Generate CSV report"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'IP', 'Port', 'Service', 'Banner', 'CVE_ID', 'CVE_Description', 
                'Severity', 'CVSS_Score', 'Weak_Configs', 'OS'
            ])
            
            # Data rows
            for host in scan_results:
                ip = host['ip']
                os_info = host.get('os', 'Unknown')
                
                for service in host.get('services', []):
                    port = service['port']
                    service_name = service['service']
                    banner = service.get('banner', 'N/A').replace('\n', ' ').replace('\r', '')
                    weak_configs = '; '.join(service.get('weak_configs', []))
                    
                    cves = service.get('cves', [])
                    if cves:
                        for cve in cves:
                            writer.writerow([
                                ip, port, service_name, banner,
                                cve['cve_id'], cve['description'],
                                cve.get('severity', 'Unknown'),
                                cve.get('cvss_score', 0.0),
                                weak_configs, os_info
                            ])
                    else:
                        writer.writerow([
                            ip, port, service_name, banner,
                            '', '', '', '', weak_configs, os_info
                        ])
        
        logger.info(f"CSV report saved: {filename}")
    
    def generate_markdown(self, scan_results, filename="scan_report.md"):
        """Generate Markdown report"""
        stats = self.cve_checker.get_statistics(scan_results)
        
        md_content = f"""# 🛡️ Network Security Scan Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📊 Executive Summary

- **Active Hosts:** {len(scan_results)}
- **Total Open Ports:** {sum(len(host.get('services', [])) for host in scan_results)}
- **Total CVEs Found:** {stats['total_cves']}
- **Unique CVEs:** {stats['unique_cves']}
- **Affected Hosts:** {stats['affected_hosts']}

### CVE Severity Breakdown
- 🔴 **Critical:** {stats['by_severity']['Critical']}
- 🟠 **High:** {stats['by_severity']['High']}
- 🟡 **Medium:** {stats['by_severity']['Medium']}
- 🟢 **Low:** {stats['by_severity']['Low']}

---

## 🖥️ Detailed Findings

"""
        
        for host in scan_results:
            md_content += f"""### Host: {host['ip']}

**Operating System:** {host.get('os', 'Unknown')}  
**Open Ports:** {len(host.get('services', []))}

| Port | Service | Banner | Security Issues |
|------|---------|--------|-----------------|
"""
            
            for service in host.get('services', []):
                port = service['port']
                service_name = service['service']
                banner = service.get('banner', 'N/A')[:50] + "..." if len(service.get('banner', 'N/A')) > 50 else service.get('banner', 'N/A')
                
                issues = []
                for cve in service.get('cves', []):
                    emoji = self.cve_checker.get_severity_emoji(cve.get('severity', 'Unknown'))
                    issues.append(f"{emoji} {cve['cve_id']}")
                
                for config in service.get('weak_configs', []):
                    issues.append(f"⚠️ {config}")
                
                issues_str = "<br>".join(issues) if issues else "✅ None"
                
                md_content += f"| {port} | {service_name} | `{banner}` | {issues_str} |\n"
            
            md_content += "\n"
        
        md_content += f"""
---

## 📋 Recommendations

1. **Critical/High CVEs:** Prioritize patching systems with critical and high severity vulnerabilities
2. **Weak Configurations:** Review and harden service configurations
3. **Regular Scanning:** Implement regular vulnerability assessments
4. **Access Control:** Ensure proper network segmentation and access controls

*Report generated by Advanced Network Scanner v2.0*
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        logger.info(f"Markdown report saved: {filename}")
