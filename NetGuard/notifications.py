#!/usr/bin/env python3
"""
Email Notifications Module
Handles automated email alerts for scan results and security changes
"""

import smtplib
import json
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
import ssl

logger = logging.getLogger(__name__)

class EmailNotifier:
    def __init__(self, config_file="config/email_config.json"):
        self.config_file = Path(config_file)
        self.config = {}
        
        # Ensure config directory exists
        self.config_file.parent.mkdir(exist_ok=True)
        
        # Load configuration
        self.load_config()
        
        logger.info("Email notifier initialized")
    
    def load_config(self):
        """Load email configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                logger.info(f"Loaded email configuration from {self.config_file}")
            else:
                # Create default configuration
                self.config = {
                    "enabled": False,
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "use_tls": True,
                    "username": "",
                    "password": "",
                    "from_email": "",
                    "from_name": "Network Scanner",
                    "recipients": [],
                    "notification_triggers": {
                        "scan_complete": True,
                        "new_critical_cve": True,
                        "new_high_cve": False,
                        "new_host": True,
                        "scan_failure": True,
                        "weekly_summary": True
                    },
                    "summary_schedule": {
                        "enabled": True,
                        "frequency": "weekly",
                        "day": "monday",
                        "time": "09:00"
                    }
                }
                self.save_config()
                logger.info("Created default email configuration")
        except Exception as e:
            logger.error(f"Error loading email config: {e}")
            self.config = {}
    
    def save_config(self):
        """Save email configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.debug("Email configuration saved")
        except Exception as e:
            logger.error(f"Error saving email config: {e}")
    
    def configure_email(self, smtp_server, smtp_port, username, password, 
                       from_email, recipients, use_tls=True):
        """Configure email settings"""
        self.config.update({
            "enabled": True,
            "smtp_server": smtp_server,
            "smtp_port": smtp_port,
            "use_tls": use_tls,
            "username": username,
            "password": password,
            "from_email": from_email,
            "recipients": recipients if isinstance(recipients, list) else [recipients]
        })
        self.save_config()
        logger.info(f"Email configured for {len(self.config['recipients'])} recipients")
    
    def test_connection(self):
        """Test email server connection"""
        if not self.config.get("enabled"):
            return False, "Email notifications are disabled"
        
        try:
            server = smtplib.SMTP(self.config["smtp_server"], self.config["smtp_port"])
            
            if self.config.get("use_tls"):
                context = ssl.create_default_context()
                # Allow self-signed certificates in corporate environments
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                server.starttls(context=context)
            
            server.login(self.config["username"], self.config["password"])
            server.quit()
            
            logger.info("Email server connection test successful")
            return True, "Connection successful"
            
        except Exception as e:
            logger.error(f"Email connection test failed: {e}")
            return False, str(e)
    
    def send_scan_complete_notification(self, scan_results, scan_duration, network_range):
        """Send notification when scan completes"""
        if not self._should_notify("scan_complete"):
            return False
        
        total_hosts = len(scan_results)
        total_ports = sum(len(host.get('services', [])) for host in scan_results)
        total_cves = sum(
            len(service.get('cves', []))
            for host in scan_results
            for service in host.get('services', [])
        )
        
        # Count CVEs by severity
        cve_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for host in scan_results:
            for service in host.get('services', []):
                for cve in service.get('cves', []):
                    severity = cve.get('severity', 'Unknown')
                    if severity in cve_counts:
                        cve_counts[severity] += 1
        
        subject = f"Network Scan Complete - {network_range}"
        
        # Create HTML content
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2>Network Scan Results</h2>
            <p><strong>Scan completed:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Network range:</strong> {network_range}</p>
            <p><strong>Duration:</strong> {scan_duration:.1f} seconds</p>
            
            <h3>Summary</h3>
            <table border="1" style="border-collapse: collapse;">
                <tr><td><strong>Active Hosts</strong></td><td>{total_hosts}</td></tr>
                <tr><td><strong>Open Ports</strong></td><td>{total_ports}</td></tr>
                <tr><td><strong>Total CVEs</strong></td><td>{total_cves}</td></tr>
            </table>
            
            <h3>Vulnerabilities by Severity</h3>
            <table border="1" style="border-collapse: collapse;">
                <tr style="background-color: #dc3545; color: white;"><td><strong>Critical</strong></td><td>{cve_counts['Critical']}</td></tr>
                <tr style="background-color: #fd7e14; color: white;"><td><strong>High</strong></td><td>{cve_counts['High']}</td></tr>
                <tr style="background-color: #ffc107;"><td><strong>Medium</strong></td><td>{cve_counts['Medium']}</td></tr>
                <tr style="background-color: #28a745; color: white;"><td><strong>Low</strong></td><td>{cve_counts['Low']}</td></tr>
            </table>
            
            <p><em>Detailed results are available in the generated reports.</em></p>
        </body>
        </html>
        """
        
        return self._send_email(subject, html_content, is_html=True)
    
    def send_change_notification(self, changes, network_range):
        """Send notification about detected changes"""
        if not changes or not self._should_notify_about_changes(changes):
            return False
        
        subject = f"Network Changes Detected - {network_range}"
        
        # Group changes by type
        change_groups = {}
        for change in changes:
            change_type = change['change_type']
            if change_type not in change_groups:
                change_groups[change_type] = []
            change_groups[change_type].append(change)
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2>Network Changes Detected</h2>
            <p><strong>Detection time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Network range:</strong> {network_range}</p>
            <p><strong>Total changes:</strong> {len(changes)}</p>
            
            <h3>Change Summary</h3>
        """
        
        for change_type, type_changes in change_groups.items():
            html_content += f"<h4>{change_type.replace('_', ' ').title()} ({len(type_changes)})</h4><ul>"
            
            for change in type_changes[:10]:  # Limit to first 10 of each type
                severity_color = self._get_severity_color(change.get('severity_level', 'Medium'))
                html_content += f"""
                <li style="color: {severity_color};">
                    <strong>{change.get('severity_level', 'Medium')}:</strong> 
                    {change['change_description']}
                </li>
                """
            
            if len(type_changes) > 10:
                html_content += f"<li><em>... and {len(type_changes) - 10} more {change_type} changes</em></li>"
            
            html_content += "</ul>"
        
        html_content += """
            <p><em>Run a new scan to see current network status.</em></p>
        </body>
        </html>
        """
        
        return self._send_email(subject, html_content, is_html=True)
    
    def send_critical_cve_alert(self, cve_data, host_ip, service_info):
        """Send immediate alert for critical CVEs"""
        if not self._should_notify("new_critical_cve"):
            return False
        
        subject = f"CRITICAL VULNERABILITY DETECTED - {host_ip}"
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #dc3545;">Critical Vulnerability Alert</h2>
            <p><strong>Detection time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h3>Vulnerability Details</h3>
            <table border="1" style="border-collapse: collapse;">
                <tr><td><strong>CVE ID</strong></td><td>{cve_data.get('cve_id', 'Unknown')}</td></tr>
                <tr><td><strong>Severity</strong></td><td style="color: #dc3545; font-weight: bold;">{cve_data.get('severity', 'Unknown')}</td></tr>
                <tr><td><strong>CVSS Score</strong></td><td>{cve_data.get('cvss_score', 'Unknown')}</td></tr>
                <tr><td><strong>Affected Host</strong></td><td>{host_ip}</td></tr>
                <tr><td><strong>Service</strong></td><td>{service_info.get('service', 'Unknown')} on port {service_info.get('port', 'Unknown')}</td></tr>
            </table>
            
            <h3>Description</h3>
            <p>{cve_data.get('description', 'No description available')}</p>
            
            <h3>Recommendation</h3>
            <p style="background-color: #fff3cd; padding: 10px; border: 1px solid #ffc107;">
                <strong>Immediate action required:</strong> This is a critical vulnerability that should be patched immediately.
                Please review the affected system and apply security updates as soon as possible.
            </p>
        </body>
        </html>
        """
        
        return self._send_email(subject, html_content, is_html=True, priority="high")
    
    def send_scan_failure_notification(self, error_message, network_range):
        """Send notification when scan fails"""
        if not self._should_notify("scan_failure"):
            return False
        
        subject = f"Network Scan Failed - {network_range}"
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #dc3545;">Scan Failure Alert</h2>
            <p><strong>Failure time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Network range:</strong> {network_range}</p>
            
            <h3>Error Details</h3>
            <div style="background-color: #f8d7da; padding: 10px; border: 1px solid #dc3545; border-radius: 4px;">
                <code>{error_message}</code>
            </div>
            
            <h3>Next Steps</h3>
            <ul>
                <li>Check network connectivity</li>
                <li>Verify scanner configuration</li>
                <li>Review system logs for additional details</li>
                <li>Retry the scan manually if needed</li>
            </ul>
        </body>
        </html>
        """
        
        return self._send_email(subject, html_content, is_html=True, priority="high")
    
    def send_weekly_summary(self, database):
        """Send weekly security summary"""
        if not self._should_notify("weekly_summary"):
            return False
        
        try:
            # Get trends for the last 7 days
            trends = database.get_vulnerability_trends(days_back=7)
            changes = database.get_recent_changes(days_back=7)
            scan_history = database.get_scan_history(days_back=7)
            
            if not scan_history:
                return False  # No scans to report on
            
            subject = "Weekly Network Security Summary"
            
            # Calculate summary statistics
            total_scans = len(scan_history)
            total_hosts = sum(scan.get('total_hosts', 0) for scan in scan_history)
            total_cves = sum(scan.get('total_cves', 0) for scan in scan_history)
            
            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>Weekly Network Security Summary</h2>
                <p><strong>Report period:</strong> Last 7 days</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h3>Scan Activity</h3>
                <table border="1" style="border-collapse: collapse;">
                    <tr><td><strong>Total Scans</strong></td><td>{total_scans}</td></tr>
                    <tr><td><strong>Hosts Scanned</strong></td><td>{total_hosts}</td></tr>
                    <tr><td><strong>Vulnerabilities Found</strong></td><td>{total_cves}</td></tr>
                    <tr><td><strong>Changes Detected</strong></td><td>{len(changes)}</td></tr>
                </table>
                
                <h3>Recent Changes</h3>
            """
            
            if changes:
                change_types = {}
                for change in changes:
                    change_type = change['change_type']
                    if change_type not in change_types:
                        change_types[change_type] = 0
                    change_types[change_type] += 1
                
                html_content += "<ul>"
                for change_type, count in change_types.items():
                    html_content += f"<li>{change_type.replace('_', ' ').title()}: {count}</li>"
                html_content += "</ul>"
            else:
                html_content += "<p>No significant changes detected this week.</p>"
            
            html_content += """
                <h3>Security Trend</h3>
            """
            
            if len(trends) >= 2:
                latest = trends[-1]
                previous = trends[0]
                cve_change = latest.get('total_cve_instances', 0) - previous.get('total_cve_instances', 0)
                
                if cve_change > 0:
                    html_content += f'<p style="color: #dc3545;">⚠️ Security trend: +{cve_change} vulnerabilities detected</p>'
                elif cve_change < 0:
                    html_content += f'<p style="color: #28a745;">✅ Security trend: {abs(cve_change)} vulnerabilities resolved</p>'
                else:
                    html_content += '<p>📊 Security trend: No significant change</p>'
            else:
                html_content += "<p>Insufficient data for trend analysis.</p>"
            
            html_content += """
                <p><em>This is an automated weekly summary. For detailed information, please review individual scan reports.</em></p>
            </body>
            </html>
            """
            
            return self._send_email(subject, html_content, is_html=True)
            
        except Exception as e:
            logger.error(f"Error generating weekly summary: {e}")
            return False
    
    def _should_notify(self, trigger_type):
        """Check if notification should be sent for given trigger"""
        if not self.config.get("enabled"):
            return False
        
        triggers = self.config.get("notification_triggers", {})
        return triggers.get(trigger_type, False)
    
    def _should_notify_about_changes(self, changes):
        """Determine if changes warrant notification"""
        for change in changes:
            change_type = change['change_type']
            severity = change.get('severity_level', 'Medium')
            
            if change_type == 'new_cve':
                if severity == 'Critical' and self._should_notify("new_critical_cve"):
                    return True
                if severity == 'High' and self._should_notify("new_high_cve"):
                    return True
            elif change_type == 'new_host' and self._should_notify("new_host"):
                return True
        
        return False
    
    def _get_severity_color(self, severity):
        """Get color for severity level"""
        colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14", 
            "Medium": "#ffc107",
            "Low": "#28a745"
        }
        return colors.get(severity, "#6c757d")
    
    def _send_email(self, subject, content, is_html=False, priority="normal", attachments=None):
        """Send email with given content"""
        if not self.config.get("enabled"):
            logger.debug("Email notifications disabled")
            return False
        
        recipients = self.config.get("recipients", [])
        if not recipients:
            logger.warning("No email recipients configured")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.get('from_name', 'Network Scanner')} <{self.config['from_email']}>"
            msg['To'] = ', '.join(recipients)
            
            if priority == "high":
                msg['X-Priority'] = '1'
                msg['X-MSMail-Priority'] = 'High'
            
            # Add content
            if is_html:
                msg.attach(MIMEText(content, 'html'))
            else:
                msg.attach(MIMEText(content, 'plain'))
            
            # Add attachments if provided
            if attachments:
                for attachment_path in attachments:
                    if Path(attachment_path).exists():
                        with open(attachment_path, "rb") as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {Path(attachment_path).name}'
                        )
                        msg.attach(part)
            
            # Send email
            server = smtplib.SMTP(self.config["smtp_server"], self.config["smtp_port"])
            
            if self.config.get("use_tls"):
                context = ssl.create_default_context()
                # Allow self-signed certificates in corporate environments
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                server.starttls(context=context)
            
            server.login(self.config["username"], self.config["password"])
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email notification sent: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False
