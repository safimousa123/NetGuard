#!/usr/bin/env python3
"""
Utilities Module
Helper functions for logging, validation, and common operations
"""

import logging
import ipaddress
import re
from pathlib import Path

def setup_logging(verbose=False, log_file="scanner.log"):
    """Setup logging configuration"""
    
    # Create logs directory if it doesn't exist
    log_path = Path("logs")
    log_path.mkdir(exist_ok=True)
    
    # Configure logging level
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup file handler
    file_handler = logging.FileHandler(log_path / log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Setup console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Prevent duplicate logs
    root_logger.propagate = False
    
    return root_logger

def validate_ip_range(ip_range):
    """Validate IP range format (CIDR or range notation)"""
    try:
        if "/" in ip_range:
            # CIDR notation
            ipaddress.IPv4Network(ip_range, strict=False)
            return True
        elif "-" in ip_range:
            # Range notation (e.g., 192.168.1.1-50)
            if ip_range.count('.') == 3:
                base_ip, end_part = ip_range.rsplit('.', 1)
                if '-' in end_part:
                    start_end, end_end = end_part.split('-')
                    try:
                        start_num = int(start_end)
                        end_num = int(end_end)
                        if 0 <= start_num <= 255 and 0 <= end_num <= 255 and start_num <= end_num:
                            # Validate base IP
                            ipaddress.IPv4Address(f"{base_ip}.{start_num}")
                            return True
                    except ValueError:
                        pass
        else:
            # Single IP
            ipaddress.IPv4Address(ip_range)
            return True
    except (ipaddress.AddressValueError, ValueError):
        pass
    
    return False

def validate_ports(ports_str):
    """Validate port specification"""
    try:
        if "-" in ports_str:
            # Port range
            start, end = map(int, ports_str.split("-"))
            return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end
        else:
            # Comma-separated ports
            ports = [int(p.strip()) for p in ports_str.split(",")]
            return all(1 <= port <= 65535 for port in ports)
    except ValueError:
        return False

def get_service_name(port):
    """Get service name for common ports"""
    common_services = {
        21: "ftp",
        22: "ssh", 
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        389: "ldap",
        443: "https",
        445: "microsoft-ds",
        465: "smtps",
        587: "smtp-submission",
        636: "ldaps",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        2049: "nfs",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        9200: "elasticsearch",
        27017: "mongodb"
    }
    return common_services.get(port, "unknown")

def parse_ip_range(ip_range):
    """Parse IP range into list of IPs"""
    ips = []
    
    try:
        if "/" in ip_range:
            # CIDR notation
            network = ipaddress.IPv4Network(ip_range, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        elif "-" in ip_range and ip_range.count('.') == 3:
            # Range notation
            base_ip, end_part = ip_range.rsplit('.', 1)
            if '-' in end_part:
                start_end, end_end = end_part.split('-')
                start_num = int(start_end)
                end_num = int(end_end)
                ips = [f"{base_ip}.{i}" for i in range(start_num, end_num + 1)]
        else:
            # Single IP
            ips = [ip_range]
    except Exception as e:
        logging.error(f"Error parsing IP range {ip_range}: {e}")
    
    return ips

def parse_ports(ports_str):
    """Parse port specification into list of ports"""
    ports = []
    
    try:
        if "-" in ports_str:
            # Port range
            start, end = map(int, ports_str.split("-"))
            ports = list(range(start, end + 1))
        else:
            # Comma-separated ports
            ports = [int(p.strip()) for p in ports_str.split(",")]
    except Exception as e:
        logging.error(f"Error parsing ports {ports_str}: {e}")
    
    return ports

def format_banner(banner, max_length=100):
    """Format banner for display"""
    if not banner or banner == "N/A":
        return "N/A"
    
    # Clean banner
    cleaned = re.sub(r'[\r\n\t]+', ' ', banner).strip()
    
    # Truncate if too long
    if len(cleaned) > max_length:
        return cleaned[:max_length] + "..."
    
    return cleaned

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    size_index = 0
    
    while size_bytes >= 1024 and size_index < len(size_names) - 1:
        size_bytes /= 1024
        size_index += 1
    
    return f"{size_bytes:.1f} {size_names[size_index]}"

def create_directory_structure():
    """Create the required directory structure"""
    directories = ["data", "reports", "logs"]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        logging.debug(f"Created/verified directory: {directory}")

def get_scan_summary(scan_results):
    """Generate a summary of scan results"""
    if not scan_results:
        return "No active hosts found"
    
    total_hosts = len(scan_results)
    total_ports = sum(len(host.get('services', [])) for host in scan_results)
    total_cves = sum(
        len(service.get('cves', []))
        for host in scan_results
        for service in host.get('services', [])
    )
    
    return f"Found {total_hosts} active hosts with {total_ports} open ports and {total_cves} potential vulnerabilities"

def validate_output_filename(filename):
    """Validate and sanitize output filename"""
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Ensure it's not empty
    if not sanitized:
        sanitized = "scan_report"
    
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    
    return sanitized

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    @classmethod
    def colorize(cls, text, color):
        """Colorize text for terminal output"""
        return f"{color}{text}{cls.END}"

def check_dependencies():
    """Check if required Python packages are installed"""
    required_packages = ["requests"]
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing required packages: {', '.join(missing_packages)}")
        print("📦 Install with: pip3 install " + " ".join(missing_packages))
        return False
    
    return True

def print_banner():
    """Print application banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                   NETWORK SCANNER v2.0                   ║
║              Advanced Security Assessment Tool            ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}🔍 Features: Port Scanning | CVE Detection | OS Fingerprinting{Colors.END}
{Colors.YELLOW}📊 Reports: HTML | JSON | CSV | Markdown{Colors.END}
{Colors.YELLOW}⚡ Enhanced: Multi-threading | Weak Config Detection{Colors.END}
"""
    print(banner)
