#!/usr/bin/env python3
"""
Network Scanner Module
Handles port scanning, banner grabbing, and service detection
"""

import socket
import subprocess
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import get_service_name

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, max_threads=100, timeout=4, os_detection=False, weak_config_tests=False):
        self.max_threads = max_threads
        self.timeout = timeout
        self.os_detection = os_detection
        self.weak_config_tests = weak_config_tests
    
    def scan_port(self, ip, port):
        """Scan a single port on target IP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    service_info = {
                        "port": port,
                        "service": get_service_name(port),
                        "ip": ip,
                        "state": "open"
                    }
                    return service_info
        except Exception as e:
            logger.debug(f"Error scanning {ip}:{port} - {e}")
        return None
    
    def grab_banner(self, ip, port, timeout=1):
        """Grab service banner"""
        try:
            with socket.socket() as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                
                # Send appropriate probe based on service
                if port == 80:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 443:
                    # For HTTPS, we'll just grab what we can
                    pass
                elif port in [21, 22, 23, 25, 110, 143]:
                    # These services usually send banner immediately
                    pass
                else:
                    # Generic probe
                    s.send(b"\r\n")
                
                banner = s.recv(1024).decode(errors='ignore').strip()
                return banner
        except Exception as e:
            logger.debug(f"Banner grab failed for {ip}:{port} - {e}")
            return None
    
    def detect_os_basic(self, ip):
        """Basic OS detection using TTL and other fingerprints"""
        try:
            # Ping to get TTL
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip], 
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'ttl=' in line.lower():
                        ttl = int(line.split('ttl=')[1].split()[0])
                        
                        # TTL-based OS detection
                        if ttl <= 64:
                            return "Linux/Unix"
                        elif ttl <= 128:
                            return "Windows"
                        else:
                            return "Network Device/Other"
                            
        except Exception as e:
            logger.debug(f"OS detection failed for {ip} - {e}")
        
        return "Unknown"
    
    def test_weak_configurations(self, ip, port, service):
        """Test for weak configurations"""
        weak_configs = []
        
        try:
            if service == "ftp" and port == 21:
                # Test anonymous FTP
                if self._test_anonymous_ftp(ip, port):
                    weak_configs.append("Anonymous FTP login allowed")
            
            elif service == "http" and port == 80:
                # Get HTTP headers
                headers = self._get_http_headers(ip, port)
                if headers:
                    weak_configs.extend(self._analyze_http_headers(headers))
            
            elif service == "smb" and port == 445:
                # Test SMB version
                smb_info = self._test_smb_version(ip)
                if smb_info:
                    weak_configs.extend(smb_info)
                    
        except Exception as e:
            logger.debug(f"Weak config test failed for {ip}:{port} - {e}")
        
        return weak_configs
    
    def _test_anonymous_ftp(self, ip, port):
        """Test for anonymous FTP login"""
        try:
            with socket.socket() as s:
                s.settimeout(2)
                s.connect((ip, port))
                s.recv(1024)  # Welcome banner
                
                s.send(b"USER anonymous\r\n")
                response = s.recv(1024).decode()
                
                if "331" in response:  # Password required
                    s.send(b"PASS anonymous@test.com\r\n")
                    response = s.recv(1024).decode()
                    return "230" in response  # Login successful
                    
        except:
            pass
        return False
    
    def _get_http_headers(self, ip, port):
        """Get HTTP headers"""
        try:
            with socket.socket() as s:
                s.settimeout(2)
                s.connect((ip, port))
                
                request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                s.send(request.encode())
                
                response = s.recv(4096).decode(errors='ignore')
                return response
        except:
            return None
    
    def _analyze_http_headers(self, headers):
        """Analyze HTTP headers for security issues"""
        issues = []
        headers_lower = headers.lower()
        
        if "server:" in headers_lower:
            server_line = [line for line in headers.split('\n') if line.lower().startswith('server:')]
            if server_line:
                issues.append(f"Server header exposed: {server_line[0].strip()}")
        
        if "x-powered-by:" in headers_lower:
            powered_line = [line for line in headers.split('\n') if line.lower().startswith('x-powered-by:')]
            if powered_line:
                issues.append(f"Technology stack exposed: {powered_line[0].strip()}")
        
        # Check for missing security headers
        security_headers = ["x-frame-options", "x-content-type-options", "strict-transport-security"]
        for header in security_headers:
            if header not in headers_lower:
                issues.append(f"Missing security header: {header}")
        
        return issues
    
    def _test_smb_version(self, ip):
        """Test SMB version and configuration"""
        try:
            # This is a simplified check - in practice you'd use more sophisticated SMB probing
            result = subprocess.run(
                ["smbclient", "-L", ip, "-N"], 
                capture_output=True, text=True, timeout=5
            )
            
            issues = []
            if "NT_STATUS_ACCESS_DENIED" not in result.stderr:
                issues.append("SMB null session allowed")
            
            return issues
        except:
            return []
    
    def scan_host(self, ip, ports, cve_checker):
        """Scan all ports on a single host"""
        logger.info(f"Scanning {ip}...")
        
        host_info = {
            "ip": ip,
            "services": [],
            "os": None,
            "scan_time": None
        }
        
        # OS Detection
        if self.os_detection:
            host_info["os"] = self.detect_os_basic(ip)
        
        # Port scanning
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    # Banner grabbing
                    banner = self.grab_banner(ip, result["port"])
                    result["banner"] = banner if banner else "N/A"
                    
                    # CVE checking
                    result["cves"] = cve_checker.check_service(result["service"], banner)
                    
                    # Weak configuration tests
                    if self.weak_config_tests:
                        weak_configs = self.test_weak_configurations(ip, result["port"], result["service"])
                        result["weak_configs"] = weak_configs
                    
                    open_ports.append(result)
        
        host_info["services"] = open_ports
        return host_info if open_ports else None
    
    def scan_network(self, ip_range, ports, cve_checker):
        """Scan entire network range"""
        active_hosts = []
        
        # Parse IP range
        if isinstance(ip_range, str):
            if "/" in ip_range:
                # CIDR notation
                targets = [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False)]
            elif "-" in ip_range:
                # Range notation (192.168.1.1-50)
                base_ip, end_range = ip_range.rsplit(".", 1)
                if "-" in end_range:
                    start, end = map(int, end_range.split("-"))
                    targets = [f"{base_ip}.{i}" for i in range(start, end + 1)]
                else:
                    targets = [ip_range]
            else:
                targets = [ip_range]
        else:
            targets = ip_range
        
        logger.info(f"Scanning {len(targets)} targets...")
        
        # Scan each target
        with ThreadPoolExecutor(max_workers=min(10, len(targets))) as executor:
            future_to_ip = {
                executor.submit(self.scan_host, ip, ports, cve_checker): ip 
                for ip in targets
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        active_hosts.append(result)
                        logger.info(f"✅ {ip}: {len(result['services'])} open ports")
                    else:
                        logger.debug(f"❌ {ip}: No open ports")
                except Exception as e:
                    logger.error(f"Error scanning {ip}: {e}")
        
        return active_hosts
