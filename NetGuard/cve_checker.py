#!/usr/bin/env python3
"""
Enhanced CVE Checker Module
Handles CVE database loading and vulnerability matching with API integration
Supports both local database and real-time NIST API lookups
"""

import json
import requests
import logging
import time
import re
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)

class EnhancedCVEChecker:
    def __init__(self, cve_database_path="data/cves.json", use_api=True):
        self.local_database = []
        self.use_api = use_api
        self.api_cache = {}
        self.cache_file = "data/api_cache.json"
        
        # Load local database
        self.load_cve_database(cve_database_path)
        
        # Load API cache if using API
        if self.use_api:
            self.load_api_cache()
        
        # API configuration
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
        self.api_delay = 1.5  # Rate limiting - 1.5 seconds between requests
        self.last_api_call = 0
        self.api_timeout = 10
        
        logger.info(f"CVE Checker initialized - API: {'Enabled' if use_api else 'Disabled'}")
    
    def load_cve_database(self, filepath):
        """Load CVE database from JSON file"""
        try:
            cve_path = Path(filepath)
            if cve_path.exists():
                with open(cve_path, 'r') as f:
                    self.local_database = json.load(f)
                logger.info(f"✅ Loaded {len(self.local_database)} local CVE entries")
            else:
                logger.error(f"CVE database not found at {filepath}")
                logger.error("Please ensure data/cves.json exists")
                self.local_database = []
        except Exception as e:
            logger.error(f"Failed to load CVE database: {e}")
            self.local_database = []
    
    def load_api_cache(self):
        """Load cached API responses"""
        try:
            if Path(self.cache_file).exists():
                with open(self.cache_file, 'r') as f:
                    self.api_cache = json.load(f)
                logger.info(f"📄 Loaded {len(self.api_cache)} cached API responses")
            else:
                self.api_cache = {}
                logger.debug("No API cache found, starting fresh")
        except Exception as e:
            logger.debug(f"No API cache found: {e}")
            self.api_cache = {}
    
    def save_api_cache(self):
        """Save API responses to cache"""
        try:
            Path(self.cache_file).parent.mkdir(exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.api_cache, f, indent=2)
            logger.debug("💾 API cache saved")
        except Exception as e:
            logger.error(f"Failed to save API cache: {e}")
    
    def rate_limit_api(self):
        """Ensure we don't exceed API rate limits"""
        current_time = time.time()
        time_since_last = current_time - self.last_api_call
        if time_since_last < self.api_delay:
            sleep_time = self.api_delay - time_since_last
            logger.debug(f"⏱️ Rate limiting: sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
        self.last_api_call = time.time()
    
    def extract_keywords_from_banner(self, banner, service):
        """Extract relevant keywords from banner for API search"""
        if not banner or banner == "N/A":
            return []
        
        keywords = []
        banner_lower = banner.lower()
        
        # Common software keywords to look for
        software_keywords = [
            'apache', 'nginx', 'iis', 'tomcat', 'jetty', 'lighttpd',
            'openssh', 'openssl', 'mysql', 'postgresql', 'mariadb',
            'redis', 'mongodb', 'elasticsearch', 'jenkins', 'git',
            'wordpress', 'drupal', 'joomla', 'confluence', 'sharepoint',
            'exchange', 'postfix', 'sendmail', 'dovecot', 'vsftpd',
            'proftpd', 'pureftpd', 'bind', 'unbound', 'dnsmasq'
        ]
        
        # Extract version numbers
        version_pattern = r'(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)'
        versions = re.findall(version_pattern, banner)
        
        # Find software names in banner
        found_software = []
        for keyword in software_keywords:
            if keyword in banner_lower:
                keywords.append(keyword)
                found_software.append(keyword)
        
        # Add versions with software names
        for software in found_software[:2]:  # Limit to 2 software items
            for version in versions[:2]:  # Limit to 2 versions
                keywords.append(f"{software} {version}")
        
        # Add service type
        keywords.append(service)
        
        # Add raw versions
        keywords.extend(versions[:2])
        
        return list(set(keywords))[:5]  # Remove duplicates and limit to 5
    
    def search_nvd_api(self, keywords, service):
        """Search NIST NVD API for CVEs"""
        if not keywords:
            return []
        
        # Create cache key
        cache_key = hashlib.md5(f"{service}:{':'.join(sorted(keywords))}".encode()).hexdigest()
        
        # Check cache first
        if cache_key in self.api_cache:
            logger.debug(f"💨 Using cached result for {keywords[:2]}")
            return self.api_cache[cache_key]
        
        try:
            # Rate limiting
            self.rate_limit_api()
            
            # Build search query - use most specific keywords
            primary_keywords = [k for k in keywords if len(k) > 3][:3]
            if not primary_keywords:
                primary_keywords = keywords[:2]
            
            keyword_query = " ".join(primary_keywords)
            
            params = {
                "keywordSearch": keyword_query,
                "resultsPerPage": 8,  # Limit results for performance
                "startIndex": 0
            }
            
            logger.info(f"🔍 Searching NVD API: {keyword_query}")
            response = requests.get(
                self.nvd_api_url, 
                params=params, 
                timeout=self.api_timeout,
                headers={'User-Agent': 'Security-Scanner/2.0'}
            )
            
            if response.status_code == 200:
                data = response.json()
                cves = self.parse_nvd_response(data, service, keywords)
                
                # Cache the result
                self.api_cache[cache_key] = cves
                self.save_api_cache()
                
                logger.info(f"✅ Found {len(cves)} relevant CVEs from API")
                return cves
            else:
                logger.warning(f"⚠️ NVD API returned status {response.status_code}")
                return []
                
        except requests.exceptions.Timeout:
            logger.warning("⏰ NVD API request timed out")
            return []
        except requests.exceptions.RequestException as e:
            logger.warning(f"🌐 NVD API request failed: {e}")
            return []
        except Exception as e:
            logger.error(f"❌ NVD API search failed: {e}")
            return []
    
    def parse_nvd_response(self, nvd_data, service, keywords):
        """Parse NVD API response into our format"""
        cves = []
        
        try:
            vulnerabilities = nvd_data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities[:6]:  # Limit to top 6 results
                cve_item = vuln.get('cve', {})
                cve_id = cve_item.get('id', 'Unknown')
                
                # Get description
                descriptions = cve_item.get('descriptions', [])
                description = "No description available"
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        # Truncate long descriptions
                        if len(description) > 150:
                            description = description[:150] + "..."
                        break
                
                # Get CVSS score and severity
                metrics = vuln.get('cve', {}).get('metrics', {})
                cvss_score = 0.0
                severity = "Unknown"
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'Unknown')
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'Unknown')
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    # Convert CVSS v2 score to severity
                    if cvss_score >= 7.0:
                        severity = "High"
                    elif cvss_score >= 4.0:
                        severity = "Medium"
                    else:
                        severity = "Low"
                
                # Check relevance - description should contain at least one keyword
                desc_lower = description.lower()
                relevant = any(
                    keyword.lower() in desc_lower 
                    for keyword in keywords 
                    if len(keyword) > 2
                )
                
                if relevant and cvss_score > 0:
                    cve_entry = {
                        "cve_id": cve_id,
                        "description": description,
                        "severity": severity.title() if severity != "Unknown" else "Medium",
                        "cvss_score": cvss_score,
                        "source": "NVD_API",
                        "match_reason": "api_search"
                    }
                    cves.append(cve_entry)
            
        except Exception as e:
            logger.error(f"Error parsing NVD response: {e}")
        
        return cves
    
    def check_service(self, service, banner):
        """Main CVE checking method - chooses local vs enhanced based on initialization"""
        if self.use_api:
            return self.check_service_enhanced(service, banner)
        else:
            return self.check_local_database(service, banner)
    
    def check_service_enhanced(self, service, banner):
        """Enhanced CVE checking with API integration"""
        all_cves = []
        
        # 1. Always check local database first (fast)
        local_cves = self.check_local_database(service, banner)
        all_cves.extend(local_cves)
        
        # 2. Enhance with API if enabled and we have useful banner data
        if self.use_api and banner and banner != "N/A" and len(banner) > 5:
            keywords = self.extract_keywords_from_banner(banner, service)
            
            if keywords:
                api_cves = self.search_nvd_api(keywords, service)
                
                # Deduplicate CVEs by ID
                existing_cve_ids = {cve['cve_id'] for cve in all_cves}
                for cve in api_cves:
                    if cve['cve_id'] not in existing_cve_ids:
                        all_cves.append(cve)
        
        return all_cves
    
    def check_local_database(self, service, banner):
        """Check local CVE database (original functionality)"""
        if not banner or banner == "N/A":
            return []
        
        matched_cves = []
        banner_lower = banner.lower()
        
        for cve_entry in self.local_database:
            # Check service match
            if cve_entry.get("service", "").lower() != service.lower():
                continue
            
            # Check banner keywords
            banner_match = any(
                keyword.lower() in banner_lower 
                for keyword in cve_entry.get("banner_contains", [])
            )
            
            # Check version patterns
            version_match = False
            for pattern in cve_entry.get("version_patterns", []):
                try:
                    if re.search(pattern.lower(), banner_lower):
                        version_match = True
                        break
                except re.error:
                    logger.debug(f"Invalid regex pattern: {pattern}")
            
            if banner_match or version_match:
                matched_cve = {
                    "cve_id": cve_entry["cve_id"],
                    "description": cve_entry["description"],
                    "severity": cve_entry.get("severity", "Unknown"),
                    "cvss_score": cve_entry.get("cvss_score", 0.0),
                    "source": "Local_DB",
                    "match_reason": "banner_match" if banner_match else "version_match"
                }
                matched_cves.append(matched_cve)
        
        return matched_cves
    
    def get_severity_color(self, severity):
        """Get color code for severity level"""
        severity_colors = {
            "Critical": "#dc3545",  # Red
            "High": "#fd7e14",      # Orange  
            "Medium": "#ffc107",    # Yellow
            "Low": "#28a745",       # Green
            "Unknown": "#6c757d"    # Gray
        }
        return severity_colors.get(severity, "#6c757d")
    
    def get_severity_emoji(self, severity):
        """Get emoji for severity level"""
        severity_emojis = {
            "Critical": "🔴",
            "High": "🟠", 
            "Medium": "🟡",
            "Low": "🟢",
            "Unknown": "⚪"
        }
        return severity_emojis.get(severity, "⚪")
    
    def get_statistics(self, scan_results):
        """Get CVE statistics from scan results"""
        stats = {
            "total_cves": 0,
            "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0},
            "unique_cves": set(),
            "affected_hosts": 0
        }
        
        for host in scan_results:
            host_has_cves = False
            for service in host.get("services", []):
                cves = service.get("cves", [])
                if cves:
                    host_has_cves = True
                    for cve in cves:
                        stats["total_cves"] += 1
                        severity = cve.get("severity", "Unknown")
                        stats["by_severity"][severity] += 1
                        stats["unique_cves"].add(cve["cve_id"])
            
            if host_has_cves:
                stats["affected_hosts"] += 1
        
        stats["unique_cves"] = len(stats["unique_cves"])
        return stats
