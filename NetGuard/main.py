#!/usr/bin/env python3
"""
Network Scanner - Main Entry Point
Professional cybersecurity scanning tool with CVE detection and historical tracking
"""

import argparse
import sys
import time
from pathlib import Path
from scanner import NetworkScanner
from cve_checker import EnhancedCVEChecker
from report import ReportGenerator
from database import ScanDatabase
from notifications import EmailNotifier
from utils import setup_logging, validate_ip_range, create_directory_structure, check_dependencies

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced Network Scanner with CVE Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --range 192.168.1.0/24 --mode fast
  python3 main.py --range 10.0.0.1-50 --mode full --output custom_report
  python3 main.py --target 192.168.1.100 --ports 80,443,22 --verbose
  python3 main.py --range 192.168.1.0/24 --mode fast --use-api --os-detect --weak-config
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--range", "-r", 
                             help="IP range (CIDR: 192.168.1.0/24 or range: 192.168.1.1-50)")
    target_group.add_argument("--target", "-t", 
                             help="Single target IP")
    
    # Scan options
    parser.add_argument("--mode", "-m", 
                       choices=["fast", "full", "custom"], 
                       default="fast",
                       help="Scan mode: fast (common ports), full (1-1024), custom (specify ports)")
    
    parser.add_argument("--ports", "-p", 
                       help="Custom ports (comma-separated: 80,443,22 or range: 1-1000)")
    
    parser.add_argument("--threads", "-T", 
                       type=int, default=100,
                       help="Number of threads (default: 100)")
    
    # Output options
    parser.add_argument("--output", "-o", 
                       default="network_scan_report",
                       help="Output filename prefix (default: network_scan_report)")
    
    parser.add_argument("--format", "-f",
                       choices=["html", "json", "csv", "all"],
                       default="html",
                       help="Output format(s)")
    
    # Advanced options
    parser.add_argument("--timeout", 
                       type=int, default=2,
                       help="Connection timeout in seconds (default: 2)")
    
    parser.add_argument("--verbose", "-v", 
                       action="store_true",
                       help="Enable verbose output")
    
    parser.add_argument("--os-detect", 
                       action="store_true",
                       help="Enable OS detection")
    
    parser.add_argument("--weak-config", 
                       action="store_true",
                       help="Test for weak configurations")
    
    # CVE API options
    api_group = parser.add_mutually_exclusive_group()
    api_group.add_argument("--use-api", 
                          action="store_true",
                          help="Enable live CVE API lookups (slower but comprehensive)")
    api_group.add_argument("--no-api", 
                          action="store_true", 
                          help="Use only local CVE database (faster)")
    
    # Database options
    parser.add_argument("--no-db", 
                       action="store_true",
                       help="Skip storing results in database")
    
    return parser.parse_args()

def main():
    print("🛡️ NetGuard - Enterprise Network Security Scanner v2.0")
    print("=" * 40)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Create directory structure
    create_directory_structure()
    
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(verbose=args.verbose)
    
    # Validate inputs
    if args.range and not validate_ip_range(args.range):
        logger.error("Invalid IP range format")
        sys.exit(1)
    
    # Determine target(s)
    targets = []
    if args.target:
        targets = [args.target]
    elif args.range:
        # Handle CIDR or range format
        targets = args.range
    
    # Determine ports
    if args.mode == "fast":
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3389, 5432, 3306]
    elif args.mode == "full":
        ports = list(range(1, 1025))
    elif args.mode == "custom" and args.ports:
        if "-" in args.ports:
            start, end = map(int, args.ports.split("-"))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in args.ports.split(",")]
    else:
        logger.error("Custom mode requires --ports argument")
        sys.exit(1)
    
    # Determine CVE API mode
    use_api = True  # Default: Smart mode (local + API)
    if args.no_api:
        use_api = False
        logger.info("🗂️ CVE Mode: Local database only")
    elif args.use_api:
        use_api = True
        logger.info("🌐 CVE Mode: API-enhanced detection")
    else:
        use_api = True
        logger.info("🧠 CVE Mode: Smart mode (local + API)")
    
    logger.info(f"Starting scan on {len(ports)} ports with {args.threads} threads")
    
    # Initialize components
    scanner = NetworkScanner(
        max_threads=args.threads,
        timeout=args.timeout,
        os_detection=args.os_detect,
        weak_config_tests=args.weak_config
    )
    
    cve_checker = EnhancedCVEChecker("data/cves.json", use_api=use_api)
    report_generator = ReportGenerator()
    
    # Initialize database (unless disabled)
    database = None
    if not args.no_db:
        try:
            database = ScanDatabase()
            logger.info("📄 Database initialized for historical tracking")
        except Exception as e:
            logger.warning(f"Database initialization failed: {e}")
            logger.warning("Continuing without database tracking")
    
    # Initialize email notifier
    email_notifier = None
    try:
        email_notifier = EmailNotifier()
        if email_notifier.config.get("enabled"):
            logger.info("📧 Email notifications enabled")
        else:
            logger.info("📧 Email notifications disabled")
    except Exception as e:
        logger.warning(f"Email notifier initialization failed: {e}")
        logger.warning("Continuing without email notifications")
    
    # Run scan
    logger.info("🚀 Scan started...")
    start_time = time.time()
    results = scanner.scan_network(targets, ports, cve_checker)
    scan_duration = time.time() - start_time
    
    # Store results in database
    scan_id = None
    if database and results:
        try:
            # Build scan options string for database
            scan_options_parts = []
            if args.mode:
                scan_options_parts.append(f"--mode {args.mode}")
            if args.os_detect:
                scan_options_parts.append("--os-detect")
            if args.weak_config:
                scan_options_parts.append("--weak-config")
            if args.use_api:
                scan_options_parts.append("--use-api")
            elif args.no_api:
                scan_options_parts.append("--no-api")
            
            scan_options = " ".join(scan_options_parts)
            target_str = args.target if args.target else args.range
            
            scan_id = database.store_scan_results(results, target_str, scan_options, scan_duration)
            
            if scan_id:
                logger.info(f"Scan results stored in database (ID: {scan_id})")
                
                # Check for changes since last scan
                changes = database.get_recent_changes(days_back=1)
                if changes:
                    logger.info(f"Detected {len(changes)} changes since last scan:")
                    for change in changes[:5]:  # Show first 5 changes
                        logger.info(f"  • {change['change_description']}")
                    if len(changes) > 5:
                        logger.info(f"  • ... and {len(changes) - 5} more changes")
                    
                    # Send change notification email
                    if email_notifier and email_notifier.config.get("enabled"):
                        try:
                            email_notifier.send_change_notification(changes, target_str)
                            logger.info("Change notification email sent")
                        except Exception as e:
                            logger.error(f"Failed to send change notification: {e}")
                else:
                    logger.info("No significant changes detected since last scan")
            
        except Exception as e:
            logger.error(f"Failed to store results in database: {e}")
            
            # Send scan failure notification
            if email_notifier and email_notifier.config.get("enabled"):
                try:
                    target_str = args.target if args.target else args.range
                    email_notifier.send_scan_failure_notification(str(e), target_str)
                    logger.info("Scan failure notification email sent")
                except Exception as email_error:
                    logger.error(f"Failed to send failure notification: {email_error}")
    
    # Check for critical CVEs and send immediate alerts
    if email_notifier and email_notifier.config.get("enabled") and results:
        try:
            for host in results:
                for service in host.get('services', []):
                    for cve in service.get('cves', []):
                        if cve.get('severity', '').lower() == 'critical':
                            email_notifier.send_critical_cve_alert(cve, host['ip'], service)
                            logger.info(f"Critical CVE alert sent for {cve['cve_id']} on {host['ip']}")
        except Exception as e:
            logger.error(f"Failed to send critical CVE alerts: {e}")
    
    # Generate reports
    logger.info("Generating reports...")
    if args.format in ["html", "all"]:
        report_generator.generate_html(results, f"{args.output}.html")
    
    if args.format in ["json", "all"]:
        report_generator.generate_json(results, f"{args.output}.json")
    
    if args.format in ["csv", "all"]:
        report_generator.generate_csv(results, f"{args.output}.csv")
    
    # Send scan completion notification
    if email_notifier and email_notifier.config.get("enabled") and results:
        try:
            target_str = args.target if args.target else args.range
            email_notifier.send_scan_complete_notification(results, scan_duration, target_str)
            logger.info("Scan completion notification email sent")
        except Exception as e:
            logger.error(f"Failed to send completion notification: {e}")
    
    # Summary
    total_hosts = len(results)
    total_open_ports = sum(len(host.get("services", [])) for host in results)
    total_cves = sum(
        len(service.get("cves", []))
        for host in results
        for service in host.get("services", [])
    )
    
    print(f"\n✅ Scan completed in {scan_duration:.1f} seconds!")
    print(f"📊 Summary: {total_hosts} hosts, {total_open_ports} open ports, {total_cves} CVEs")
    print(f"📄 Reports saved with prefix: {args.output}")
    
    if database and scan_id:
        print(f"📊 Results stored in database (scan ID: {scan_id})")
    
    # Show recent vulnerability trends if database available
    if database and not args.no_db:
        try:
            trends = database.get_vulnerability_trends(target_str, days_back=30)
            if len(trends) > 1:
                latest = trends[-1]
                previous = trends[-2]
                
                cve_change = latest['total_cve_instances'] - previous['total_cve_instances']
                if cve_change > 0:
                    print(f"📈 Security trend: +{cve_change} vulnerabilities since last scan")
                elif cve_change < 0:
                    print(f"📉 Security trend: {cve_change} vulnerabilities fixed since last scan")
                else:
                    print(f"📊 Security trend: No change in vulnerability count")
        except Exception as e:
            logger.debug(f"Could not generate trend analysis: {e}")

if __name__ == "__main__":
    main()
