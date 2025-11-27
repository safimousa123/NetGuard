#!/usr/bin/env python3
"""
Database Module for Network Scanner
Handles historical scan data storage and change detection using SQLite
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)

class ScanDatabase:
    def __init__(self, db_path="data/scan_history.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        
        # Initialize database
        self.init_database()
        logger.info(f"Database initialized: {self.db_path}")
    
    def init_database(self):
        """Create database tables if they don't exist"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Scans table - stores metadata about each scan
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TEXT NOT NULL,
                    network_range TEXT NOT NULL,
                    scan_type TEXT,
                    total_hosts INTEGER DEFAULT 0,
                    total_ports INTEGER DEFAULT 0,
                    total_cves INTEGER DEFAULT 0,
                    scan_duration REAL DEFAULT 0.0,
                    scanner_options TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Hosts table - stores discovered hosts for each scan
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    ip_address TEXT NOT NULL,
                    hostname TEXT,
                    os_detected TEXT,
                    os_confidence INTEGER DEFAULT 0,
                    ports_count INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            ''')
            
            # Services table - stores discovered services/ports
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    scan_id INTEGER,
                    port_number INTEGER NOT NULL,
                    service_name TEXT,
                    service_banner TEXT,
                    service_version TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    status TEXT DEFAULT 'open',
                    FOREIGN KEY (host_id) REFERENCES hosts (id),
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            ''')
            
            # CVEs table - stores vulnerability data
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_id INTEGER,
                    scan_id INTEGER,
                    cve_id TEXT NOT NULL,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL DEFAULT 0.0,
                    source TEXT,
                    first_detected TEXT,
                    last_detected TEXT,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (service_id) REFERENCES services (id),
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            ''')
            
            # Changes table - tracks what changed between scans
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    change_type TEXT NOT NULL,
                    ip_address TEXT,
                    port_number INTEGER,
                    cve_id TEXT,
                    change_description TEXT,
                    severity_level TEXT,
                    change_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            ''')
            
            # Create indices for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_services_port ON services(port_number)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_id ON cves(cve_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_changes_type ON changes(change_type)')
            
            conn.commit()
            logger.debug("Database tables created/verified")
    
    def store_scan_results(self, scan_results, network_range, scan_options="", scan_duration=0.0):
        """Store complete scan results in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Calculate summary statistics
                total_hosts = len(scan_results)
                total_ports = sum(len(host.get('services', [])) for host in scan_results)
                total_cves = sum(
                    len(service.get('cves', []))
                    for host in scan_results
                    for service in host.get('services', [])
                )
                
                # Insert scan record
                scan_date = datetime.now().isoformat()
                cursor.execute('''
                    INSERT INTO scans (scan_date, network_range, total_hosts, total_ports, 
                                     total_cves, scan_duration, scanner_options)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (scan_date, network_range, total_hosts, total_ports, total_cves, 
                     scan_duration, scan_options))
                
                scan_id = cursor.lastrowid
                
                # Store host and service data
                for host_data in scan_results:
                    host_id = self._store_host(cursor, scan_id, host_data, scan_date)
                    
                    for service_data in host_data.get('services', []):
                        service_id = self._store_service(cursor, host_id, scan_id, service_data, scan_date)
                        
                        for cve_data in service_data.get('cves', []):
                            self._store_cve(cursor, service_id, scan_id, cve_data, scan_date)
                
                conn.commit()
                logger.info(f"Stored scan results: {total_hosts} hosts, {total_ports} ports, {total_cves} CVEs")
                
                # Detect changes compared to previous scan
                changes = self.detect_changes(scan_id, network_range)
                if changes:
                    self._store_changes(cursor, scan_id, changes)
                    conn.commit()
                
                return scan_id
                
        except Exception as e:
            logger.error(f"Error storing scan results: {e}")
            return None
    
    def _store_host(self, cursor, scan_id, host_data, scan_date):
        """Store host data and return host_id"""
        ip_address = host_data['ip']
        os_detected = host_data.get('os', 'Unknown')
        ports_count = len(host_data.get('services', []))
        
        # Check if host exists
        cursor.execute('SELECT id FROM hosts WHERE ip_address = ?', (ip_address,))
        existing_host = cursor.fetchone()
        
        if existing_host:
            host_id = existing_host[0]
            # Update last seen
            cursor.execute('''
                UPDATE hosts SET last_seen = ?, ports_count = ?, os_detected = ?
                WHERE id = ?
            ''', (scan_date, ports_count, os_detected, host_id))
        else:
            # Insert new host
            cursor.execute('''
                INSERT INTO hosts (scan_id, ip_address, os_detected, ports_count, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (scan_id, ip_address, os_detected, ports_count, scan_date, scan_date))
            host_id = cursor.lastrowid
        
        return host_id
    
    def _store_service(self, cursor, host_id, scan_id, service_data, scan_date):
        """Store service data and return service_id"""
        port_number = service_data['port']
        service_name = service_data.get('service', 'unknown')
        service_banner = service_data.get('banner', '')
        
        # Get host IP for lookup
        cursor.execute('SELECT ip_address FROM hosts WHERE id = ?', (host_id,))
        ip_address = cursor.fetchone()[0]
        
        # Check if service exists
        cursor.execute('''
            SELECT s.id FROM services s 
            JOIN hosts h ON s.host_id = h.id 
            WHERE h.ip_address = ? AND s.port_number = ?
        ''', (ip_address, port_number))
        existing_service = cursor.fetchone()
        
        if existing_service:
            service_id = existing_service[0]
            # Update last seen and banner
            cursor.execute('''
                UPDATE services SET last_seen = ?, service_banner = ?, service_name = ?
                WHERE id = ?
            ''', (scan_date, service_banner, service_name, service_id))
        else:
            # Insert new service
            cursor.execute('''
                INSERT INTO services (host_id, scan_id, port_number, service_name, 
                                    service_banner, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (host_id, scan_id, port_number, service_name, service_banner, scan_date, scan_date))
            service_id = cursor.lastrowid
        
        return service_id
    
    def _store_cve(self, cursor, service_id, scan_id, cve_data, scan_date):
        """Store CVE data"""
        cve_id = cve_data['cve_id']
        description = cve_data.get('description', '')
        severity = cve_data.get('severity', 'Unknown')
        cvss_score = cve_data.get('cvss_score', 0.0)
        source = cve_data.get('source', 'Unknown')
        
        # Check if CVE exists for this service
        cursor.execute('''
            SELECT id FROM cves WHERE service_id = ? AND cve_id = ?
        ''', (service_id, cve_id))
        existing_cve = cursor.fetchone()
        
        if existing_cve:
            # Update last detected
            cursor.execute('''
                UPDATE cves SET last_detected = ?, status = 'active'
                WHERE id = ?
            ''', (scan_date, existing_cve[0]))
        else:
            # Insert new CVE
            cursor.execute('''
                INSERT INTO cves (service_id, scan_id, cve_id, description, severity, 
                                cvss_score, source, first_detected, last_detected)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (service_id, scan_id, cve_id, description, severity, cvss_score, 
                 source, scan_date, scan_date))
    
    def detect_changes(self, current_scan_id, network_range):
        """Detect changes compared to previous scan of same network"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get previous scan for same network
                cursor.execute('''
                    SELECT id FROM scans 
                    WHERE network_range = ? AND id < ? 
                    ORDER BY scan_date DESC LIMIT 1
                ''', (network_range, current_scan_id))
                
                previous_scan = cursor.fetchone()
                if not previous_scan:
                    logger.info("No previous scan found for comparison")
                    return []
                
                previous_scan_id = previous_scan[0]
                changes = []
                
                # Detect new hosts
                cursor.execute('''
                    SELECT DISTINCT h.ip_address FROM hosts h
                    WHERE h.scan_id = ? AND h.ip_address NOT IN (
                        SELECT DISTINCT h2.ip_address FROM hosts h2 WHERE h2.scan_id = ?
                    )
                ''', (current_scan_id, previous_scan_id))
                
                for (ip,) in cursor.fetchall():
                    changes.append({
                        'type': 'new_host',
                        'ip_address': ip,
                        'description': f'New host discovered: {ip}',
                        'severity': 'Medium'
                    })
                
                # Detect disappeared hosts
                cursor.execute('''
                    SELECT DISTINCT h.ip_address FROM hosts h
                    WHERE h.scan_id = ? AND h.ip_address NOT IN (
                        SELECT DISTINCT h2.ip_address FROM hosts h2 WHERE h2.scan_id = ?
                    )
                ''', (previous_scan_id, current_scan_id))
                
                for (ip,) in cursor.fetchall():
                    changes.append({
                        'type': 'host_disappeared',
                        'ip_address': ip,
                        'description': f'Host no longer responding: {ip}',
                        'severity': 'Low'
                    })
                
                # Detect new services
                cursor.execute('''
                    SELECT DISTINCT h.ip_address, s.port_number, s.service_name FROM services s
                    JOIN hosts h ON s.host_id = h.id
                    WHERE s.scan_id = ? AND NOT EXISTS (
                        SELECT 1 FROM services s2 
                        JOIN hosts h2 ON s2.host_id = h2.id
                        WHERE s2.scan_id = ? AND h2.ip_address = h.ip_address AND s2.port_number = s.port_number
                    )
                ''', (current_scan_id, previous_scan_id))
                
                for ip, port, service in cursor.fetchall():
                    changes.append({
                        'type': 'new_service',
                        'ip_address': ip,
                        'port_number': port,
                        'description': f'New service: {ip}:{port} ({service})',
                        'severity': 'Medium'
                    })
                
                # Detect new CVEs
                cursor.execute('''
                    SELECT DISTINCT h.ip_address, s.port_number, c.cve_id, c.severity FROM cves c
                    JOIN services s ON c.service_id = s.id
                    JOIN hosts h ON s.host_id = h.id
                    WHERE c.scan_id = ? AND NOT EXISTS (
                        SELECT 1 FROM cves c2
                        JOIN services s2 ON c2.service_id = s2.id  
                        JOIN hosts h2 ON s2.host_id = h2.id
                        WHERE c2.scan_id = ? AND h2.ip_address = h.ip_address 
                        AND s2.port_number = s.port_number AND c2.cve_id = c.cve_id
                    )
                ''', (current_scan_id, previous_scan_id))
                
                for ip, port, cve_id, severity in cursor.fetchall():
                    changes.append({
                        'type': 'new_cve',
                        'ip_address': ip,
                        'port_number': port,
                        'cve_id': cve_id,
                        'description': f'New vulnerability: {cve_id} on {ip}:{port}',
                        'severity': severity
                    })
                
                logger.info(f"Detected {len(changes)} changes since previous scan")
                return changes
                
        except Exception as e:
            logger.error(f"Error detecting changes: {e}")
            return []
    
    def _store_changes(self, cursor, scan_id, changes):
        """Store detected changes"""
        for change in changes:
            cursor.execute('''
                INSERT INTO changes (scan_id, change_type, ip_address, port_number, 
                                   cve_id, change_description, severity_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (scan_id, change['type'], change.get('ip_address'),
                 change.get('port_number'), change.get('cve_id'),
                 change['description'], change['severity']))
    
    def get_scan_history(self, network_range=None, days_back=30):
        """Get scan history for analysis"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
                
                query = '''
                    SELECT id, scan_date, network_range, total_hosts, total_ports, 
                           total_cves, scan_duration
                    FROM scans 
                    WHERE scan_date >= ?
                '''
                params = [since_date]
                
                if network_range:
                    query += ' AND network_range = ?'
                    params.append(network_range)
                
                query += ' ORDER BY scan_date DESC'
                
                cursor.execute(query, params)
                columns = [desc[0] for desc in cursor.description]
                
                scans = []
                for row in cursor.fetchall():
                    scan_data = dict(zip(columns, row))
                    scans.append(scan_data)
                
                return scans
                
        except Exception as e:
            logger.error(f"Error getting scan history: {e}")
            return []
    
    def get_recent_changes(self, days_back=7):
        """Get recent changes for reporting"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
                
                cursor.execute('''
                    SELECT change_type, ip_address, port_number, cve_id,
                           change_description, severity_level, change_date
                    FROM changes 
                    WHERE change_date >= ?
                    ORDER BY change_date DESC
                ''', (since_date,))
                
                columns = [desc[0] for desc in cursor.description]
                changes = []
                for row in cursor.fetchall():
                    change_data = dict(zip(columns, row))
                    changes.append(change_data)
                
                return changes
                
        except Exception as e:
            logger.error(f"Error getting recent changes: {e}")
            return []
    
    def get_vulnerability_trends(self, network_range=None, days_back=30):
        """Get vulnerability trends over time"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
                
                query = '''
                    SELECT s.scan_date, COUNT(DISTINCT c.cve_id) as unique_cves,
                           COUNT(c.id) as total_cve_instances,
                           SUM(CASE WHEN c.severity = 'Critical' THEN 1 ELSE 0 END) as critical,
                           SUM(CASE WHEN c.severity = 'High' THEN 1 ELSE 0 END) as high,
                           SUM(CASE WHEN c.severity = 'Medium' THEN 1 ELSE 0 END) as medium,
                           SUM(CASE WHEN c.severity = 'Low' THEN 1 ELSE 0 END) as low
                    FROM scans s
                    LEFT JOIN cves c ON s.id = c.scan_id
                    WHERE s.scan_date >= ?
                '''
                
                params = [since_date]
                
                if network_range:
                    query += ' AND s.network_range = ?'
                    params.append(network_range)
                
                query += '''
                    GROUP BY s.scan_date
                    ORDER BY s.scan_date
                '''
                
                cursor.execute(query, params)
                columns = [desc[0] for desc in cursor.description]
                
                trends = []
                for row in cursor.fetchall():
                    trend_data = dict(zip(columns, row))
                    trends.append(trend_data)
                
                return trends
                
        except Exception as e:
            logger.error(f"Error getting vulnerability trends: {e}")
            return []
    
    def cleanup_old_data(self, keep_days=90):
        """Clean up old scan data to prevent database bloat"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cutoff_date = (datetime.now() - timedelta(days=keep_days)).isoformat()
                
                # Get old scan IDs
                cursor.execute('SELECT id FROM scans WHERE scan_date < ?', (cutoff_date,))
                old_scan_ids = [row[0] for row in cursor.fetchall()]
                
                if not old_scan_ids:
                    logger.info("No old data to clean up")
                    return 0
                
                # Delete related data
                placeholders = ','.join('?' * len(old_scan_ids))
                
                cursor.execute(f'DELETE FROM changes WHERE scan_id IN ({placeholders})', old_scan_ids)
                cursor.execute(f'DELETE FROM cves WHERE scan_id IN ({placeholders})', old_scan_ids)
                cursor.execute(f'DELETE FROM services WHERE scan_id IN ({placeholders})', old_scan_ids)
                cursor.execute(f'DELETE FROM hosts WHERE scan_id IN ({placeholders})', old_scan_ids)
                cursor.execute(f'DELETE FROM scans WHERE id IN ({placeholders})', old_scan_ids)
                
                deleted_scans = len(old_scan_ids)
                conn.commit()
                
                # Vacuum database to reclaim space
                cursor.execute('VACUUM')
                
                logger.info(f"Cleaned up {deleted_scans} old scans")
                return deleted_scans
                
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
            return 0
