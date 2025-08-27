#!/usr/bin/env python3
"""
Vulnerability Database Updater for Mous Scanner
Author: SayerLinux
"""

import sqlite3
import requests
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path


class VulnDBUpdater:
    """Handle vulnerability database updates from external sources"""
    
    def __init__(self, db_path: str = "data/vulnerabilities/mous.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger('mous.updater')
        
    def update(self):
        """Update vulnerability database from all sources"""
        self.logger.info("Starting vulnerability database update...")
        
        try:
            # Initialize database if not exists
            self._init_database()
            
            # Update from NIST NVD
            self._update_from_nvd()
            
            # Update from ExploitDB
            self._update_from_exploitdb()
            
            # Update from Metasploit
            self._update_from_metasploit()
            
            # Update local signatures
            self._update_signatures()
            
            self.logger.info("Database update completed successfully")
            
        except Exception as e:
            self.logger.error(f"Database update failed: {str(e)}")
            raise
    
    def _init_database(self):
        """Initialize vulnerability database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # CVE table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published_date TEXT,
                last_modified TEXT,
                references TEXT,
                vulnerable_versions TEXT,
                patched_versions TEXT
            )
        ''')
        
        # Exploits table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                title TEXT,
                description TEXT,
                exploit_type TEXT,
                platform TEXT,
                author TEXT,
                date TEXT,
                url TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves (id)
            )
        ''')
        
        # Signatures table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                type TEXT,
                pattern TEXT,
                description TEXT,
                severity TEXT,
                remediation TEXT,
                created_date TEXT,
                last_updated TEXT
            )
        ''')
        
        # Update log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS update_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                items_added INTEGER,
                update_date TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _update_from_nvd(self):
        """Update CVE data from NIST NVD"""
        self.logger.info("Updating from NIST NVD...")
        
        # NVD API endpoint
        api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        
        try:
            # Get recent CVEs (last 30 days)
            params = {
                'resultsPerPage': 2000,
                'startIndex': 0,
                'pubStartDate': (datetime.now().replace(day=1) - timedelta(days=30)).strftime('%Y-%m-%dT00:00:00:000 UTC')
            }
            
            response = requests.get(api_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = data.get('result', {}).get('CVE_Items', [])
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            added_count = 0
            for cve_item in cves:
                cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                if not cve_id:
                    continue
                
                description = cve_item.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', '')
                
                # CVSS score
                impact = cve_item.get('impact', {})
                cvss_score = None
                severity = 'Unknown'
                
                if 'baseMetricV3' in impact:
                    cvss_score = impact['baseMetricV3']['cvssV3']['baseScore']
                    severity = impact['baseMetricV3']['cvssV3']['baseSeverity']
                elif 'baseMetricV2' in impact:
                    cvss_score = impact['baseMetricV2']['cvssV2']['baseScore']
                    severity = impact['baseMetricV2']['severity']
                
                # References
                references = []
                for ref in cve_item.get('cve', {}).get('references', {}).get('reference_data', []):
                    references.append(ref.get('url', ''))
                
                # Insert or update CVE
                cursor.execute('''
                    INSERT OR REPLACE INTO cves 
                    (id, description, severity, cvss_score, published_date, last_modified, references)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id,
                    description,
                    severity,
                    cvss_score,
                    cve_item.get('publishedDate'),
                    cve_item.get('lastModifiedDate'),
                    json.dumps(references)
                ))
                
                added_count += 1
            
            # Log update
            cursor.execute('''
                INSERT INTO update_log (source, items_added, update_date)
                VALUES (?, ?, ?)
            ''', ('NIST NVD', added_count, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Added {added_count} CVEs from NIST NVD")
            
        except Exception as e:
            self.logger.error(f"Failed to update from NIST NVD: {str(e)}")
    
    def _update_from_exploitdb(self):
        """Update exploit data from ExploitDB"""
        self.logger.info("Updating from ExploitDB...")
        
        try:
            # ExploitDB GitHub repository
            github_url = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
            
            response = requests.get(github_url, timeout=30)
            response.raise_for_status()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Parse CSV data
            import csv
            from io import StringIO
            
            csv_data = StringIO(response.text)
            reader = csv.DictReader(csv_data)
            
            added_count = 0
            for row in reader:
                if row.get('codes', '').startswith('CVE-'):
                    cve_id = row['codes']
                    title = row.get('description', '')
                    platform = row.get('platform', '')
                    exploit_type = row.get('type', '')
                    date = row.get('date', '')
                    url = f"https://www.exploit-db.com/exploits/{row.get('id', '')}"
                    
                    cursor.execute('''
                        INSERT INTO exploits 
                        (cve_id, title, description, exploit_type, platform, date, url)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve_id,
                        title,
                        title,  # Using title as description
                        exploit_type,
                        platform,
                        date,
                        url
                    ))
                    
                    added_count += 1
            
            # Log update
            cursor.execute('''
                INSERT INTO update_log (source, items_added, update_date)
                VALUES (?, ?, ?)
            ''', ('ExploitDB', added_count, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Added {added_count} exploits from ExploitDB")
            
        except Exception as e:
            self.logger.error(f"Failed to update from ExploitDB: {str(e)}")
    
    def _update_from_metasploit(self):
        """Update exploit data from Metasploit"""
        self.logger.info("Updating from Metasploit...")
        
        try:
            # Metasploit modules GitHub repository
            github_url = "https://api.github.com/repos/rapid7/metasploit-framework/contents/modules"
            
            response = requests.get(github_url, timeout=30)
            response.raise_for_status()
            
            # This is a simplified version - in reality, you'd parse module metadata
            self.logger.info("Metasploit update completed (simplified)")
            
        except Exception as e:
            self.logger.error(f"Failed to update from Metasploit: {str(e)}")
    
    def _update_signatures(self):
        """Update local vulnerability signatures"""
        self.logger.info("Updating local signatures...")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Add default signatures if they don't exist
        default_signatures = [
            {
                'name': 'SQL Injection Error',
                'type': 'sql_injection',
                'pattern': r'(?i)(mysql_fetch_array|mysql_num_rows|ORA-\d+|PostgreSQL query failed)',
                'description': 'Database error message indicating potential SQL injection vulnerability',
                'severity': 'High',
                'remediation': 'Use parameterized queries and input validation'
            },
            {
                'name': 'XSS Script Tag',
                'type': 'xss',
                'pattern': r'(?i)<script[^>]*>.*?</script>',
                'description': 'Script tag detected in response, potential XSS vulnerability',
                'severity': 'Medium',
                'remediation': 'Implement proper input sanitization and output encoding'
            },
            {
                'name': 'Directory Listing',
                'type': 'info_disclosure',
                'pattern': r'(?i)(Index of|Directory listing for)',
                'description': 'Directory listing enabled, exposing file structure',
                'severity': 'Low',
                'remediation': 'Disable directory listing in web server configuration'
            }
        ]
        
        added_count = 0
        for sig in default_signatures:
            cursor.execute('''
                SELECT COUNT(*) FROM signatures WHERE name = ? AND type = ?
            ''', (sig['name'], sig['type']))
            
            if cursor.fetchone()[0] == 0:
                cursor.execute('''
                    INSERT INTO signatures 
                    (name, type, pattern, description, severity, remediation, created_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    sig['name'],
                    sig['type'],
                    sig['pattern'],
                    sig['description'],
                    sig['severity'],
                    sig['remediation'],
                    datetime.now().isoformat()
                ))
                added_count += 1
        
        # Log update
        cursor.execute('''
            INSERT INTO update_log (source, items_added, update_date)
            VALUES (?, ?, ?)
        ''', ('Local Signatures', added_count, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Added {added_count} local signatures")


# Fix for missing timedelta import
from datetime import timedelta