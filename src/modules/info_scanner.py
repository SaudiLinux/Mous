#!/usr/bin/env python3
"""
Information Disclosure Scanner Module
Author: SayerLinux
"""

import re
import requests
import os
import time
import json
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class InfoScanner:
    """Information disclosure vulnerability scanner"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.get('user_agent')})
        
        # Load sensitive patterns
        self.patterns = self._load_patterns()
        
        # Setup timeout and retries
        self.timeout = config.get('timeout', 30)
        self.retries = config.get('retries', 3)
    
    def _load_patterns(self) -> Dict[str, List[str]]:
        """Load sensitive information patterns"""
        patterns_file = self.config.get('payloads.info_patterns_file')
        
        if patterns_file and os.path.exists(patterns_file):
            with open(patterns_file, 'r') as f:
                return json.load(f)
        
        # Default sensitive information patterns
        return {
            'api_keys': [
                r'api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'apikey\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'access[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'private[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'secret[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'Bearer\s+([a-zA-Z0-9_-]{20,})',
                r'X-API-Key:\s*([a-zA-Z0-9_-]{20,})',
                r'Authorization:\s*Bearer\s+([a-zA-Z0-9_-]{20,})'
            ],
            'database_credentials': [
                r'database[_-]?url\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'db[_-]?host\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'db[_-]?user\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'db[_-]?pass\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'db[_-]?password\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'db[_-]?name\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'mysql://([^"\'\s]+)',
                r'postgresql://([^"\'\s]+)',
                r'mongodb://([^"\'\s]+)',
                r'redis://([^"\'\s]+)'
            ],
            'email_addresses': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                r'email\s*[:=]\s*["\']?([^"\'\s@]+@[^"\'\s@]+\.[^"\'\s]+)["\']?',
                r'mail\s*[:=]\s*["\']?([^"\'\s@]+@[^"\'\s@]+\.[^"\'\s]+)["\']?',
                r'contact\s*[:=]\s*["\']?([^"\'\s@]+@[^"\'\s@]+\.[^"\'\s]+)["\']?'
            ],
            'phone_numbers': [
                r'\b\d{3}-\d{3}-\d{4}\b',
                r'\b\(\d{3}\)\s*\d{3}-\d{4}\b',
                r'\b\+?1?\s*\(?\d{3}\)?[-\s]*\d{3}[-\s]*\d{4}\b',
                r'\b\d{10}\b',
                r'phone\s*[:=]\s*["\']?(\+?\d{10,15})["\']?',
                r'tel\s*[:=]\s*["\']?(\+?\d{10,15})["\']?'
            ],
            'credit_cards': [
                r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                r'\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b',
                r'\b\d{4}-\d{4}-\d{4}-\d{4}\b',
                r'\b\d{16}\b'
            ],
            'ssn': [
                r'\b\d{3}-\d{2}-\d{4}\b',
                r'\b\d{9}\b',
                r'ssn\s*[:=]\s*["\']?(\d{3}-\d{2}-\d{4})["\']?',
                r'social[_-]?security\s*[:=]\s*["\']?(\d{3}-\d{2}-\d{4})["\']?'
            ],
            'ip_addresses': [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b',
                r'\b(?:[0-9A-Fa-f]{1,4}:){1,7}:[0-9A-Fa-f]{1,4}\b',
                r'\b[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,7}\b'
            ],
            'server_info': [
                r'Server:\s*([^\r\n]+)',
                r'X-Powered-By:\s*([^\r\n]+)',
                r'X-AspNet-Version:\s*([^\r\n]+)',
                r'X-Generator:\s*([^\r\n]+)',
                r'X-Drupal-Cache:\s*([^\r\n]+)',
                r'X-WordPress-Version:\s*([^\r\n]+)',
                r'X-Joomla-Version:\s*([^\r\n]+)',
                r'X-Content-Type-Options:\s*([^\r\n]+)',
                r'X-Frame-Options:\s*([^\r\n]+)',
                r'X-XSS-Protection:\s*([^\r\n]+)'
            ],
            'paths': [
                r'[\"\']([^"\']*(?:\\|/)(?:[^"\']*(?:\\|/)){2,}[^"\']*)[\"\']',
                r'path\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'file\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'directory\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'root\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'home\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'var/www/[^"\'\s]+',
                r'/home/[^"\'\s]+',
                r'/etc/[^"\'\s]+',
                r'/usr/local/[^"\'\s]+',
                r'/opt/[^"\'\s]+'
            ],
            'software_versions': [
                r'Apache/([\d.]+)',
                r'nginx/([\d.]+)',
                r'PHP/([\d.]+)',
                r'Python/([\d.]+)',
                r'Node\.js/([\d.]+)',
                r'Express/([\d.]+)',
                r'Django/([\d.]+)',
                r'Flask/([\d.]+)',
                r'Rails/([\d.]+)',
                r'WordPress ([\d.]+)',
                r'Drupal ([\d.]+)',
                r'Joomla! ([\d.]+)',
                r'Magento ([\d.]+)',
                r'PrestaShop ([\d.]+)',
                r'OpenCart ([\d.]+)',
                r'phpMyAdmin ([\d.]+)',
                r'MySQL ([\d.]+)',
                r'PostgreSQL ([\d.]+)',
                r'MongoDB ([\d.]+)',
                r'Redis ([\d.]+)'
            ],
            'debug_info': [
                r'DEBUG\s*=\s*True',
                r'TRACE\s*=\s*True',
                r'ENVIRONMENT\s*=\s*["\']?development["\']?',
                r'ENV\s*=\s*["\']?dev["\']?',
                r'STACK\s*TRACE',
                r'Exception:\s*[^\n]+',
                r'Error:\s*[^\n]+',
                r'Warning:\s*[^\n]+',
                r'Notice:\s*[^\n]+',
                r'Deprecated:\s*[^\n]+',
                r'Fatal\s*error:\s*[^\n]+',
                r'Parse\s*error:\s*[^\n]+',
                r'Syntax\s*error:\s*[^\n]+',
                r'Undefined\s*variable:\s*[^\n]+',
                r'Undefined\s*index:\s*[^\n]+',
                r'Undefined\s*offset:\s*[^\n]+',
                r'Call\s*to\s*undefined\s*function:\s*[^\n]+',
                r'Method\s*not\s*found:\s*[^\n]+',
                r'Class\s*not\s*found:\s*[^\n]+',
                r'File\s*not\s*found:\s*[^\n]+',
                r'Permission\s*denied:\s*[^\n]+',
                r'Access\s*denied:\s*[^\n]+'
            ]
        }
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan target for information disclosure"""
        vulnerabilities = []
        
        try:
            # Get initial response
            response = self.session.get(target, timeout=self.timeout)
            
            # Scan response content
            content_vulns = self._scan_content(response)
            vulnerabilities.extend(content_vulns)
            
            # Scan headers
            header_vulns = self._scan_headers(response)
            vulnerabilities.extend(header_vulns)
            
            # Scan common sensitive files
            file_vulns = self._scan_sensitive_files(target)
            vulnerabilities.extend(file_vulns)
            
            # Scan robots.txt
            robots_vulns = self._scan_robots_txt(target)
            vulnerabilities.extend(robots_vulns)
            
            # Scan sitemap.xml
            sitemap_vulns = self._scan_sitemap_xml(target)
            vulnerabilities.extend(sitemap_vulns)
            
            # Scan .git directory
            git_vulns = self._scan_git_directory(target)
            vulnerabilities.extend(git_vulns)
            
            # Scan .svn directory
            svn_vulns = self._scan_svn_directory(target)
            vulnerabilities.extend(svn_vulns)
            
            # Scan backup files
            backup_vulns = self._scan_backup_files(target)
            vulnerabilities.extend(backup_vulns)
            
        except Exception as e:
            print(f"Error in info disclosure scan: {str(e)}")
        
        return vulnerabilities
    
    def _scan_content(self, response: requests.Response) -> List[Dict[str, Any]]:
        """Scan response content for sensitive information"""
        vulnerabilities = []
        
        try:
            content = response.text
            
            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        
                        # Skip common false positives
                        if self._is_false_positive(match, category):
                            continue
                        
                        vulnerabilities.append({
                            'type': 'INFO_DISCLOSURE',
                            'subtype': category.upper(),
                            'severity': self._get_severity(category),
                            'description': f'Information disclosure: {category}',
                            'category': category,
                            'pattern': pattern,
                            'match': match,
                            'url': response.url,
                            'evidence': f'Found: {match[:100]}...' if len(match) > 100 else f'Found: {match}'
                        })
        
        except Exception as e:
            print(f"Error scanning content: {str(e)}")
        
        return vulnerabilities
    
    def _scan_headers(self, response: requests.Response) -> List[Dict[str, Any]]:
        """Scan response headers for sensitive information"""
        vulnerabilities = []
        
        try:
            headers = dict(response.headers)
            
            # Check for sensitive headers
            sensitive_headers = {
                'Server': 'Server version disclosure',
                'X-Powered-By': 'Technology stack disclosure',
                'X-AspNet-Version': 'ASP.NET version disclosure',
                'X-Generator': 'CMS/framework disclosure',
                'X-Drupal-Cache': 'Drupal version disclosure',
                'X-WordPress-Version': 'WordPress version disclosure',
                'X-Joomla-Version': 'Joomla version disclosure',
                'Set-Cookie': 'Cookie information disclosure',
                'WWW-Authenticate': 'Authentication information disclosure'
            }
            
            for header_name, description in sensitive_headers.items():
                if header_name in headers:
                    vulnerabilities.append({
                        'type': 'INFO_DISCLOSURE',
                        'subtype': 'HEADER_DISCLOSURE',
                        'severity': 'medium',
                        'description': description,
                        'header_name': header_name,
                        'header_value': headers[header_name],
                        'url': response.url,
                        'evidence': f'{header_name}: {headers[header_name]}'
                    })
            
            # Check for security headers
            security_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'Referrer-Policy',
                'Permissions-Policy'
            ]
            
            missing_headers = [h for h in security_headers if h not in headers]
            if missing_headers:
                vulnerabilities.append({
                    'type': 'INFO_DISCLOSURE',
                    'subtype': 'MISSING_SECURITY_HEADERS',
                    'severity': 'low',
                    'description': 'Missing security headers',
                    'missing_headers': missing_headers,
                    'url': response.url,
                    'evidence': f'Missing: {", ".join(missing_headers)}'
                })
        
        except Exception as e:
            print(f"Error scanning headers: {str(e)}")
        
        return vulnerabilities
    
    def _scan_sensitive_files(self, target: str) -> List[Dict[str, Any]]:
        """Scan for common sensitive files"""
        vulnerabilities = []
        
        sensitive_files = [
            '.env',
            '.htaccess',
            '.htpasswd',
            'config.php',
            'wp-config.php',
            'configuration.php',
            'database.php',
            'settings.php',
            'application.yml',
            'config.yml',
            'database.yml',
            'secrets.yml',
            'parameters.yml',
            '.git/config',
            '.git/index',
            '.svn/entries',
            '.svn/wc.db',
            'composer.json',
            'package.json',
            'requirements.txt',
            'Gemfile',
            'pom.xml',
            'build.gradle',
            'Dockerfile',
            'docker-compose.yml',
            'docker-compose.yaml',
            'Dockerfile.prod',
            'Dockerfile.dev',
            'nginx.conf',
            'apache.conf',
            'httpd.conf',
            'web.config',
            '.htaccess.bak',
            'config.php.bak',
            'wp-config.php.bak',
            'backup.zip',
            'backup.tar.gz',
            'backup.sql',
            'dump.sql',
            'database.sql',
            'db.sql',
            'mysql.sql',
            'postgresql.sql',
            'mongo.sql',
            'redis.sql',
            'logs.txt',
            'error.log',
            'access.log',
            'debug.log',
            'application.log',
            'app.log',
            'server.log',
            'php_errors.log',
            'php.log',
            'apache.log',
            'nginx.log',
            'system.log',
            'auth.log',
            'security.log',
            'audit.log',
            'console.log',
            'debug.txt',
            'test.txt',
            'temp.txt',
            'tmp.txt',
            'readme.txt',
            'README.md',
            'CHANGELOG.md',
            'CHANGELOG.txt',
            'LICENSE',
            'LICENSE.txt',
            'COPYING',
            'INSTALL',
            'INSTALL.txt',
            'UPGRADE',
            'UPGRADE.txt',
            'TODO',
            'TODO.txt',
            'FIXME',
            'FIXME.txt',
            'HACK',
            'HACK.txt',
            'SECURITY.md',
            'SECURITY.txt',
            'SECURITY.md',
            'CONTRIBUTING.md',
            'CONTRIBUTING.txt',
            'CODE_OF_CONDUCT.md',
            'CODE_OF_CONDUCT.txt'
        ]
        
        for file_path in sensitive_files:
            try:
                test_url = urljoin(target, file_path)
                response = self.session.get(test_url, timeout=self.timeout)
                
                if response.status_code == 200 and len(response.text) > 0:
                    # Check if it's actually a sensitive file
                    if self._is_sensitive_file(response, file_path):
                        vulnerabilities.append({
                            'type': 'INFO_DISCLOSURE',
                            'subtype': 'SENSITIVE_FILE',
                            'severity': 'high',
                            'description': f'Sensitive file accessible: {file_path}',
                            'file_path': file_path,
                            'url': test_url,
                            'size': len(response.text),
                            'evidence': response.text[:200] + '...' if len(response.text) > 200 else response.text
                        })
                
                time.sleep(self.config.get('delay', 0))
                
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _scan_robots_txt(self, target: str) -> List[Dict[str, Any]]:
        """Scan robots.txt for sensitive paths"""
        vulnerabilities = []
        
        try:
            robots_url = urljoin(target, 'robots.txt')
            response = self.session.get(robots_url, timeout=self.timeout)
            
            if response.status_code == 200 and 'Disallow:' in response.text:
                # Extract disallowed paths
                disallowed_paths = re.findall(r'Disallow:\s*([^\n\r]+)', response.text, re.IGNORECASE)
                
                if disallowed_paths:
                    vulnerabilities.append({
                        'type': 'INFO_DISCLOSURE',
                        'subtype': 'ROBOTS_TXT',
                        'severity': 'low',
                        'description': 'Sensitive paths disclosed in robots.txt',
                        'disallowed_paths': [path.strip() for path in disallowed_paths],
                        'url': robots_url,
                        'evidence': response.text
                    })
        
        except Exception as e:
            print(f"Error scanning robots.txt: {str(e)}")
        
        return vulnerabilities
    
    def _scan_sitemap_xml(self, target: str) -> List[Dict[str, Any]]:
        """Scan sitemap.xml for sensitive information"""
        vulnerabilities = []
        
        try:
            sitemap_url = urljoin(target, 'sitemap.xml')
            response = self.session.get(sitemap_url, timeout=self.timeout)
            
            if response.status_code == 200 and '<url>' in response.text:
                # Extract URLs from sitemap
                urls = re.findall(r'<loc>([^<]+)</loc>', response.text)
                
                if urls:
                    vulnerabilities.append({
                        'type': 'INFO_DISCLOSURE',
                        'subtype': 'SITEMAP_XML',
                        'severity': 'low',
                        'description': 'URL structure disclosed in sitemap.xml',
                        'urls_count': len(urls),
                        'sample_urls': urls[:5],
                        'url': sitemap_url,
                        'evidence': f'Found {len(urls)} URLs'
                    })
        
        except Exception as e:
            print(f"Error scanning sitemap.xml: {str(e)}")
        
        return vulnerabilities
    
    def _scan_git_directory(self, target: str) -> List[Dict[str, Any]]:
        """Scan for exposed .git directory"""
        vulnerabilities = []
        
        try:
            git_url = urljoin(target, '.git/')
            response = self.session.get(git_url, timeout=self.timeout)
            
            if response.status_code == 200 and ('Index of /.git' in response.text or 'Directory listing' in response.text):
                vulnerabilities.append({
                    'type': 'INFO_DISCLOSURE',
                    'subtype': 'GIT_EXPOSURE',
                    'severity': 'high',
                    'description': 'Git repository directory exposed',
                    'url': git_url,
                    'evidence': 'Git directory listing exposed'
                })
            
            # Check for git config
            config_url = urljoin(target, '.git/config')
            response = self.session.get(config_url, timeout=self.timeout)
            
            if response.status_code == 200 and '[core]' in response.text:
                vulnerabilities.append({
                    'type': 'INFO_DISCLOSURE',
                    'subtype': 'GIT_CONFIG',
                    'severity': 'high',
                    'description': 'Git configuration file exposed',
                    'url': config_url,
                    'evidence': response.text[:200] + '...' if len(response.text) > 200 else response.text
                })
        
        except Exception as e:
            print(f"Error scanning git directory: {str(e)}")
        
        return vulnerabilities
    
    def _scan_svn_directory(self, target: str) -> List[Dict[str, Any]]:
        """Scan for exposed .svn directory"""
        vulnerabilities = []
        
        try:
            svn_url = urljoin(target, '.svn/')
            response = self.session.get(svn_url, timeout=self.timeout)
            
            if response.status_code == 200 and ('Index of /.svn' in response.text or 'Directory listing' in response.text):
                vulnerabilities.append({
                    'type': 'INFO_DISCLOSURE',
                    'subtype': 'SVN_EXPOSURE',
                    'severity': 'high',
                    'description': 'SVN repository directory exposed',
                    'url': svn_url,
                    'evidence': 'SVN directory listing exposed'
                })
            
            # Check for SVN entries
            entries_url = urljoin(target, '.svn/entries')
            response = self.session.get(entries_url, timeout=self.timeout)
            
            if response.status_code == 200 and 'dir' in response.text:
                vulnerabilities.append({
                    'type': 'INFO_DISCLOSURE',
                    'subtype': 'SVN_ENTRIES',
                    'severity': 'high',
                    'description': 'SVN entries file exposed',
                    'url': entries_url,
                    'evidence': response.text[:200] + '...' if len(response.text) > 200 else response.text
                })
        
        except Exception as e:
            print(f"Error scanning SVN directory: {str(e)}")
        
        return vulnerabilities
    
    def _scan_backup_files(self, target: str) -> List[Dict[str, Any]]:
        """Scan for backup files"""
        vulnerabilities = []
        
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.copy', '.tmp', '.temp', '~', '.swp', '.swo']
        
        # Common files to check for backups
        common_files = [
            'index.html',
            'index.php',
            'config.php',
            'wp-config.php',
            'database.php',
            'settings.php',
            'application.yml',
            'config.yml',
            'package.json',
            'composer.json',
            'requirements.txt',
            'Gemfile',
            'Dockerfile',
            'docker-compose.yml',
            'nginx.conf',
            'apache.conf',
            'httpd.conf',
            '.htaccess',
            'robots.txt',
            'sitemap.xml'
        ]
        
        for file_path in common_files:
            for extension in backup_extensions:
                try:
                    backup_file = file_path + extension
                    test_url = urljoin(target, backup_file)
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if response.status_code == 200 and len(response.text) > 0:
                        vulnerabilities.append({
                            'type': 'INFO_DISCLOSURE',
                            'subtype': 'BACKUP_FILE',
                            'severity': 'medium',
                            'description': f'Backup file accessible: {backup_file}',
                            'original_file': file_path,
                            'backup_extension': extension,
                            'url': test_url,
                            'size': len(response.text),
                            'evidence': response.text[:200] + '...' if len(response.text) > 200 else response.text
                        })
                    
                    time.sleep(self.config.get('delay', 0))
                    
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _is_false_positive(self, match: str, category: str) -> bool:
        """Check if a match is a false positive"""
        false_positives = {
            'api_keys': ['example', 'test', 'demo', 'placeholder', 'your-api-key', 'api-key-here'],
            'email_addresses': ['example.com', 'test.com', 'demo.com', 'localhost', 'example.org'],
            'phone_numbers': ['000-000-0000', '123-456-7890', '111-111-1111'],
            'credit_cards': ['0000-0000-0000-0000', '1234-5678-9012-3456'],
            'ssn': ['000-00-0000', '123-45-6789']
        }
        
        if category in false_positives:
            for fp in false_positives[category]:
                if fp.lower() in match.lower():
                    return True
        
        return False
    
    def _is_sensitive_file(self, response: requests.Response, file_path: str) -> bool:
        """Check if the response indicates a sensitive file"""
        content_type = response.headers.get('content-type', '').lower()
        
        # Check content type
        sensitive_types = [
            'application/json',
            'application/xml',
            'application/yaml',
            'text/plain',
            'text/xml',
            'text/yaml',
            'application/octet-stream'
        ]
        
        if any(sensitive in content_type for sensitive in sensitive_types):
            return True
        
        # Check file extension
        sensitive_extensions = [
            '.env', '.config', '.conf', '.ini', '.json', '.xml', '.yml', '.yaml',
            '.log', '.sql', '.bak', '.backup', '.old', '.tmp', '.swp', '.swo'
        ]
        
        if any(ext in file_path.lower() for ext in sensitive_extensions):
            return True
        
        # Check for sensitive content patterns
        sensitive_patterns = [
            'password', 'secret', 'key', 'token', 'database', 'config',
            'mysql', 'postgresql', 'mongodb', 'redis', 'api_key',
            'private_key', 'certificate', 'ssl', 'https'
        ]
        
        content_lower = response.text.lower()
        if any(pattern in content_lower for pattern in sensitive_patterns):
            return True
        
        return False
    
    def _get_severity(self, category: str) -> str:
        """Get severity level for different information types"""
        severity_map = {
            'api_keys': 'critical',
            'database_credentials': 'critical',
            'ssn': 'high',
            'credit_cards': 'high',
            'email_addresses': 'medium',
            'phone_numbers': 'medium',
            'server_info': 'low',
            'software_versions': 'low',
            'paths': 'medium',
            'debug_info': 'medium'
        }
        
        return severity_map.get(category, 'medium')