#!/usr/bin/env python3
"""
Core Scanner Engine for Mous
Author: SayerLinux
"""

import asyncio
import concurrent.futures
import logging
import os
import time
from typing import List, Dict, Any
from urllib.parse import urlparse
from datetime import timedelta

from src.core.config import Config
from src.modules.xss_scanner import XSSScanner
from src.modules.sql_scanner import SQLScanner
from src.modules.lfi_scanner import LFIScanner
from src.modules.rce_scanner import RCEScanner
from src.modules.info_scanner import InfoScanner
from src.modules.discovery_scanner import DiscoveryScanner


class MousScanner:
    """Main scanner orchestrator for Mous vulnerability scanner"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = self._setup_logging()
        self.scanners = self._initialize_scanners()
        self.results = []
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('mous.scanner')
        logger.setLevel(getattr(logging, self.config.get('logging.level', 'INFO')))
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _initialize_scanners(self) -> Dict[str, Any]:
        """Initialize all scanning modules"""
        scanners = {}
        
        if self.config.get('scan.xss', True):
            scanners['xss'] = XSSScanner(self.config)
        
        if self.config.get('scan.sql', True):
            scanners['sql'] = SQLScanner(self.config)
        
        if self.config.get('scan.lfi', True):
            scanners['lfi'] = LFIScanner(self.config)
        
        if self.config.get('scan.rce', True):
            scanners['rce'] = RCEScanner(self.config)
        
        if self.config.get('scan.info', True):
            scanners['info'] = InfoScanner(self.config)
        
        scanners['discovery'] = DiscoveryScanner(self.config)
        
        return scanners
    
    def scan(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Main scanning orchestration method"""
        self.logger.info(f"Starting scan of {len(targets)} targets")
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.get('threads', 10)
        ) as executor:
            future_to_target = {
                executor.submit(self._scan_single_target, target): target
                for target in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.info(f"Completed scan of {target}")
                except Exception as e:
                    self.logger.error(f"Error scanning {target}: {str(e)}")
                    results.append({
                        'target': target,
                        'error': str(e),
                        'vulnerabilities': []
                    })
        
        self.results = results
        return results
    
    def _scan_single_target(self, target: str) -> Dict[str, Any]:
        """Scan a single target comprehensively"""
        self.logger.info(f"Starting scan of {target}")
        
        start_time = time.time()
        
        # Normalize target
        target = self._normalize_target(target)
        
        # Initialize result structure
        result = {
            'target': target,
            'scan_start': start_time,
            'vulnerabilities': [],
            'info': {},
            'discovery': {}
        }
        
        try:
            # Phase 1: Discovery and reconnaissance
            self.logger.debug(f"Phase 1: Discovery for {target}")
            discovery_results = self.scanners['discovery'].scan(target)
            result['discovery'] = discovery_results
            
            # Phase 2: Vulnerability scanning
            self.logger.debug(f"Phase 2: Vulnerability scanning for {target}")
            for scanner_name, scanner in self.scanners.items():
                if scanner_name == 'discovery':
                    continue
                
                try:
                    vulns = scanner.scan(target)
                    result['vulnerabilities'].extend(vulns)
                except Exception as e:
                    self.logger.error(f"Error in {scanner_name} scanner: {str(e)}")
            
            # Phase 3: Additional information gathering
            self.logger.debug(f"Phase 3: Information gathering for {target}")
            result['info'] = self._gather_additional_info(target)
            
        except Exception as e:
            self.logger.error(f"Critical error scanning {target}: {str(e)}")
            result['error'] = str(e)
        
        result['scan_duration'] = time.time() - start_time
        result['total_vulnerabilities'] = len(result['vulnerabilities'])
        
        return result
    
    def _normalize_target(self, target: str) -> str:
        """Normalize and validate target URL/IP"""
        target = target.strip()
        
        # Add protocol if missing
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Validate URL format
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"Invalid target format: {target}")
        
        return target
    
    def _gather_additional_info(self, target: str) -> Dict[str, Any]:
        """Gather additional information about the target"""
        info = {}
        
        try:
            import socket
            import ssl
            
            parsed = urlparse(target)
            hostname = parsed.netloc
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            # DNS resolution
            try:
                ip = socket.gethostbyname(hostname)
                info['ip_address'] = ip
                info['hostname'] = hostname
            except socket.gaierror:
                info['dns_error'] = f"Could not resolve {hostname}"
            
            # SSL certificate info
            if parsed.scheme == 'https':
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            info['ssl_cert'] = {
                                'subject': dict(x[0] for x in cert['subject']),
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'version': cert['version'],
                                'serial_number': cert['serialNumber'],
                                'not_before': cert['notBefore'],
                                'not_after': cert['notAfter']
                            }
                except Exception as e:
                    info['ssl_error'] = str(e)
            
        except Exception as e:
            self.logger.error(f"Error gathering additional info: {str(e)}")
        
        return info
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        if not self.results:
            return {}
        
        total_targets = len(self.results)
        total_vulnerabilities = sum(r.get('total_vulnerabilities', 0) for r in self.results)
        
        vuln_types = {}
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for result in self.results:
            for vuln in result.get('vulnerabilities', []):
                vuln_type = vuln.get('type', 'unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                
                severity = vuln.get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        return {
            'total_targets': total_targets,
            'total_vulnerabilities': total_vulnerabilities,
            'vulnerability_types': vuln_types,
            'severity_distribution': severity_counts,
            'scan_duration': sum(r.get('scan_duration', 0) for r in self.results)
        }