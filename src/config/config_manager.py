#!/usr/bin/env python3
"""
Configuration Manager for Mous Scanner
Author: SayerLinux
"""

import json
import yaml
import os
import argparse
from typing import Dict, Any, List, Optional
from pathlib import Path


class ConfigManager:
    """Manage configuration settings for Mous Scanner"""
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or "mous_config.json"
        self.config_path = Path(self.config_file)
        self.default_config = self._get_default_config()
        self.config = {}
        self.load_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration settings"""
        return {
            "scanner": {
                "max_threads": 10,
                "request_timeout": 30,
                "user_agent": "Mous Security Scanner/1.0",
                "delay_between_requests": 1,
                "max_retries": 3,
                "follow_redirects": True,
                "verify_ssl": False,
                "max_depth": 3,
                "max_pages": 100
            },
            "scan_types": {
                "xss": {
                    "enabled": True,
                    "payloads_file": "data/payloads/xss.txt",
                    "test_parameters": True,
                    "test_forms": True,
                    "test_headers": True,
                    "test_cookies": True
                },
                "sql": {
                    "enabled": True,
                    "payloads_file": "data/payloads/sql.txt",
                    "test_blind": True,
                    "test_error": True,
                    "test_union": True,
                    "test_time": True
                },
                "lfi": {
                    "enabled": True,
                    "payloads_file": "data/payloads/lfi.txt",
                    "test_parameters": True,
                    "test_forms": True
                },
                "rce": {
                    "enabled": True,
                    "payloads_file": "data/payloads/rce.txt",
                    "test_parameters": True,
                    "test_forms": True,
                    "test_headers": True
                },
                "info": {
                    "enabled": True,
                    "check_headers": True,
                    "check_robots": True,
                    "check_sitemap": True,
                    "check_git": True,
                    "check_backup": True,
                    "check_sensitive_files": True
                },
                "discovery": {
                    "enabled": True,
                    "wordlist_file": "data/wordlists/common.txt",
                    "extensions": ["php", "html", "txt", "bak", "old"],
                    "directories": True,
                    "files": True,
                    "recursive": False
                }
            },
            "database": {
                "auto_update": True,
                "update_interval_hours": 24,
                "cve_sources": [
                    "nvd",
                    "exploitdb"
                ],
                "local_database": "vulnerabilities.db"
            },
            "reporting": {
                "output_directory": "reports",
                "formats": ["html", "json"],
                "include_screenshots": False,
                "template": "default",
                "generate_executive_summary": True,
                "include_remediation": True,
                "include_cve_details": True
            },
            "proxy": {
                "enabled": False,
                "http_proxy": "",
                "https_proxy": "",
                "socks_proxy": ""
            },
            "authentication": {
                "enabled": False,
                "username": "",
                "password": "",
                "auth_type": "basic",  # basic, digest, bearer
                "token": "",
                "session_file": ""
            },
            "headers": {
                "custom_headers": {},
                "cookies": {},
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "accept_language": "en-US,en;q=0.5",
                "accept_encoding": "gzip, deflate"
            },
            "logging": {
                "level": "INFO",
                "file": "logs/mous.log",
                "max_size_mb": 10,
                "backup_count": 5,
                "console_output": True
            },
            "exclusions": {
                "ignore_extensions": ["css", "js", "png", "jpg", "jpeg", "gif", "ico", "svg"],
                "ignore_paths": ["/admin", "/wp-admin", "/administrator"],
                "ignore_parameters": ["utm_source", "utm_medium", "utm_campaign"],
                "max_response_size": 10485760  # 10MB
            },
            "performance": {
                "max_concurrent_requests": 50,
                "request_delay": 0.5,
                "connection_pool_size": 10,
                "read_timeout": 30,
                "connect_timeout": 10
            },
            "integrations": {
                "nessus": {
                    "enabled": False,
                    "host": "localhost",
                    "port": 8834,
                    "username": "",
                    "password": "",
                    "policy_id": 0
                },
                "metasploit": {
                    "enabled": False,
                    "host": "localhost",
                    "port": 55553,
                    "username": "",
                    "password": ""
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": "",
                    "channel": "#security-alerts"
                },
                "email": {
                    "enabled": False,
                    "smtp_server": "",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "from_email": "",
                    "to_emails": []
                }
            }
        }
    
    def load_config(self):
        """Load configuration from file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    if self.config_path.suffix.lower() in ['.yml', '.yaml']:
                        self.config = yaml.safe_load(f) or {}
                    else:
                        self.config = json.load(f)
            except Exception as e:
                print(f"Error loading config file: {e}")
                self.config = self.default_config.copy()
        else:
            self.config = self.default_config.copy()
            self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                if self.config_path.suffix.lower() in ['.yml', '.yaml']:
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config file: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                # Check default config
                default_value = self.default_config
                for dk in keys:
                    if isinstance(default_value, dict) and dk in default_value:
                        default_value = default_value[dk]
                    else:
                        return default
                return default_value
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value by key (supports dot notation)"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def update_from_args(self, args: argparse.Namespace):
        """Update configuration from command line arguments"""
        
        # Update scanner settings
        if hasattr(args, 'threads') and args.threads:
            self.set('scanner.max_threads', args.threads)
        
        if hasattr(args, 'timeout') and args.timeout:
            self.set('scanner.request_timeout', args.timeout)
        
        if hasattr(args, 'user_agent') and args.user_agent:
            self.set('scanner.user_agent', args.user_agent)
        
        if hasattr(args, 'delay') and args.delay:
            self.set('scanner.delay_between_requests', args.delay)
        
        # Update scan types
        scan_types = ['xss', 'sql', 'lfi', 'rce', 'info', 'discovery']
        for scan_type in scan_types:
            if hasattr(args, scan_type):
                self.set(f'scan_types.{scan_type}.enabled', getattr(args, scan_type))
        
        # Update reporting
        if hasattr(args, 'output') and args.output:
            self.set('reporting.output_directory', os.path.dirname(args.output))
        
        if hasattr(args, 'format') and args.format:
            self.set('reporting.formats', [args.format])
        
        # Update proxy settings
        if hasattr(args, 'proxy') and args.proxy:
            self.set('proxy.enabled', True)
            self.set('proxy.http_proxy', args.proxy)
            self.set('proxy.https_proxy', args.proxy)
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Validate scanner settings
        if self.get('scanner.max_threads') <= 0:
            errors.append("max_threads must be positive")
        
        if self.get('scanner.request_timeout') <= 0:
            errors.append("request_timeout must be positive")
        
        # Validate file paths
        payload_files = [
            self.get('scan_types.xss.payloads_file'),
            self.get('scan_types.sql.payloads_file'),
            self.get('scan_types.lfi.payloads_file'),
            self.get('scan_types.rce.payloads_file'),
            self.get('scan_types.discovery.wordlist_file')
        ]
        
        for file_path in payload_files:
            if file_path and not os.path.exists(file_path):
                errors.append(f"File not found: {file_path}")
        
        # Validate proxy settings
        if self.get('proxy.enabled'):
            http_proxy = self.get('proxy.http_proxy')
            https_proxy = self.get('proxy.https_proxy')
            
            if not http_proxy and not https_proxy:
                errors.append("Proxy enabled but no proxy URL provided")
        
        # Validate authentication settings
        if self.get('authentication.enabled'):
            auth_type = self.get('authentication.auth_type')
            if auth_type not in ['basic', 'digest', 'bearer']:
                errors.append(f"Invalid auth_type: {auth_type}")
        
        return errors
    
    def get_scan_config(self) -> Dict[str, Any]:
        """Get scan-specific configuration"""
        return {
            'scanner': self.get('scanner'),
            'scan_types': self.get('scan_types'),
            'proxy': self.get('proxy'),
            'authentication': self.get('authentication'),
            'headers': self.get('headers'),
            'exclusions': self.get('exclusions'),
            'performance': self.get('performance')
        }
    
    def get_report_config(self) -> Dict[str, Any]:
        """Get report-specific configuration"""
        return self.get('reporting')
    
    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration"""
        return self.get('database')
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.get('logging')
    
    def get_integration_config(self) -> Dict[str, Any]:
        """Get integration configuration"""
        return self.get('integrations')
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self.default_config.copy()
        self.save_config()
    
    def export_config(self, output_file: str):
        """Export current configuration"""
        try:
            output_path = Path(output_file)
            with open(output_path, 'w') as f:
                if output_path.suffix.lower() in ['.yml', '.yaml']:
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error exporting config: {e}")
            return False
    
    def import_config(self, input_file: str) -> bool:
        """Import configuration from file"""
        try:
            input_path = Path(input_file)
            with open(input_path, 'r') as f:
                if input_path.suffix.lower() in ['.yml', '.yaml']:
                    imported_config = yaml.safe_load(f)
                else:
                    imported_config = json.load(f)
            
            # Merge with current config
            self.config.update(imported_config)
            self.save_config()
            return True
        except Exception as e:
            print(f"Error importing config: {e}")
            return False
    
    def create_sample_config(self, output_file: str = None):
        """Create sample configuration file"""
        if not output_file:
            output_file = "mous_config_sample.json"
        
        sample_config = self.default_config.copy()
        sample_config['scanner']['user_agent'] = "Mous/1.0 (Security Scanner)"
        sample_config['proxy']['http_proxy'] = "http://proxy.example.com:8080"
        sample_config['authentication']['username'] = "admin"
        sample_config['integrations']['slack']['webhook_url'] = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(sample_config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error creating sample config: {e}")
            return False
    
    def get_active_scan_types(self) -> List[str]:
        """Get list of enabled scan types"""
        scan_types = []
        for scan_type, config in self.get('scan_types').items():
            if config.get('enabled', False):
                scan_types.append(scan_type)
        return scan_types
    
    def get_payload_files(self) -> Dict[str, str]:
        """Get payload files for each scan type"""
        payload_files = {}
        scan_types = self.get('scan_types')
        
        for scan_type, config in scan_types.items():
            if config.get('enabled', False) and 'payloads_file' in config:
                payload_files[scan_type] = config['payloads_file']
        
        return payload_files
    
    def get_custom_headers(self) -> Dict[str, str]:
        """Get custom headers for requests"""
        headers = self.get('headers.custom_headers', {})
        
        # Add standard headers
        if self.get('headers.accept'):
            headers['Accept'] = self.get('headers.accept')
        
        if self.get('headers.accept_language'):
            headers['Accept-Language'] = self.get('headers.accept_language')
        
        if self.get('headers.accept_encoding'):
            headers['Accept-Encoding'] = self.get('headers.accept_encoding')
        
        # Add cookies
        cookies = self.get('headers.cookies', {})
        if cookies:
            headers['Cookie'] = '; '.join([f"{k}={v}" for k, v in cookies.items()])
        
        return headers
    
    def get_proxy_settings(self) -> Optional[Dict[str, str]]:
        """Get proxy settings if enabled"""
        if not self.get('proxy.enabled'):
            return None
        
        proxy_settings = {}
        
        http_proxy = self.get('proxy.http_proxy')
        if http_proxy:
            proxy_settings['http'] = http_proxy
        
        https_proxy = self.get('proxy.https_proxy')
        if https_proxy:
            proxy_settings['https'] = https_proxy
        
        socks_proxy = self.get('proxy.socks_proxy')
        if socks_proxy:
            proxy_settings['socks'] = socks_proxy
        
        return proxy_settings if proxy_settings else None
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return json.dumps(self.config, indent=2)
    
    def __repr__(self) -> str:
        """Representation of configuration"""
        return f"ConfigManager(config_file='{self.config_file}')"