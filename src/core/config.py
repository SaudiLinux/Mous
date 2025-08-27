#!/usr/bin/env python3
"""
Configuration Management for Mous Scanner
Author: SayerLinux
"""

import json
import yaml
import os
import argparse
from typing import Dict, Any, Optional


class Config:
    """Configuration manager for Mous scanner"""
    
    DEFAULT_CONFIG = {
        'threads': 10,
        'timeout': 30,
        'user_agent': 'Mous-Scanner/1.0',
        'delay': 0,
        'retries': 3,
        'logging': {
            'level': 'INFO',
            'file': None,
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'scan': {
            'xss': True,
            'sql': True,
            'lfi': True,
            'rce': True,
            'info': True,
            'discovery': True,
            'brute_force': False,
            'aggressive': False
        },
        'payloads': {
            'xss_payloads_file': 'data/signatures/xss.txt',
            'sql_payloads_file': 'data/signatures/sql.txt',
            'lfi_payloads_file': 'data/signatures/lfi.txt',
            'rce_payloads_file': 'data/signatures/rce.txt'
        },
        'discovery': {
            'wordlist_directories': 'data/signatures/directories.txt',
            'wordlist_files': 'data/signatures/files.txt',
            'extensions': ['php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'txt', 'xml', 'json'],
            'user_agents': 'data/signatures/user_agents.txt',
            'max_depth': 3
        },
        'database': {
            'vulnerabilities_db': 'data/vulnerabilities/vulns.db',
            'auto_update': True,
            'update_interval': 86400  # 24 hours
        },
        'reporting': {
            'output_dir': 'reports',
            'template_dir': 'src/reports/templates',
            'include_screenshots': False,
            'include_headers': True
        },
        'proxy': {
            'http': None,
            'https': None,
            'socks': None
        },
        'headers': {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0'
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration"""
        self.config = self.DEFAULT_CONFIG.copy()
        
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
        else:
            # Try to load from default locations
            self._load_default_configs()
    
    def _load_default_configs(self):
        """Load configuration from default locations"""
        default_locations = [
            'mous.conf',
            'config/mous.yaml',
            'config/mous.json',
            '~/.mous/config.yaml',
            '/etc/mous/config.yaml'
        ]
        
        for location in default_locations:
            location = os.path.expanduser(location)
            if os.path.exists(location):
                self.load_from_file(location)
                break
    
    def load_from_file(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.endswith('.json'):
                    file_config = json.load(f)
                elif config_file.endswith(('.yaml', '.yml')):
                    file_config = yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported config file format: {config_file}")
            
            self._merge_config(file_config)
            
        except Exception as e:
            raise RuntimeError(f"Error loading config file {config_file}: {str(e)}")
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """Merge new configuration with existing"""
        def deep_merge(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    deep_merge(base[key], value)
                else:
                    base[key] = value
            return base
        
        deep_merge(self.config, new_config)
    
    def update_from_args(self, args: argparse.Namespace):
        """Update configuration from command line arguments"""
        if hasattr(args, 'threads') and args.threads:
            self.config['threads'] = args.threads
        
        if hasattr(args, 'timeout') and args.timeout:
            self.config['timeout'] = args.timeout
        
        if hasattr(args, 'user_agent') and args.user_agent:
            self.config['user_agent'] = args.user_agent
        
        if hasattr(args, 'delay') and args.delay is not None:
            self.config['delay'] = args.delay
        
        # Update scan types based on arguments
        if hasattr(args, 'xss') and args.xss:
            self.config['scan']['xss'] = True
        
        if hasattr(args, 'sql') and args.sql:
            self.config['scan']['sql'] = True
        
        if hasattr(args, 'lfi') and args.lfi:
            self.config['scan']['lfi'] = True
        
        if hasattr(args, 'rce') and args.rce:
            self.config['scan']['rce'] = True
        
        if hasattr(args, 'info') and args.info:
            self.config['scan']['info'] = True
        
        if hasattr(args, 'all') and args.all:
            for scan_type in ['xss', 'sql', 'lfi', 'rce', 'info']:
                self.config['scan'][scan_type] = True
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, config_file: str):
        """Save current configuration to file"""
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                if config_file.endswith('.json'):
                    json.dump(self.config, f, indent=2, ensure_ascii=False)
                elif config_file.endswith(('.yaml', '.yml')):
                    yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
                else:
                    raise ValueError(f"Unsupported config file format: {config_file}")
                    
        except Exception as e:
            raise RuntimeError(f"Error saving config file {config_file}: {str(e)}")
    
    def validate(self) -> bool:
        """Validate configuration"""
        required_keys = [
            'threads',
            'timeout',
            'user_agent',
            'database.vulnerabilities_db'
        ]
        
        for key in required_keys:
            if self.get(key) is None:
                raise ValueError(f"Missing required configuration: {key}")
        
        # Validate threads
        threads = self.get('threads')
        if not isinstance(threads, int) or threads < 1 or threads > 100:
            raise ValueError("Threads must be an integer between 1 and 100")
        
        # Validate timeout
        timeout = self.get('timeout')
        if not isinstance(timeout, int) or timeout < 1:
            raise ValueError("Timeout must be a positive integer")
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary"""
        return self.config.copy()
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return json.dumps(self.config, indent=2, ensure_ascii=False)