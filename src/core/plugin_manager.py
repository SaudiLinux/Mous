#!/usr/bin/env python3
"""
Plugin Manager for Mous Scanner
Author: SayerLinux
"""

import os
import importlib
import inspect
from pathlib import Path
from typing import List, Dict, Any
import logging


class PluginManager:
    """Manage scanner plugins and extensions"""
    
    def __init__(self, plugins_dir: str = "src/plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger('mous.plugins')
        self.loaded_plugins = {}
    
    def load_plugins(self):
        """Load all available plugins"""
        self.logger.info("Loading plugins...")
        
        if not self.plugins_dir.exists():
            return
        
        for plugin_file in self.plugins_dir.glob("*.py"):
            if plugin_file.name.startswith("__"):
                continue
            
            try:
                plugin_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find plugin classes
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if name.endswith("Plugin") and hasattr(obj, 'scan'):
                        plugin_instance = obj()
                        self.loaded_plugins[plugin_name] = plugin_instance
                        self.logger.info(f"Loaded plugin: {plugin_name}")
                        
            except Exception as e:
                self.logger.error(f"Failed to load plugin {plugin_file}: {str(e)}")
    
    def list_plugins(self):
        """List all available plugins"""
        print("\n=== Available Plugins ===")
        
        if not self.loaded_plugins:
            print("No plugins loaded.")
            return
        
        for name, plugin in self.loaded_plugins.items():
            description = getattr(plugin, 'description', 'No description available')
            version = getattr(plugin, 'version', 'Unknown')
            author = getattr(plugin, 'author', 'Unknown')
            
            print(f"Plugin: {name}")
            print(f"  Version: {version}")
            print(f"  Author: {author}")
            print(f"  Description: {description}")
            print()
    
    def get_plugin(self, name: str):
        """Get a specific plugin by name"""
        return self.loaded_plugins.get(name)
    
    def get_all_plugins(self) -> Dict[str, Any]:
        """Get all loaded plugins"""
        return self.loaded_plugins
    
    def create_sample_plugins(self):
        """Create sample plugins for demonstration"""
        sample_plugin = '''#!/usr/bin/env python3
"""
Sample Plugin for Mous Scanner
Author: SayerLinux
"""

from typing import List, Dict, Any


class SamplePlugin:
    """Sample scanner plugin"""
    
    def __init__(self):
        self.name = "Sample Plugin"
        self.version = "1.0.0"
        self.author = "SayerLinux"
        self.description = "A sample plugin demonstrating plugin architecture"
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Perform sample scan"""
        vulnerabilities = []
        
        # Sample vulnerability detection logic
        vulnerabilities.append({
            'type': 'sample',
            'name': 'Sample Vulnerability',
            'description': 'This is a sample vulnerability for demonstration',
            'severity': 'Info',
            'url': target,
            'evidence': 'Sample evidence',
            'remediation': 'This is just a sample'
        })
        
        return vulnerabilities


class CustomHeaderPlugin:
    """Custom HTTP header analysis plugin"""
    
    def __init__(self):
        self.name = "Custom Header Analyzer"
        self.version = "1.0.0"
        self.author = "SayerLinux"
        self.description = "Analyzes custom HTTP headers for security issues"
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Analyze HTTP headers"""
        import requests
        
        vulnerabilities = []
        
        try:
            response = requests.get(target, timeout=10)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            for header in security_headers:
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'missing_security_header',
                        'name': f'Missing {header}',
                        'description': f'The {header} security header is missing',
                        'severity': 'Medium' if header in ['X-Frame-Options', 'X-Content-Type-Options'] else 'Low',
                        'url': target,
                        'evidence': f'Header {header} not found',
                        'remediation': f'Add the {header} header to improve security'
                    })
        
        except Exception as e:
            pass  # Handle connection errors gracefully
        
        return vulnerabilities
'''
        
        # Create plugins directory and sample plugins
        plugins_dir = Path("src/plugins")
        plugins_dir.mkdir(parents=True, exist_ok=True)
        
        sample_file = plugins_dir / "sample_plugin.py"
        if not sample_file.exists():
            with open(sample_file, 'w') as f:
                f.write(sample_plugin)
        
        # Create __init__.py for plugins
        init_file = plugins_dir / "__init__.py"
        if not init_file.exists():
            with open(init_file, 'w') as f:
                f.write('')


# Create a simple plugin base class
class BasePlugin:
    """Base class for all scanner plugins"""
    
    def __init__(self):
        self.name = "Base Plugin"
        self.version = "1.0.0"
        self.author = "Unknown"
        self.description = "Base plugin class"
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Override this method in subclasses"""
        return []
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description
        }