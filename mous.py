#!/usr/bin/env python3
"""
Mous - Advanced Web Vulnerability Scanner
Author: SayerLinux
Website: https://github.com/SaudiLinux
Email: SayerLinux@gmail.com

A comprehensive web vulnerability scanner that detects security flaws,
misconfigurations, and known vulnerabilities in web servers.
"""

import argparse
import sys
import os
from src.core.scanner import MousScanner
from src.core.config import Config
from src.reports.report_generator import ReportGenerator

__version__ = "1.0.0"
__author__ = "SayerLinux"


def banner():
    """Display the Mous scanner banner with logo"""
    banner_text = """
    ███╗   ███╗ ██████╗ ██████╗ ███╗   ██╗██╗   ██╗
    ████╗ ████║██╔═══██╗██╔══██╗████╗  ██║╚██╗ ██╔╝
    ██╔████╔██║██║   ██║██████╔╝██╔██╗ ██║ ╚████╔╝ 
    ██║╚██╔╝██║██║   ██║██╔═══╝ ██║╚██╗██║  ╚██╔╝  
    ██║ ╚═╝ ██║╚██████╔╝██║     ██║ ╚████║   ██║   
    ╚═╝     ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═══╝   ╚═╝   
    
    Mous Web Vulnerability Scanner v{}
    Author: {}
    Website: {}
    Email: {}
    
    A comprehensive security scanner for web applications
    """.format(__version__, __author__, "https://github.com/SaudiLinux", "SayerLinux@gmail.com")
    
    print(banner_text)


def main():
    """Main entry point for Mous scanner"""
    parser = argparse.ArgumentParser(description="Mous - Advanced Web Vulnerability Scanner")
    
    # Target specification
    parser.add_argument("-u", "--url", help="Target URL to scan")
    parser.add_argument("-l", "--list", help="File containing list of URLs to scan")
    parser.add_argument("-i", "--ip", help="Target IP address to scan")
    
    # Scan options
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--user-agent", default="Mous-Scanner/1.0", help="Custom User-Agent string")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")
    
    # Scan types
    parser.add_argument("--xss", action="store_true", help="Enable XSS vulnerability scanning")
    parser.add_argument("--sql", action="store_true", help="Enable SQL injection scanning")
    parser.add_argument("--lfi", action="store_true", help="Enable Local File Inclusion scanning")
    parser.add_argument("--rce", action="store_true", help="Enable Remote Code Execution scanning")
    parser.add_argument("--info", action="store_true", help="Enable information disclosure scanning")
    parser.add_argument("--all", action="store_true", help="Enable all scan types")
    
    # Reporting
    parser.add_argument("-o", "--output", help="Output file name (without extension)")
    parser.add_argument("--format", choices=["html", "csv", "xml", "json"], default="html", help="Report format")
    parser.add_argument("--template", help="Custom report template")
    
    # Configuration
    parser.add_argument("-c", "--config", help="Configuration file path")
    parser.add_argument("--update", action="store_true", help="Update vulnerability database")
    parser.add_argument("--list-plugins", action="store_true", help="List available plugins")
    
    # Verbosity
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode - minimal output")
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        banner()
        parser.print_help()
        sys.exit(0)
    
    if not args.quiet:
        banner()
    
    try:
        # Initialize configuration
        config = Config(args.config)
        config.update_from_args(args)
        
        # Update vulnerability database if requested
        if args.update:
            from src.database.updater import VulnDBUpdater
            updater = VulnDBUpdater()
            updater.update()
            return
        
        # List plugins if requested
        if args.list_plugins:
            from src.core.plugin_manager import PluginManager
            plugin_manager = PluginManager()
            plugin_manager.create_sample_plugins()
            plugin_manager.load_plugins()
            plugin_manager.list_plugins()
            return
        
        # Initialize scanner
        scanner = MousScanner(config)
        
        # Determine targets
        targets = []
        if args.url:
            targets.append(args.url)
        elif args.list:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        elif args.ip:
            targets.append(args.ip)
        else:
            print("Error: No target specified. Use -u, -l, or -i")
            sys.exit(1)
        
        # Run scan
        results = scanner.scan(targets)
        
        # Generate reports
        if args.output:
            report_generator = ReportGenerator()
            report_path = report_generator.generate_report(results, args.format, args.output)
            print(f"Report generated: {report_path}")
        else:
            # Print results to console
            for result in results:
                print(f"Target: {result['target']}")
                print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")
                for vuln in result['vulnerabilities']:
                    print(f"  - {vuln['type']}: {vuln['description']}")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        if args.verbose > 1:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()