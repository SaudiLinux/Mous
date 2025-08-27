# 🔍 Mous Security Scanner

**Advanced Web Vulnerability Scanner**

<p align="center">
  <img src="mous/assets/logo/mous_logo.svg" alt="Mous Logo" width="200"/>
</p>

<p align="center">
  <a href="https://github.com/SaudiLinux"><img src="https://img.shields.io/badge/GitHub-SaudiLinux-blue.svg" alt="GitHub"></a>
  <a href="mailto:SayerLinux@gmail.com"><img src="https://img.shields.io/badge/Email-SayerLinux@gmail.com-red.svg" alt="Email"></a>
  <img src="https://img.shields.io/badge/Platform-Linux-blue.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.7+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

## 🚀 Overview

Mous is a powerful, comprehensive web vulnerability scanner designed to identify security issues in web applications. It combines automated vulnerability detection with intelligent scanning techniques to provide thorough security assessments.

## ✨ Features

### 🔍 Vulnerability Detection
- **Cross-Site Scripting (XSS)** - Reflected, Stored, and DOM-based XSS
- **SQL Injection** - Union, Blind, Error-based, and Time-based SQLi
- **Local File Inclusion (LFI)** - Path traversal and file inclusion
- **Remote Code Execution (RCE)** - Command injection and code execution
- **Information Disclosure** - Sensitive data exposure
- **Misconfigurations** - Security headers, directory listing, default files

### 🗄️ Database & Intelligence
- **CVE Database** - Comprehensive vulnerability database with automatic updates
- **Exploit Integration** - Integration with ExploitDB and Metasploit
- **Signature Detection** - Pattern-based vulnerability signatures
- **Real-time Updates** - Automatic database synchronization

### 📊 Reporting
- **Multiple Formats** - HTML, CSV, XML, and JSON reports
- **Executive Summary** - High-level vulnerability overview
- **Detailed Findings** - Complete vulnerability details with evidence
- **Remediation Guidance** - Step-by-step fixing instructions

### ⚙️ Configuration
- **Flexible Scanning** - Configurable scan types and depth
- **Performance Tuning** - Thread control and rate limiting
- **Proxy Support** - HTTP/HTTPS/SOCKS proxy configuration
- **Authentication** - Support for various authentication methods

## 🛠️ Installation

### Prerequisites
- Python 3.7 or higher
- Linux operating system (Ubuntu, CentOS, Kali, etc.)

### Quick Installation
```bash
# Clone the repository
git clone https://github.com/SaudiLinux/Mous.git
cd Mous

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x mous.py
```

### Docker Installation
```bash
# Build Docker image
docker build -t mous-scanner .

# Run with Docker
docker run -it --rm mous-scanner python mous.py --help
```

## 🎯 Usage

### Basic Usage
```bash
# Scan a single URL
python mous.py -u https://example.com

# Scan with specific vulnerability types
python mous.py -u https://example.com --xss --sql

# Scan with custom output
python mous.py -u https://example.com -o reports/example_scan.html
```

### Advanced Usage
```bash
# Comprehensive scan with all features
python mous.py -u https://example.com \
  --all \
  --threads 20 \
  --timeout 60 \
  --output reports/comprehensive_scan.html \
  --format html

# Scan with proxy
python mous.py -u https://example.com \
  --proxy http://proxy.example.com:8080 \
  --xss --sql

# Scan with authentication
python mous.py -u https://example.com \
  --auth-type basic \
  --auth-user admin \
  --auth-pass password
```

### Configuration File Usage
```bash
# Use custom configuration
python mous.py -u https://example.com -c custom_config.json

# Generate sample configuration
python mous.py --generate-config
```

## 📋 Command Line Options

### Target Specification
- `-u, --url` - Target URL to scan
- `-l, --list` - File containing list of URLs to scan
- `--ip` - Target IP address (for network scanning)

### Scan Options
- `--threads` - Number of concurrent threads (default: 10)
- `--timeout` - Request timeout in seconds (default: 30)
- `--user-agent` - Custom User-Agent string
- `--delay` - Delay between requests in seconds

### Scan Types
- `--xss` - Enable XSS scanning
- `--sql` - Enable SQL injection scanning
- `--lfi` - Enable LFI scanning
- `--rce` - Enable RCE scanning
- `--info` - Enable information disclosure scanning
- `--all` - Enable all scan types

### Output Options
- `-o, --output` - Output file path
- `--format` - Report format (html, csv, xml, json)
- `--template` - Report template to use

### Configuration
- `-c, --config` - Configuration file path
- `--generate-config` - Generate sample configuration file
- `--update-db` - Update vulnerability database

### Database Options
- `--list-plugins` - List available plugins
- `--update-plugins` - Update vulnerability plugins

### Verbosity
- `-v, --verbose` - Enable verbose output
- `-q, --quiet` - Suppress output except errors

## 🔧 Configuration

### Configuration File Structure
Create `mous_config.json`:

```json
{
  "scanner": {
    "max_threads": 10,
    "request_timeout": 30,
    "user_agent": "Mous Security Scanner/1.0",
    "delay_between_requests": 1
  },
  "scan_types": {
    "xss": {
      "enabled": true,
      "payloads_file": "data/payloads/xss.txt"
    },
    "sql": {
      "enabled": true,
      "payloads_file": "data/payloads/sql.txt"
    }
  },
  "reporting": {
    "output_directory": "reports",
    "formats": ["html", "json"],
    "include_remediation": true
  },
  "proxy": {
    "enabled": false,
    "http_proxy": "http://proxy.example.com:8080"
  }
}
```

### Environment Variables
```bash
export MOUS_THREADS=20
export MOUS_TIMEOUT=60
export MOUS_OUTPUT_DIR=/custom/reports
export MOUS_PROXY=http://proxy:8080
```

## 📊 Report Formats

### HTML Report
Rich, interactive web report with:
- Executive summary
- Vulnerability details
- Evidence and proof-of-concept
- Remediation steps
- Severity ratings
- CVSS scores

### CSV Report
Spreadsheet-friendly format for:
- Bulk analysis
- Integration with other tools
- Custom reporting

### XML Report
Structured format for:
- Tool integration
- Automated processing
- Custom parsers

### JSON Report
Machine-readable format for:
- API integration
- Custom dashboards
- Automated workflows

## 🔌 Integrations

### Nessus Integration
```bash
# Configure Nessus connection
python mous.py --nessus-host localhost --nessus-port 8834
```

### Metasploit Integration
```bash
# Configure Metasploit connection
python mous.py --msf-host localhost --msf-port 55553
```

### Slack Notifications
```json
{
  "integrations": {
    "slack": {
      "enabled": true,
      "webhook_url": "YOUR_WEBHOOK_URL",
      "channel": "#security-alerts"
    }
  }
}
```

## 🗂️ Project Structure

```
Mous/
├── mous.py                 # Main executable
├── requirements.txt        # Dependencies
├── README.md              # This file
├── mous/
│   ├── src/
│   │   ├── core/          # Core scanner engine
│   │   ├── modules/       # Scanning modules
│   │   ├── database/      # Vulnerability database
│   │   ├── reports/       # Report generation
│   │   └── config/        # Configuration management
│   ├── data/
│   │   ├── payloads/      # Attack payloads
│   │   ├── signatures/    # Vulnerability signatures
│   │   └── wordlists/     # Discovery wordlists
│   ├── assets/
│   │   └── logo/          # Branding assets
│   ├── logs/              # Application logs
│   └── reports/           # Generated reports
├── tests/                 # Unit tests
├── docs/                  # Documentation
└── examples/              # Usage examples
```

## 🧪 Testing

### Run Unit Tests
```bash
python -m pytest tests/
```

### Run Integration Tests
```bash
python -m pytest tests/integration/
```

### Test Against Vulnerable Applications
```bash
# Test against DVWA
python mous.py -u http://localhost/dvwa --all

# Test against WebGoat
python mous.py -u http://localhost/webgoat --all
```

## 🛡️ Security Considerations

### Responsible Usage
- Only scan systems you own or have explicit permission to test
- Respect rate limits and robots.txt
- Use appropriate delays between requests
- Consider the impact on target systems

### Data Protection
- Scan results contain sensitive information
- Secure storage of reports and logs
- Regular cleanup of temporary files
- Encrypted transmission of results

## 🐛 Troubleshooting

### Common Issues

#### Database Update Failures
```bash
# Manual database update
python mous.py --update-db --force

# Check network connectivity
ping services.nvd.nist.gov
```

#### High Memory Usage
```bash
# Reduce thread count
python mous.py -u https://example.com --threads 5

# Use smaller wordlists
python mous.py -u https://example.com --wordlist small.txt
```

#### SSL Certificate Issues
```bash
# Disable SSL verification
python mous.py -u https://example.com --no-verify-ssl
```

#### Proxy Configuration
```bash
# Test proxy connectivity
python mous.py -u https://example.com --proxy http://proxy:8080 --test-proxy
```

### Debug Mode
```bash
# Enable debug logging
python mous.py -u https://example.com --debug --verbose
```

## 📈 Performance Tuning

### Optimize for Speed
```bash
# Increase threads for faster scanning
python mous.py -u https://example.com --threads 50

# Reduce timeout for faster failures
python mous.py -u https://example.com --timeout 10
```

### Optimize for Stealth
```bash
# Use delays to avoid detection
python mous.py -u https://example.com --delay 2 --threads 1

# Use random user agents
python mous.py -u https://example.com --random-user-agent
```

## 🔄 Continuous Integration

### GitHub Actions
```yaml
name: Security Scan
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday at 2 AM
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Mous Scanner
        run: |
          python mous.py -u ${{ secrets.TARGET_URL }} \
            --format json \
            --output security-report.json
```

## 📚 API Reference

### Python API Usage
```python
from mous.src.core.scanner import MousScanner
from mous.src.config.config_manager import ConfigManager

# Initialize scanner
config = ConfigManager()
scanner = MousScanner(config)

# Run scan
results = scanner.scan("https://example.com")

# Generate report
from mous.src.reports.report_generator import ReportGenerator
reporter = ReportGenerator()
report_path = reporter.generate_report(results, "html")
```

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/SaudiLinux/Mous.git
cd Mous
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements-dev.txt
```

### Contribution Guidelines
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Code Style
- Follow PEP 8 guidelines
- Use type hints
- Add comprehensive tests
- Update documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Author

**SayerLinux**

- GitHub: [@SaudiLinux](https://github.com/SaudiLinux)
- Email: [SayerLinux@gmail.com](mailto:SayerLinux@gmail.com)
- Website: [SaudiLinux GitHub](https://github.com/SaudiLinux)

## 🙏 Acknowledgments

- OWASP for security guidelines
- NIST for CVE database
- Security community for research and tools
- Contributors and testers

## 📞 Support

For support, please:
1. Check the [troubleshooting section](#troubleshooting)
2. Search [existing issues](https://github.com/SaudiLinux/Mous/issues)
3. Create a new issue with detailed information
4. Contact: [SayerLinux@gmail.com](mailto:SayerLinux@gmail.com)

---

<div align="center">
  <p><strong>🔍 Mous Security Scanner</strong></p>
  <p>Advanced Web Vulnerability Assessment Tool</p>
  <p><em>Built with ❤️ by SayerLinux</em></p>
</div>