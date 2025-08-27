#!/usr/bin/env python3
"""
Discovery Scanner Module - Sensitive Files and Directories
Author: SayerLinux
"""

import os
import requests
import time
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse


class DiscoveryScanner:
    """Discovery scanner for sensitive files and directories"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.get('user_agent')})
        
        # Load wordlists
        self.directories = self._load_directories()
        self.files = self._load_files()
        
        # Setup timeout and retries
        self.timeout = config.get('timeout', 30)
        self.retries = config.get('retries', 3)
    
    def _load_directories(self) -> List[str]:
        """Load directory wordlist"""
        wordlist_file = self.config.get('payloads.directory_wordlist')
        
        if wordlist_file and os.path.exists(wordlist_file):
            with open(wordlist_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        
        # Default directory wordlist
        return [
            'admin', 'administrator', 'adminpanel', 'admincp', 'adm', 'panel',
            'cpanel', 'control', 'control-panel', 'dashboard', 'manage', 'management',
            'backend', 'backoffice', 'console', 'terminal', 'shell', 'ssh',
            'ftp', 'sftp', 'filemanager', 'file-manager', 'upload', 'uploads',
            'download', 'downloads', 'backup', 'backups', 'old', 'bak', 'tmp',
            'temp', 'temporary', 'cache', 'logs', 'log', 'debug', 'debugging',
            'test', 'testing', 'dev', 'development', 'staging', 'demo', 'examples',
            'sample', 'samples', 'docs', 'documentation', 'api', 'rest', 'soap',
            'graphql', 'ajax', 'json', 'xml', 'rss', 'feed', 'atom',
            'config', 'configuration', 'settings', 'setup', 'install', 'installer',
            'update', 'upgrade', 'migration', 'migrate', 'db', 'database',
            'sql', 'mysql', 'postgresql', 'pgsql', 'mongodb', 'redis', 'memcached',
            'sqlite', 'oracle', 'mssql', 'sqlserver', 'dbadmin', 'phpmyadmin',
            'adminer', 'pma', 'webadmin', 'webadmin', 'server-status', 'server-info',
            'info', 'status', 'health', 'ping', 'alive', 'check', 'monitor',
            'monitoring', 'metrics', 'stats', 'statistics', 'analytics',
            'reports', 'reporting', 'error', 'errors', '404', '403', '500',
            'maintenance', 'maintenance-mode', 'coming-soon', 'under-construction',
            'login', 'signin', 'sign-in', 'log-in', 'logout', 'signout', 'sign-out',
            'register', 'signup', 'sign-up', 'create-account', 'new-account',
            'profile', 'account', 'user', 'users', 'member', 'members',
            'customer', 'customers', 'client', 'clients', 'vendor', 'vendors',
            'partner', 'partners', 'supplier', 'suppliers', 'employee', 'employees',
            'staff', 'team', 'teams', 'group', 'groups', 'role', 'roles',
            'permission', 'permissions', 'auth', 'authentication', 'authorization',
            'session', 'sessions', 'token', 'tokens', 'jwt', 'oauth', 'openid',
            'sso', 'single-sign-on', 'saml', 'ldap', 'ad', 'active-directory',
            'mail', 'email', 'smtp', 'pop3', 'imap', 'mailer', 'mailserver',
            'mail-server', 'webmail', 'roundcube', 'horde', 'squirrelmail',
            'calendar', 'scheduler', 'scheduling', 'booking', 'reservation',
            'chat', 'messaging', 'message', 'messages', 'notification', 'notifications',
            'alert', 'alerts', 'news', 'announcement', 'announcements',
            'blog', 'news', 'article', 'articles', 'post', 'posts', 'page', 'pages',
            'content', 'contents', 'media', 'files', 'images', 'img', 'pictures',
            'photos', 'video', 'videos', 'audio', 'music', 'documents', 'docs',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv',
            'zip', 'tar', 'gz', 'rar', '7z', 'tar.gz', 'tar.bz2', 'tar.xz',
            'git', 'svn', 'cvs', 'hg', 'mercurial', 'bazaar', 'bzr',
            'wordpress', 'wp-admin', 'wp-content', 'wp-includes', 'wp-json',
            'drupal', 'sites/default', 'sites/all', 'modules', 'themes',
            'joomla', 'administrator', 'components', 'modules', 'templates',
            'magento', 'admin', 'app', 'skin', 'js', 'css', 'lib', 'media',
            'prestashop', 'admin', 'modules', 'themes', 'img', 'js', 'css',
            'shopify', 'admin', 'apps', 'themes', 'assets', 'cdn', 's3',
            'aws', 'amazon', 's3.amazonaws.com', 'cloudfront.net',
            'google', 'gcp', 'storage.googleapis.com', 'firebase',
            'microsoft', 'azure', 'blob.core.windows.net', 'onedrive',
            'dropbox', 'box', 'drive', 'icloud', 'onedrive'
        ]
    
    def _load_files(self) -> List[str]:
        """Load file wordlist"""
        wordlist_file = self.config.get('payloads.file_wordlist')
        
        if wordlist_file and os.path.exists(wordlist_file):
            with open(wordlist_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        
        # Default file wordlist
        return [
            '.env', '.env.local', '.env.dev', '.env.prod', '.env.staging',
            '.env.example', '.env.sample', '.env.template', '.env.backup',
            'config.php', 'config.inc.php', 'config.xml', 'config.json',
            'config.yml', 'config.yaml', 'config.ini', 'config.cfg',
            'settings.php', 'settings.xml', 'settings.json', 'settings.yml',
            'settings.yaml', 'settings.ini', 'settings.cfg',
            'database.php', 'database.xml', 'database.json', 'database.yml',
            'database.yaml', 'database.ini', 'database.sql', 'db.sql',
            'backup.sql', 'dump.sql', 'schema.sql', 'data.sql',
            'wp-config.php', 'wp-config-sample.php', 'wp-config.backup.php',
            'configuration.php', 'configuration.php.bak', 'configuration.php.old',
            '.htaccess', '.htpasswd', '.htaccess.bak', '.htaccess.old',
            'web.config', 'web.config.bak', 'web.config.old',
            'nginx.conf', 'nginx.conf.bak', 'nginx.conf.old',
            'apache.conf', 'apache.conf.bak', 'apache.conf.old',
            'httpd.conf', 'httpd.conf.bak', 'httpd.conf.old',
            'server.conf', 'server.conf.bak', 'server.conf.old',
            'php.ini', 'php.ini.bak', 'php.ini.old', 'phpinfo.php',
            'info.php', 'test.php', 'phpinfo.html', 'info.html',
            'readme.txt', 'README.md', 'README.txt', 'readme.md',
            'CHANGELOG.md', 'CHANGELOG.txt', 'CHANGELOG',
            'LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING',
            'INSTALL', 'INSTALL.txt', 'INSTALL.md', 'SETUP.md',
            'UPGRADE', 'UPGRADE.txt', 'UPGRADE.md', 'UPDATE.md',
            'TODO', 'TODO.txt', 'TODO.md', 'FIXME', 'FIXME.txt',
            'SECURITY.md', 'SECURITY.txt', 'SECURITY',
            'CONTRIBUTING.md', 'CONTRIBUTING.txt', 'CONTRIBUTING',
            'CODE_OF_CONDUCT.md', 'CODE_OF_CONDUCT.txt',
            'package.json', 'package-lock.json', 'yarn.lock', 'composer.json',
            'composer.lock', 'requirements.txt', 'Pipfile', 'Pipfile.lock',
            'Gemfile', 'Gemfile.lock', 'pom.xml', 'build.gradle',
            'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            '.dockerignore', 'docker-compose.override.yml',
            'robots.txt', 'sitemap.xml', 'sitemap.txt', 'sitemap.html',
            'crossdomain.xml', 'clientaccesspolicy.xml',
            '.gitignore', '.gitattributes', '.gitmodules', '.git/config',
            '.svn/entries', '.svn/wc.db', '.svnignore',
            '.hgignore', '.hg/hgrc', '.bzrignore',
            'backup.zip', 'backup.tar.gz', 'backup.tar.bz2',
            'backup.tar', 'backup.rar', 'backup.7z', 'backup.sql',
            'site.zip', 'site.tar.gz', 'site.tar.bz2', 'site.tar',
            'public_html.zip', 'public_html.tar.gz', 'public_html.tar',
            'www.zip', 'www.tar.gz', 'www.tar', 'www.rar',
            'htdocs.zip', 'htdocs.tar.gz', 'htdocs.tar', 'htdocs.rar',
            'logs.txt', 'error.log', 'access.log', 'debug.log',
            'application.log', 'app.log', 'server.log', 'system.log',
            'php_errors.log', 'php.log', 'apache.log', 'nginx.log',
            'mysql.log', 'postgresql.log', 'mongodb.log', 'redis.log',
            'index.html', 'index.htm', 'index.php', 'default.html',
            'default.htm', 'default.php', 'home.html', 'home.htm',
            'home.php', 'main.html', 'main.htm', 'main.php',
            'login.html', 'login.htm', 'login.php', 'signin.html',
            'signin.htm', 'signin.php', 'admin.html', 'admin.htm',
            'admin.php', 'panel.html', 'panel.htm', 'panel.php',
            'dashboard.html', 'dashboard.htm', 'dashboard.php',
            'upload.html', 'upload.htm', 'upload.php', 'uploads.html',
            'uploads.htm', 'uploads.php', 'files.html', 'files.htm',
            'files.php', 'download.html', 'download.htm', 'download.php',
            'downloads.html', 'downloads.htm', 'downloads.php'
        ]
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan target for sensitive files and directories"""
        vulnerabilities = []
        
        try:
            # Scan directories
            dir_vulns = self._scan_directories(target)
            vulnerabilities.extend(dir_vulns)
            
            # Scan files
            file_vulns = self._scan_files(target)
            vulnerabilities.extend(file_vulns)
            
            # Scan common application paths
            app_vulns = self._scan_application_paths(target)
            vulnerabilities.extend(app_vulns)
            
            # Scan version control systems
            vcs_vulns = self._scan_version_control(target)
            vulnerabilities.extend(vcs_vulns)
            
            # Scan backup files
            backup_vulns = self._scan_backup_files(target)
            vulnerabilities.extend(backup_vulns)
            
        except Exception as e:
            print(f"Error in discovery scan: {str(e)}")
        
        return vulnerabilities
    
    def _scan_directories(self, target: str) -> List[Dict[str, Any]]:
        """Scan for sensitive directories"""
        vulnerabilities = []
        
        for directory in self.directories:
            try:
                test_url = urljoin(target, directory)
                if not test_url.endswith('/'):
                    test_url += '/'
                
                response = self.session.get(test_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    # Check if it's a directory listing
                    is_directory = (
                        'Index of' in response.text or
                        'Directory listing' in response.text or
                        'Parent Directory' in response.text or
                        response.headers.get('content-type', '').startswith('text/html')
                    )
                    
                    if is_directory:
                        vulnerabilities.append({
                            'type': 'DISCOVERY',
                            'subtype': 'DIRECTORY_LISTING',
                            'severity': 'medium',
                            'description': f'Directory accessible: {directory}/',
                            'directory': directory,
                            'url': test_url,
                            'status_code': response.status_code,
                            'content_length': len(response.content)
                        })
                elif response.status_code == 403:
                    vulnerabilities.append({
                        'type': 'DISCOVERY',
                        'subtype': 'FORBIDDEN_DIRECTORY',
                        'severity': 'low',
                        'description': f'Forbidden directory detected: {directory}/',
                        'directory': directory,
                        'url': test_url,
                        'status_code': response.status_code
                    })
                
                time.sleep(self.config.get('delay', 0))
                
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _scan_files(self, target: str) -> List[Dict[str, Any]]:
        """Scan for sensitive files"""
        vulnerabilities = []
        
        for file_path in self.files:
            try:
                test_url = urljoin(target, file_path)
                response = self.session.get(test_url, timeout=self.timeout)
                
                if response.status_code == 200 and len(response.content) > 0:
                    # Check if it's actually a file (not a directory)
                    content_type = response.headers.get('content-type', '').lower()
                    
                    vulnerabilities.append({
                        'type': 'DISCOVERY',
                        'subtype': 'SENSITIVE_FILE',
                        'severity': self._get_file_severity(file_path),
                        'description': f'Sensitive file accessible: {file_path}',
                        'file_path': file_path,
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': content_type,
                        'first_line': response.text.split('\n')[0][:100] if response.text else ''
                    })
                elif response.status_code == 403:
                    vulnerabilities.append({
                        'type': 'DISCOVERY',
                        'subtype': 'FORBIDDEN_FILE',
                        'severity': 'low',
                        'description': f'Forbidden file detected: {file_path}',
                        'file_path': file_path,
                        'url': test_url,
                        'status_code': response.status_code
                    })
                
                time.sleep(self.config.get('delay', 0))
                
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _scan_application_paths(self, target: str) -> List[Dict[str, Any]]:
        """Scan for common application paths"""
        vulnerabilities = []
        
        # Common application paths
        app_paths = [
            # WordPress
            'wp-admin/', 'wp-content/', 'wp-includes/', 'wp-json/',
            'wp-admin/admin-ajax.php', 'wp-admin/install.php',
            'wp-login.php', 'xmlrpc.php', 'wp-cron.php',
            
            # Drupal
            'admin/', 'sites/default/', 'sites/all/', 'modules/', 'themes/',
            'install.php', 'update.php', 'cron.php',
            
            # Joomla
            'administrator/', 'components/', 'modules/', 'templates/',
            'installation/', 'administrator/index.php',
            
            # Magento
            'admin/', 'app/', 'skin/', 'js/', 'lib/', 'media/',
            'downloader/', 'install.php',
            
            # PrestaShop
            'admin/', 'modules/', 'themes/', 'img/', 'js/', 'css/',
            'install/', 'admin123/',
            
            # phpMyAdmin
            'phpmyadmin/', 'pma/', 'adminer/', 'dbadmin/',
            'mysql/', 'sql/', 'database/',
            
            # API endpoints
            'api/', 'rest/', 'soap/', 'graphql/', 'ajax/', 'json/',
            'api/v1/', 'api/v2/', 'api/v3/', 'v1/', 'v2/', 'v3/',
            
            # Common tools
            'adminer.php', 'info.php', 'phpinfo.php', 'test.php',
            'status.php', 'health.php', 'ping.php', 'alive.php',
            'monitoring.php', 'metrics.php', 'stats.php'
        ]
        
        for path in app_paths:
            try:
                test_url = urljoin(target, path)
                response = self.session.get(test_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    app_type = self._identify_application(path)
                    vulnerabilities.append({
                        'type': 'DISCOVERY',
                        'subtype': 'APPLICATION_PATH',
                        'severity': 'medium',
                        'description': f'Application path accessible: {path}',
                        'path': path,
                        'application': app_type,
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_length': len(response.content)
                    })
                elif response.status_code == 403:
                    app_type = self._identify_application(path)
                    vulnerabilities.append({
                        'type': 'DISCOVERY',
                        'subtype': 'FORBIDDEN_APPLICATION_PATH',
                        'severity': 'low',
                        'description': f'Forbidden application path: {path}',
                        'path': path,
                        'application': app_type,
                        'url': test_url,
                        'status_code': response.status_code
                    })
                
                time.sleep(self.config.get('delay', 0))
                
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _scan_version_control(self, target: str) -> List[Dict[str, Any]]:
        """Scan for version control system exposure"""
        vulnerabilities = []
        
        vcs_paths = [
            '.git/', '.git/config', '.git/index', '.git/logs/', '.git/refs/',
            '.svn/', '.svn/entries', '.svn/wc.db', '.svn/pristine/',
            '.hg/', '.hg/hgrc', '.hg/store/', '.hgignore',
            '.bzr/', '.bzr/branch/', '.bzr/repository/', '.bzrignore',
            'CVS/', 'CVS/Entries', 'CVS/Root', 'CVS/Repository'
        ]
        
        for path in vcs_paths:
            try:
                test_url = urljoin(target, path)
                response = self.session.get(test_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    vcs_type = self._identify_vcs(path)
                    vulnerabilities.append({
                        'type': 'DISCOVERY',
                        'subtype': 'VCS_EXPOSURE',
                        'severity': 'high',
                        'description': f'Version control system exposed: {path}',
                        'vcs_type': vcs_type,
                        'path': path,
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_length': len(response.content)
                    })
                
                time.sleep(self.config.get('delay', 0))
                
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _scan_backup_files(self, target: str) -> List[Dict[str, Any]]:
        """Scan for backup files"""
        vulnerabilities = []
        
        # Common backup extensions
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.copy', '.tmp', '.temp', '~']
        
        # Common files to check for backups
        common_files = [
            'index.html', 'index.htm', 'index.php', 'default.html', 'home.html',
            'config.php', 'wp-config.php', 'configuration.php', 'settings.php',
            'database.php', 'application.yml', 'config.yml', 'settings.yml',
            'package.json', 'composer.json', 'requirements.txt', 'Gemfile',
            'Dockerfile', 'docker-compose.yml', 'nginx.conf', 'apache.conf',
            '.htaccess', 'robots.txt', 'sitemap.xml'
        ]
        
        for file_path in common_files:
            for extension in backup_extensions:
                try:
                    backup_file = file_path + extension
                    test_url = urljoin(target, backup_file)
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if response.status_code == 200 and len(response.content) > 0:
                        vulnerabilities.append({
                            'type': 'DISCOVERY',
                            'subtype': 'BACKUP_FILE',
                            'severity': 'medium',
                            'description': f'Backup file accessible: {backup_file}',
                            'original_file': file_path,
                            'backup_extension': extension,
                            'url': test_url,
                            'status_code': response.status_code,
                            'content_length': len(response.content)
                        })
                    
                    time.sleep(self.config.get('delay', 0))
                    
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _get_file_severity(self, file_path: str) -> str:
        """Get severity level for different file types"""
        critical_files = [
            '.env', 'config.php', 'wp-config.php', 'configuration.php',
            'database.php', '.htaccess', '.htpasswd', 'web.config',
            'nginx.conf', 'apache.conf', 'httpd.conf', 'docker-compose.yml'
        ]
        
        high_files = [
            'backup.sql', 'dump.sql', 'database.sql', 'logs.txt',
            'error.log', 'access.log', 'debug.log', 'application.log'
        ]
        
        medium_files = [
            'readme.txt', 'README.md', 'CHANGELOG.md', 'LICENSE',
            'package.json', 'composer.json', 'requirements.txt', 'Gemfile'
        ]
        
        file_lower = file_path.lower()
        
        if any(critical in file_lower for critical in critical_files):
            return 'critical'
        elif any(high in file_lower for high in high_files):
            return 'high'
        elif any(medium in file_lower for medium in medium_files):
            return 'medium'
        else:
            return 'low'
    
    def _identify_application(self, path: str) -> str:
        """Identify application type from path"""
        path_lower = path.lower()
        
        if 'wp-' in path_lower or 'wordpress' in path_lower:
            return 'WordPress'
        elif 'drupal' in path_lower or 'sites/default' in path_lower:
            return 'Drupal'
        elif 'joomla' in path_lower or 'administrator' in path_lower:
            return 'Joomla'
        elif 'magento' in path_lower:
            return 'Magento'
        elif 'prestashop' in path_lower:
            return 'PrestaShop'
        elif 'phpmyadmin' in path_lower or 'pma' in path_lower:
            return 'phpMyAdmin'
        elif 'api' in path_lower:
            return 'API'
        else:
            return 'Unknown'
    
    def _identify_vcs(self, path: str) -> str:
        """Identify version control system from path"""
        path_lower = path.lower()
        
        if '.git' in path_lower:
            return 'Git'
        elif '.svn' in path_lower:
            return 'Subversion'
        elif '.hg' in path_lower:
            return 'Mercurial'
        elif '.bzr' in path_lower:
            return 'Bazaar'
        elif 'cvs' in path_lower:
            return 'CVS'
        else:
            return 'Unknown'