#!/usr/bin/env python3
"""
Enhanced Web Application Reconnaissance Tool v4.0 - Pure Recon Edition
Comprehensive intelligence gathering for authorized penetration testing
Focus: Breadth of data collection, not scoring or filtering

For authorized security testing only - Use responsibly!
"""

import socket
import dns.resolver
import dns.zone
import dns.query
import dns.reversename
import requests
import whois
import json
import sys
import argparse
import time
import re
import hashlib
import ssl
import os
import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Set, Optional, Any, Tuple
from pathlib import Path
import concurrent.futures
from dataclasses import dataclass, asdict

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''

import warnings
warnings.filterwarnings('ignore')


@dataclass
class ReconConfig:
    """Configuration for reconnaissance"""
    target: str
    verbose: bool = False
    delay: float = 0.5
    timeout: int = 10
    threads: int = 10
    proxy: Optional[str] = None
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    max_depth: int = 3
    output_dir: str = './recon_output'
    rate_limit: int = 10
    skip_verify: bool = False


class PureWebRecon:
    """Pure reconnaissance - comprehensive data collection without filtering"""
    
    def __init__(self, config: ReconConfig):
        """Initialize reconnaissance tool"""
        self.config = config
        self.target = config.target.strip().lower()
        
        # Session setup
        self.session = self._setup_session()
        
        # Target parsing
        self.is_ip = self._is_ip_address(self.target)
        self.domain = None if self.is_ip else self._extract_domain(self.target)
        self.apex_domain = None if self.is_ip else self._extract_apex_domain(self.target)
        self.ip_address = self.target if self.is_ip else None
        
        # Results storage
        self.results = self._initialize_results()
        
        # Cache and rate limiting
        self.cache = {}
        self.last_request_time = defaultdict(float)
        self.request_semaphore = asyncio.Semaphore(config.rate_limit)
        
        # API keys
        self.api_keys = self._load_api_keys()
        
        # Create output directory
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
        
    def _setup_session(self) -> requests.Session:
        """Setup HTTP session"""
        session = requests.Session()
        session.verify = False
        session.timeout = self.config.timeout
        session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/json,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if self.config.proxy:
            session.proxies = {'http': self.config.proxy, 'https': self.config.proxy}
            
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
        
    def _initialize_results(self) -> dict:
        """Initialize comprehensive results structure"""
        return {
            'metadata': {
                'target': self.target,
                'scan_start': datetime.now().isoformat(),
                'scan_id': hashlib.md5(f"{self.target}{datetime.now()}".encode()).hexdigest()[:12]
            },
            'basic_info': {
                'domain': None,
                'apex_domain': None,
                'ip_addresses': [],
                'whois': {},
                'reverse_whois': []
            },
            'dns': {
                'records': {},
                'nameservers': [],
                'mx_records': [],
                'zone_transfer_attempts': [],
                'dnssec': {
                    'enabled': False,
                    'details': {}
                },
                'caa_records': [],
                'wildcard_dns': None
            },
            'subdomains': {
                'discovered': [],
                'verified': [],
                'sources': {}
            },
            'infrastructure': {
                'asn': {},
                'cloud_provider': None,
                'cdn': None,
                'hosting': {},
                'ip_ranges': [],
                'reverse_dns': []
            },
            'technologies': {
                'detected': {},
                'versions': {},
                'headers': {},
                'cookies': {},
                'javascript_libraries': []
            },
            'security': {
                'headers': {},
                'tls_info': {},
                'waf_detected': None,
                'cors': {},
                'certificate_chain': []
            },
            'osint': {
                'emails': [],
                'employees': [],
                'social_media': {},
                'documents': [],
                'github_repos': [],
                'code_mentions': [],
                'paste_sites': [],
                'breach_data': [],
                'google_dorks': []
            },
            'web_analysis': {
                'endpoints': [],
                'forms': [],
                'comments': [],
                'js_files': [],
                'api_endpoints': [],
                'parameters': [],
                'interesting_files': [],
                'robots_txt': None,
                'sitemap': None
            },
            'third_party': {
                'shodan': {},
                'censys': {},
                'virustotal': {},
                'securitytrails': {},
                'hunter_io': {},
                'urlscan': {}
            },
            'historical': {
                'wayback_snapshots': [],
                'dns_history': [],
                'whois_history': []
            },
            'errors': []
        }
        
    def _load_api_keys(self) -> dict:
        """Load API keys from environment"""
        return {
            'shodan': os.environ.get('SHODAN_API_KEY'),
            'censys': os.environ.get('CENSYS_API_SECRET'),
            'virustotal': os.environ.get('VT_API_KEY'),
            'securitytrails': os.environ.get('SECURITYTRAILS_API_KEY'),
            'hunter': os.environ.get('HUNTER_API_KEY'),
            'github': os.environ.get('GITHUB_TOKEN'),
            'binaryedge': os.environ.get('BINARYEDGE_API_KEY'),
            'fullhunt': os.environ.get('FULLHUNT_API_KEY')
        }
        
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            socket.inet_aton(target.split('/')[0])
            return True
        except socket.error:
            return False
            
    def _extract_domain(self, target: str) -> str:
        """Extract clean domain from target"""
        if '://' in target:
            target = target.split('://')[1]
        if '/' in target:
            target = target.split('/')[0]
        if ':' in target:
            target = target.split(':')[0]
        return target.lstrip('www.')
    
    def _extract_apex_domain(self, target: str) -> str:
        """Extract apex/root domain (e.g., business.tiktok.com -> tiktok.com)"""
        domain = self._extract_domain(target)
        parts = domain.split('.')
        
        # Handle common TLDs
        if len(parts) >= 2:
            # For .co.uk, .com.au, etc.
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'ac', 'gov', 'net', 'org']:
                return '.'.join(parts[-3:])
            # Standard TLD
            return '.'.join(parts[-2:])
        return domain
        
    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time[self.target]
        if elapsed < self.config.delay:
            time.sleep(self.config.delay - elapsed)
        self.last_request_time[self.target] = time.time()
        
    def print_status(self, message: str, status: str = "info"):
        """Print colored status message"""
        symbols = {
            "info": ("ℹ", Fore.CYAN),
            "success": ("✓", Fore.GREEN),
            "warning": ("⚠", Fore.YELLOW),
            "error": ("✗", Fore.RED),
            "progress": ("⟳", Fore.BLUE)
        }
        symbol, color = symbols.get(status, ("•", Fore.WHITE))
        print(f"{color}{symbol} {message}{Style.RESET_ALL}")
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🔍  Pure Reconnaissance Tool v4.0                          ║
║       Comprehensive Intelligence Gathering                    ║
║                                                               ║
║   Target: {self.target:<50} ║
║   Scan ID: {self.results['metadata']['scan_id']:<48} ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner)
        
    # ==================== DNS Reconnaissance ====================
    
    def dns_reconnaissance(self):
        """Comprehensive DNS reconnaissance"""
        self.print_status("Starting comprehensive DNS reconnaissance...", "progress")
        
        # Basic DNS resolution
        self._dns_resolution()
        
        # Get nameservers and MX from apex domain
        self._get_apex_records()
        
        # DNSSEC validation
        self._check_dnssec()
        
        # Zone transfer attempts
        self._zone_transfer_attempts()
        
        # CAA records
        self._get_caa_records()
        
        # Wildcard DNS detection
        self._check_wildcard_dns()
        
        self.print_status("DNS reconnaissance completed", "success")
    
    def _dns_resolution(self):
        """Perform comprehensive DNS resolution"""
        if self.is_ip:
            # Reverse DNS lookup
            try:
                self._rate_limit()
                reverse_name = dns.reversename.from_address(self.target)
                answers = dns.resolver.resolve(reverse_name, 'PTR')
                ptr_records = [str(rdata) for rdata in answers]
                self.results['dns']['records']['PTR'] = ptr_records
                if ptr_records:
                    self.domain = ptr_records[0].rstrip('.')
                    self.apex_domain = self._extract_apex_domain(self.domain)
                    self.results['basic_info']['domain'] = self.domain
                    self.results['basic_info']['apex_domain'] = self.apex_domain
                    self.print_status(f"Reverse DNS: {self.domain}", "success")
            except Exception as e:
                self.results['errors'].append(f"Reverse DNS failed: {str(e)}")
        else:
            # Forward DNS lookup
            record_types = ['A', 'AAAA', 'CNAME', 'TXT', 'SOA']
            
            for record_type in record_types:
                try:
                    self._rate_limit()
                    answers = dns.resolver.resolve(self.domain, record_type)
                    records = []
                    
                    for rdata in answers:
                        if record_type == 'SOA':
                            records.append({
                                'mname': str(rdata.mname),
                                'rname': str(rdata.rname),
                                'serial': rdata.serial,
                                'refresh': rdata.refresh,
                                'retry': rdata.retry,
                                'expire': rdata.expire,
                                'minimum': rdata.minimum
                            })
                        else:
                            records.append(str(rdata))
                    
                    self.results['dns']['records'][record_type] = records
                    
                    # Store IP addresses
                    if record_type in ['A', 'AAAA']:
                        self.results['basic_info']['ip_addresses'].extend(records)
                        if not self.ip_address and records:
                            self.ip_address = records[0]
                        
                    if records and self.config.verbose:
                        self.print_status(f"Found {len(records)} {record_type} record(s)", "info")
                        
                except dns.resolver.NXDOMAIN:
                    self.results['errors'].append(f"Domain {self.domain} does not exist")
                    break
                except dns.resolver.NoAnswer:
                    pass
                except Exception as e:
                    if self.config.verbose:
                        self.results['errors'].append(f"DNS {record_type} lookup failed: {str(e)}")
    
    def _get_apex_records(self):
        """Get NS and MX records from apex domain"""
        if not self.apex_domain:
            return
        
        self.results['basic_info']['apex_domain'] = self.apex_domain
        
        # Nameservers
        try:
            self._rate_limit()
            answers = dns.resolver.resolve(self.apex_domain, 'NS')
            ns_records = [str(rdata).rstrip('.') for rdata in answers]
            self.results['dns']['nameservers'] = ns_records
            if self.config.verbose:
                self.print_status(f"Nameservers: {', '.join(ns_records[:3])}", "info")
        except Exception as e:
            if self.config.verbose:
                self.results['errors'].append(f"NS lookup failed: {str(e)}")
        
        # MX Records
        try:
            self._rate_limit()
            answers = dns.resolver.resolve(self.apex_domain, 'MX')
            mx_records = []
            for rdata in answers:
                mx_records.append({
                    'preference': rdata.preference,
                    'exchange': str(rdata.exchange).rstrip('.')
                })
            self.results['dns']['mx_records'] = mx_records
            if self.config.verbose and mx_records:
                self.print_status(f"MX records: {len(mx_records)} found", "info")
        except Exception as e:
            if self.config.verbose:
                self.results['errors'].append(f"MX lookup failed: {str(e)}")
    
    def _check_dnssec(self):
        """Check DNSSEC configuration"""
        if not self.apex_domain:
            return
        
        try:
            self._rate_limit()
            # Query for DNSKEY records
            answers = dns.resolver.resolve(self.apex_domain, 'DNSKEY')
            
            if answers:
                self.results['dns']['dnssec']['enabled'] = True
                dnskeys = []
                for rdata in answers:
                    dnskeys.append({
                        'flags': rdata.flags,
                        'protocol': rdata.protocol,
                        'algorithm': rdata.algorithm
                    })
                self.results['dns']['dnssec']['dnskeys'] = dnskeys
                self.print_status(f"DNSSEC enabled on {self.apex_domain}", "success")
            else:
                self.results['dns']['dnssec']['enabled'] = False
                
        except dns.resolver.NoAnswer:
            self.results['dns']['dnssec']['enabled'] = False
            if self.config.verbose:
                self.print_status("DNSSEC not enabled", "info")
        except Exception as e:
            self.results['dns']['dnssec']['enabled'] = False
            if self.config.verbose:
                self.results['errors'].append(f"DNSSEC check failed: {str(e)}")
    
    def _zone_transfer_attempts(self):
        """Attempt zone transfers on all nameservers"""
        if not self.apex_domain:
            return
            
        nameservers = self.results['dns'].get('nameservers', [])
        
        if not nameservers:
            return
        
        self.print_status(f"Attempting zone transfers on {len(nameservers)} nameservers...", "progress")
        
        for ns in nameservers:
            attempt = {
                'nameserver': ns,
                'success': False,
                'records': [],
                'error': None
            }
            
            try:
                ns_clean = ns.rstrip('.')
                self._rate_limit()
                
                zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, self.apex_domain, timeout=10))
                
                if zone:
                    attempt['success'] = True
                    zone_data = []
                    
                    for name, node in zone.nodes.items():
                        zone_data.append(f"{name}.{self.apex_domain}")
                        
                    attempt['records'] = zone_data
                    
                    # Add to subdomains
                    self.results['subdomains']['discovered'].extend(zone_data)
                    self.results['subdomains']['sources']['zone_transfer'] = zone_data
                    
                    self.print_status(f"Zone transfer SUCCESS on {ns}! Found {len(zone_data)} records", "warning")
                    
            except dns.exception.FormError:
                attempt['error'] = "REFUSED"
            except Exception as e:
                attempt['error'] = str(e)
            
            self.results['dns']['zone_transfer_attempts'].append(attempt)
        
        successful = sum(1 for a in self.results['dns']['zone_transfer_attempts'] if a['success'])
        if successful == 0 and self.config.verbose:
            self.print_status("No zone transfers allowed (expected)", "info")
    
    def _get_caa_records(self):
        """Get CAA records"""
        if not self.apex_domain:
            return
        
        try:
            self._rate_limit()
            answers = dns.resolver.resolve(self.apex_domain, 'CAA')
            caa_records = []
            for rdata in answers:
                caa_records.append({
                    'flags': rdata.flags,
                    'tag': rdata.tag,
                    'value': rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value)
                })
            self.results['dns']['caa_records'] = caa_records
            if self.config.verbose and caa_records:
                self.print_status(f"CAA records: {len(caa_records)} found", "info")
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            if self.config.verbose:
                self.results['errors'].append(f"CAA lookup failed: {str(e)}")
    
    def _check_wildcard_dns(self):
        """Check for wildcard DNS"""
        if not self.domain:
            return
        
        import random
        import string
        random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        test_domain = f"{random_sub}.{self.domain}"
        
        try:
            self._rate_limit()
            answers = dns.resolver.resolve(test_domain, 'A')
            if answers:
                wildcard_ips = [str(rdata) for rdata in answers]
                self.results['dns']['wildcard_dns'] = wildcard_ips
                self.print_status(f"Wildcard DNS detected: {', '.join(wildcard_ips[:3])}", "warning")
        except:
            self.results['dns']['wildcard_dns'] = None
    
    # ==================== WHOIS & Infrastructure ====================
    
    def whois_reconnaissance(self):
        """Comprehensive WHOIS reconnaissance"""
        self.print_status("Gathering WHOIS intelligence...", "progress")
        
        target = self.apex_domain if self.apex_domain else self.target
        
        try:
            self._rate_limit()
            w = whois.whois(target)
            
            whois_data = {}
            for key, value in w.items():
                if value and value != []:
                    if isinstance(value, list):
                        whois_data[key] = [str(v) for v in value]
                    else:
                        whois_data[key] = str(value)
            
            self.results['basic_info']['whois'] = whois_data
            
            # Extract emails
            if 'emails' in whois_data:
                emails = whois_data['emails']
                if isinstance(emails, list):
                    self.results['osint']['emails'].extend(emails)
                else:
                    self.results['osint']['emails'].append(emails)
            
            # Extract registrar
            if 'registrar' in whois_data:
                self.results['infrastructure']['hosting']['registrar'] = whois_data['registrar']
            
            self.print_status("WHOIS data collected", "success")
            
        except Exception as e:
            self.results['errors'].append(f"WHOIS lookup failed: {str(e)}")
    
    def infrastructure_reconnaissance(self):
        """Infrastructure and ASN reconnaissance"""
        self.print_status("Mapping infrastructure...", "progress")
        
        if not self.ip_address:
            return
        
        # ASN lookup
        self._asn_lookup()
        
        # Cloud provider detection
        self._detect_cloud_provider()
        
        # CDN detection
        self._detect_cdn()
        
        self.print_status("Infrastructure mapping completed", "success")
    
    def _asn_lookup(self):
        """ASN information lookup"""
        if not self.ip_address:
            return
        
        try:
            # Simple ASN lookup using DNS
            ip_parts = self.ip_address.split('.')
            reverse_ip = '.'.join(reversed(ip_parts))
            query = f"{reverse_ip}.origin.asn.cymru.com"
            
            self._rate_limit()
            answers = dns.resolver.resolve(query, 'TXT')
            
            for rdata in answers:
                data = str(rdata).strip('"').split('|')
                if len(data) >= 5:
                    self.results['infrastructure']['asn'] = {
                        'asn': data[0].strip(),
                        'ip': data[1].strip(),
                        'bgp_prefix': data[2].strip(),
                        'country': data[3].strip(),
                        'registry': data[4].strip()
                    }
                    
                    if self.config.verbose:
                        self.print_status(f"ASN: {data[0].strip()}", "info")
                    break
        except Exception as e:
            if self.config.verbose:
                self.results['errors'].append(f"ASN lookup failed: {str(e)}")
    
    def _detect_cloud_provider(self):
        """Detect cloud provider"""
        if not self.ip_address:
            return
        
        # Cloud IP ranges (simplified)
        cloud_ranges = {
            'AWS': ['52.', '54.', '35.'],
            'Azure': ['13.', '40.', '52.'],
            'GCP': ['34.', '35.'],
            'Cloudflare': ['104.', '172.'],
            'Akamai': ['23.']
        }
        
        for provider, prefixes in cloud_ranges.items():
            if any(self.ip_address.startswith(p) for p in prefixes):
                self.results['infrastructure']['cloud_provider'] = provider
                if self.config.verbose:
                    self.print_status(f"Cloud provider: {provider}", "info")
                break
    
    def _detect_cdn(self):
        """Detect CDN"""
        cname_records = self.results['dns']['records'].get('CNAME', [])
        
        cdn_indicators = {
            'Cloudflare': ['cloudflare'],
            'Akamai': ['akamai', 'edgekey'],
            'Fastly': ['fastly'],
            'CloudFront': ['cloudfront'],
            'MaxCDN': ['maxcdn'],
            'Incapsula': ['incapsula']
        }
        
        for cname in cname_records:
            cname_lower = str(cname).lower()
            for cdn, indicators in cdn_indicators.items():
                if any(ind in cname_lower for ind in indicators):
                    self.results['infrastructure']['cdn'] = cdn
                    if self.config.verbose:
                        self.print_status(f"CDN detected: {cdn}", "info")
                    return
    
    # ==================== Subdomain Enumeration ====================
    
    def subdomain_enumeration(self):
        """Comprehensive subdomain enumeration - no filtering"""
        self.print_status("Starting comprehensive subdomain enumeration...", "progress")
        
        if not self.domain:
            return
        
        # Multiple sources
        self._subdomain_bruteforce()
        self._subdomain_certspotter()
        self._subdomain_crtsh()
        self._subdomain_securitytrails()
        self._subdomain_virustotal()
        self._subdomain_urlscan()
        
        # Remove duplicates
        self.results['subdomains']['discovered'] = list(set(self.results['subdomains']['discovered']))
        
        # Verify if requested
        if not self.config.skip_verify:
            self._verify_subdomains()
        
        total = len(self.results['subdomains']['discovered'])
        verified = len(self.results['subdomains']['verified'])
        
        if self.config.skip_verify:
            self.print_status(f"Found {total} subdomains (verification skipped)", "success")
        else:
            self.print_status(f"Found {total} subdomains ({verified} verified alive)", "success")
    
    def _subdomain_bruteforce(self):
        """Bruteforce common subdomains"""
        if self.config.verbose:
            self.print_status("Bruteforcing common subdomains...", "info")
        
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns', 'm', 'imap', 'test',
            'ns3', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns4',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
            'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns5', 'dns', 'search', 'staging',
            'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads',
            'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download',
            'remote', 'db', 'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live',
            'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4', 'dashboard', 'git'
        ]
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{self.domain}"
            try:
                self._rate_limit()
                answers = dns.resolver.resolve(subdomain, 'A')
                if answers:
                    return subdomain
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            results = executor.map(check_subdomain, common_subs)
            
        found = [r for r in results if r]
        self.results['subdomains']['discovered'].extend(found)
        self.results['subdomains']['sources']['bruteforce'] = found
    
    def _subdomain_crtsh(self):
        """Query crt.sh certificate transparency"""
        if self.config.verbose:
            self.print_status("Querying crt.sh...", "info")
        
        try:
            self._rate_limit()
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                found = []
                for entry in data:
                    name = entry.get('name_value', '')
                    for domain in name.split('\n'):
                        domain = domain.strip().replace('*.', '')
                        if domain.endswith(self.domain) and not domain.startswith('.'):
                            found.append(domain)
                
                found = list(set(found))
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['crtsh'] = found
                
                if self.config.verbose and found:
                    self.print_status(f"crt.sh: {len(found)} subdomains", "success")
        except:
            pass
    
    def _subdomain_certspotter(self):
        """Query CertSpotter"""
        if self.config.verbose:
            self.print_status("Querying CertSpotter...", "info")
        
        try:
            self._rate_limit()
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                found = []
                for entry in data:
                    for name in entry.get('dns_names', []):
                        name = name.replace('*.', '')
                        if name.endswith(self.domain) and not name.startswith('.'):
                            found.append(name)
                
                found = list(set(found))
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['certspotter'] = found
        except:
            pass
    
    def _subdomain_securitytrails(self):
        """Query SecurityTrails"""
        api_key = self.api_keys.get('securitytrails')
        if not api_key:
            return
        
        if self.config.verbose:
            self.print_status("Querying SecurityTrails...", "info")
        
        try:
            self._rate_limit()
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': api_key}
            response = self.session.get(url, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                found = [f"{sub}.{self.domain}" for sub in data.get('subdomains', [])]
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['securitytrails'] = found
                self.results['third_party']['securitytrails'] = data
        except:
            pass
    
    def _subdomain_virustotal(self):
        """Query VirusTotal"""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return
        
        if self.config.verbose:
            self.print_status("Querying VirusTotal...", "info")
        
        try:
            self._rate_limit()
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            headers = {'x-apikey': api_key}
            response = self.session.get(url, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                found = [item.get('id') for item in data.get('data', []) if item.get('id')]
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['virustotal'] = found
        except:
            pass
    
    def _subdomain_urlscan(self):
        """Query URLScan.io"""
        if self.config.verbose:
            self.print_status("Querying URLScan.io...", "info")
        
        try:
            self._rate_limit()
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                found = []
                for result in data.get('results', []):
                    page_domain = result.get('page', {}).get('domain', '')
                    if page_domain.endswith(self.domain):
                        found.append(page_domain)
                
                found = list(set(found))
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['urlscan'] = found
        except:
            pass
    
    def _verify_subdomains(self):
        """Simple verification - just check if alive"""
        total = len(self.results['subdomains']['discovered'])
        if total == 0:
            return
        
        self.print_status(f"Verifying {total} subdomains...", "progress")
        
        def check_subdomain(subdomain):
            if self.config.verbose:
                print(f"  Checking: {subdomain:<50}", end='\r')
            
            for protocol in ['https', 'http']:
                try:
                    self._rate_limit()
                    url = f"{protocol}://{subdomain}"
                    response = self.session.get(url, timeout=8, allow_redirects=True)
                    
                    return {
                        'domain': subdomain,
                        'protocol': protocol,
                        'status_code': response.status_code,
                        'final_url': response.url,
                        'ip': socket.gethostbyname(subdomain),
                        'server': response.headers.get('Server', 'Unknown')
                    }
                except:
                    continue
            return None
        
        checked = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            results = executor.map(check_subdomain, self.results['subdomains']['discovered'])
            
            for result in results:
                checked += 1
                if not self.config.verbose and checked % 10 == 0:
                    print(f"  Progress: {checked}/{total}...", end='\r')
                
                if result:
                    self.results['subdomains']['verified'].append(result)
        
        print()
    
    # ==================== Technology Detection ====================
    
    def technology_detection(self):
        """Detect technologies"""
        self.print_status("Detecting technologies...", "progress")
        
        target_url = self._get_target_url()
        if not target_url:
            return
        
        try:
            self._rate_limit()
            response = self.session.get(target_url, timeout=self.config.timeout)
            
            # Headers
            for header, value in response.headers.items():
                self.results['technologies']['headers'][header] = value
                
                # Technology detection
                header_lower = header.lower()
                if header_lower == 'server':
                    self.results['technologies']['detected']['Web Server'] = value
                elif header_lower == 'x-powered-by':
                    self.results['technologies']['detected']['Backend'] = value
            
            # Body analysis
            html = response.text
            
            # CMS detection
            cms_indicators = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Joomla': ['/components/com_'],
                'Drupal': ['Drupal.settings'],
                'Magento': ['Mage.Cookies']
            }
            
            for cms, indicators in cms_indicators.items():
                if any(ind in html for ind in indicators):
                    self.results['technologies']['detected']['CMS'] = cms
            
            # JavaScript libraries
            js_libs = {
                'jQuery': r'jquery[.-]([0-9.]+)',
                'React': r'react[.-]([0-9.]+)',
                'Angular': r'angular[.-]([0-9.]+)',
                'Vue': r'vue[.-]([0-9.]+)'
            }
            
            for lib, pattern in js_libs.items():
                match = re.search(pattern, html, re.I)
                if match:
                    self.results['technologies']['javascript_libraries'].append({
                        'name': lib,
                        'version': match.group(1) if match.groups() else 'detected'
                    })
            
            self.print_status("Technology detection completed", "success")
            
        except Exception as e:
            self.results['errors'].append(f"Technology detection failed: {str(e)}")
    
    # ==================== OSINT Gathering ====================
    
    def osint_gathering(self):
        """Comprehensive OSINT gathering"""
        self.print_status("Gathering OSINT intelligence...", "progress")
        
        self._harvest_emails()
        self._search_github()
        self._hunter_io_lookup()
        self._google_dorking()
        
        self.print_status(f"OSINT: {len(self.results['osint']['emails'])} emails, {len(self.results['osint']['github_repos'])} repos", "success")
    
    def _harvest_emails(self):
        """Harvest emails"""
        target_url = self._get_target_url()
        if not target_url:
            return
        
        try:
            self._rate_limit()
            response = self.session.get(target_url, timeout=self.config.timeout)
            
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, response.text)
            
            for email in emails:
                if self.domain in email:
                    self.results['osint']['emails'].append(email.lower())
            
            self.results['osint']['emails'] = list(set(self.results['osint']['emails']))
        except:
            pass
    
    def _search_github(self):
        """Search GitHub"""
        api_key = self.api_keys.get('github')
        if not api_key:
            return
        
        if self.config.verbose:
            self.print_status("Searching GitHub...", "info")
        
        try:
            self._rate_limit()
            headers = {
                'Authorization': f'token {api_key}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            url = f"https://api.github.com/search/code?q={self.domain}"
            response = self.session.get(url, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', [])[:10]:
                    self.results['osint']['code_mentions'].append({
                        'repository': item['repository']['full_name'],
                        'path': item['path'],
                        'url': item['html_url']
                    })
        except:
            pass
    
    def _hunter_io_lookup(self):
        """Hunter.io lookup"""
        api_key = self.api_keys.get('hunter')
        if not api_key or not self.domain:
            return
        
        if self.config.verbose:
            self.print_status("Querying Hunter.io...", "info")
        
        try:
            self._rate_limit()
            url = f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={api_key}"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                for email_info in data.get('data', {}).get('emails', []):
                    email = email_info.get('value')
                    if email:
                        self.results['osint']['emails'].append(email.lower())
                        
                        if email_info.get('first_name') and email_info.get('last_name'):
                            self.results['osint']['employees'].append({
                                'name': f"{email_info['first_name']} {email_info['last_name']}",
                                'email': email,
                                'position': email_info.get('position')
                            })
                
                self.results['third_party']['hunter_io'] = data.get('data', {})
        except:
            pass
    
    def _google_dorking(self):
        """Generate useful Google dorks"""
        if not self.domain:
            return
        
        dorks = [
            f'site:{self.domain} ext:pdf',
            f'site:{self.domain} ext:doc | ext:docx',
            f'site:{self.domain} ext:xls | ext:xlsx',
            f'site:{self.domain} inurl:admin',
            f'site:{self.domain} inurl:login',
            f'site:{self.domain} intitle:"index of"',
            f'site:{self.domain} inurl:wp-content',
            f'site:{self.domain} inurl:api',
            f'site:{self.domain} filetype:env',
            f'site:{self.domain} filetype:sql'
        ]
        
        self.results['osint']['google_dorks'] = dorks
    
    # ==================== Third-Party APIs ====================
    
    def third_party_intelligence(self):
        """Gather intelligence from third-party APIs"""
        self.print_status("Querying third-party intelligence sources...", "progress")
        
        self._query_shodan()
        self._query_censys()
        self._query_virustotal_domain()
        
        self.print_status("Third-party intelligence collected", "success")
    
    def _query_shodan(self):
        """Query Shodan"""
        api_key = self.api_keys.get('shodan')
        if not api_key:
            return
        
        if self.config.verbose:
            self.print_status("Querying Shodan...", "info")
        
        try:
            import shodan
            api = shodan.Shodan(api_key)
            
            target = self.ip_address if self.ip_address else self.domain
            result = api.host(target)
            
            self.results['third_party']['shodan'] = {
                'ip': result.get('ip_str'),
                'organization': result.get('org'),
                'os': result.get('os'),
                'ports': result.get('ports', []),
                'vulnerabilities': result.get('vulns', []),
                'hostnames': result.get('hostnames', []),
                'domains': result.get('domains', []),
                'services': result.get('data', [])
            }
            
            # Add hostnames to subdomains
            for hostname in result.get('hostnames', []):
                if hostname.endswith(self.domain):
                    self.results['subdomains']['discovered'].append(hostname)
                    
        except ImportError:
            pass
        except Exception as e:
            if self.config.verbose:
                self.results['errors'].append(f"Shodan failed: {str(e)}")
    
    def _query_censys(self):
        """Query Censys"""
        api_key = self.api_keys.get('censys')
        if not api_key:
            return
        
        if self.config.verbose:
            self.print_status("Querying Censys...", "info")
        
        try:
            self._rate_limit()
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Accept': 'application/json'
            }
            
            if self.ip_address:
                url = f"https://search.censys.io/api/v2/hosts/{self.ip_address}"
                response = self.session.get(url, headers=headers, timeout=20)
                
                if response.status_code == 200:
                    data = response.json()
                    self.results['third_party']['censys'] = data.get('result', {})
        except:
            pass
    
    def _query_virustotal_domain(self):
        """Query VirusTotal for domain reputation"""
        api_key = self.api_keys.get('virustotal')
        if not api_key or not self.domain:
            return
        
        try:
            self._rate_limit()
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
            headers = {'x-apikey': api_key}
            response = self.session.get(url, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                self.results['third_party']['virustotal'] = {
                    'reputation': attributes.get('reputation'),
                    'last_analysis_stats': attributes.get('last_analysis_stats'),
                    'categories': attributes.get('categories')
                }
        except:
            pass
    
    # ==================== Historical Data ====================
    
    def historical_intelligence(self):
        """Gather historical intelligence"""
        self.print_status("Gathering historical intelligence...", "progress")
        
        self._wayback_machine()
        
        self.print_status("Historical intelligence collected", "success")
    
    def _wayback_machine(self):
        """Query Wayback Machine"""
        if not self.domain:
            return
        
        try:
            self._rate_limit()
            url = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&limit=100"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:  # First row is headers
                    snapshots = []
                    for row in data[1:]:
                        if len(row) >= 3:
                            snapshots.append({
                                'timestamp': row[1],
                                'url': row[2],
                                'status': row[4] if len(row) > 4 else None
                            })
                    
                    self.results['historical']['wayback_snapshots'] = snapshots[:50]
                    
                    if self.config.verbose and snapshots:
                        self.print_status(f"Wayback: {len(snapshots)} snapshots found", "info")
        except:
            pass
    
    # ==================== Web Analysis ====================
    
    def web_content_analysis(self):
        """Analyze web content"""
        self.print_status("Analyzing web content...", "progress")
        
        target_url = self._get_target_url()
        if not target_url:
            return
        
        try:
            self._rate_limit()
            response = self.session.get(target_url, timeout=self.config.timeout)
            
            # Extract JS files
            js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']\s*>'
            js_files = re.findall(js_pattern, response.text, re.I)
            self.results['web_analysis']['js_files'] = [urljoin(target_url, js) for js in js_files]
            
            # Extract endpoints
            url_pattern = r'(?:href|src)=["\']([^"\']+)["\']'
            urls = re.findall(url_pattern, response.text, re.I)
            for url in urls:
                if url.startswith(('http://', 'https://', '/')):
                    full_url = urljoin(target_url, url)
                    if self.domain in full_url:
                        self.results['web_analysis']['endpoints'].append(full_url)
            
            # Extract forms
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, response.text, re.DOTALL | re.I)
            for form in forms:
                action = re.search(r'action=["\']([^"\']+)["\']', form, re.I)
                method = re.search(r'method=["\']([^"\']+)["\']', form, re.I)
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form, re.I)
                
                self.results['web_analysis']['forms'].append({
                    'action': action.group(1) if action else None,
                    'method': method.group(1) if method else 'GET',
                    'inputs': inputs
                })
            
            # Check robots.txt
            self._check_robots_txt()
            
            self.print_status("Web content analysis completed", "success")
            
        except Exception as e:
            self.results['errors'].append(f"Web analysis failed: {str(e)}")
    
    def _check_robots_txt(self):
        """Check robots.txt"""
        target_url = self._get_target_url()
        if not target_url:
            return
        
        try:
            robots_url = urljoin(target_url, '/robots.txt')
            self._rate_limit()
            response = self.session.get(robots_url, timeout=5)
            
            if response.status_code == 200:
                self.results['web_analysis']['robots_txt'] = response.text[:1000]
        except:
            pass
    
    # ==================== Security Analysis ====================
    
    def security_analysis(self):
        """Security analysis"""
        self.print_status("Performing security analysis...", "progress")
        
        target_url = self._get_target_url()
        if not target_url:
            return
        
        try:
            self._rate_limit()
            response = self.session.get(target_url, timeout=self.config.timeout)
            
            # Security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy'
            }
            
            for header, description in security_headers.items():
                self.results['security']['headers'][description] = {
                    'present': header in response.headers,
                    'value': response.headers.get(header)
                }
            
            # TLS analysis
            self._analyze_tls(target_url)
            
            # WAF detection
            self._detect_waf(response)
            
            self.print_status("Security analysis completed", "success")
            
        except Exception as e:
            self.results['errors'].append(f"Security analysis failed: {str(e)}")
    
    def _analyze_tls(self, url):
        """Analyze TLS/SSL"""
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            return
        
        hostname = parsed.hostname
        port = parsed.port or 443
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.results['security']['tls_info'] = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'certificate': {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'notBefore': cert['notBefore'],
                            'notAfter': cert['notAfter'],
                            'subjectAltName': cert.get('subjectAltName', [])
                        }
                    }
        except:
            pass
    
    def _detect_waf(self, response):
        """Detect WAF"""
        waf_indicators = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'AWS WAF': ['x-amzn-', 'awselb'],
            'Akamai': ['akamai', 'x-akamai'],
            'Imperva': ['incap_ses', 'visid_incap'],
            'F5 BIG-IP': ['BigIP', 'F5']
        }
        
        headers_str = str(response.headers).lower()
        
        for waf, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator.lower() in headers_str:
                    self.results['security']['waf_detected'] = waf
                    return
    
    # ==================== Utility Methods ====================
    
    def _get_target_url(self) -> Optional[str]:
        """Get a valid target URL"""
        if self.domain:
            return f"https://{self.domain}"
        elif self.ip_address:
            return f"http://{self.ip_address}"
        return None
    
    # ==================== Report Generation ====================
    
    def generate_report(self):
        """Generate comprehensive reports"""
        self.print_status("Generating comprehensive reports...", "progress")
        
        # Update metadata
        self.results['metadata']['scan_end'] = datetime.now().isoformat()
        self.results['metadata']['duration'] = str(
            datetime.fromisoformat(self.results['metadata']['scan_end']) -
            datetime.fromisoformat(self.results['metadata']['scan_start'])
        )
        
        # Clean up data types
        self._serialize_results()
        
        # Generate reports
        json_file = self._generate_json_report()
        txt_file = self._generate_txt_report()
        html_file = self._generate_html_report()
        
        # Print summary
        self._print_summary()
        
        print(f"\n{Fore.GREEN}📁 Reports generated:{Style.RESET_ALL}")
        print(f"  • JSON: {json_file}")
        print(f"  • TXT:  {txt_file}")
        print(f"  • HTML: {html_file}")
    
    def _serialize_results(self):
        """Convert to JSON-serializable formats"""
        # Convert lists to avoid duplicates
        self.results['osint']['emails'] = list(set(self.results['osint']['emails']))
        self.results['subdomains']['discovered'] = list(set(self.results['subdomains']['discovered']))
    
    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        scan_id = self.results['metadata']['scan_id']
        filename = f"{self.config.output_dir}/recon_{self.target.replace('/', '_')}_{scan_id}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, indent=2, fp=f, default=str)
        
        return filename
    
    def _generate_txt_report(self) -> str:
        """Generate text report"""
        scan_id = self.results['metadata']['scan_id']
        filename = f"{self.config.output_dir}/recon_{self.target.replace('/', '_')}_{scan_id}.txt"
        
        with open(filename, 'w') as f:
            f.write("="*70 + "\n")
            f.write("PURE RECONNAISSANCE REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan ID: {scan_id}\n")
            f.write(f"Duration: {self.results['metadata'].get('duration', 'N/A')}\n\n")
            
            # DNS
            f.write("-"*70 + "\n")
            f.write("DNS INTELLIGENCE\n")
            f.write("-"*70 + "\n")
            f.write(f"Apex Domain: {self.apex_domain}\n")
            f.write(f"Nameservers: {len(self.results['dns']['nameservers'])}\n")
            f.write(f"MX Records: {len(self.results['dns']['mx_records'])}\n")
            f.write(f"DNSSEC: {'Enabled' if self.results['dns']['dnssec']['enabled'] else 'Disabled'}\n")
            f.write(f"Zone Transfer Attempts: {len(self.results['dns']['zone_transfer_attempts'])}\n\n")
            
            # Subdomains
            f.write("-"*70 + "\n")
            f.write("SUBDOMAIN INTELLIGENCE\n")
            f.write("-"*70 + "\n")
            f.write(f"Total Discovered: {len(self.results['subdomains']['discovered'])}\n")
            f.write(f"Verified Alive: {len(self.results['subdomains']['verified'])}\n\n")
            
            for sub in sorted(self.results['subdomains']['discovered'])[:100]:
                f.write(f"  • {sub}\n")
            
            # OSINT
            f.write("\n" + "-"*70 + "\n")
            f.write("OSINT INTELLIGENCE\n")
            f.write("-"*70 + "\n")
            f.write(f"Emails: {len(self.results['osint']['emails'])}\n")
            f.write(f"Employees: {len(self.results['osint']['employees'])}\n")
            f.write(f"GitHub Mentions: {len(self.results['osint']['code_mentions'])}\n\n")
            
            for email in sorted(self.results['osint']['emails'])[:50]:
                f.write(f"  • {email}\n")
        
        return filename
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        scan_id = self.results['metadata']['scan_id']
        filename = f"{self.config.output_dir}/recon_{self.target.replace('/', '_')}_{scan_id}.html"
        
        # Stats
        total_subs = len(self.results['subdomains']['discovered'])
        verified_subs = len(self.results['subdomains']['verified'])
        emails = len(self.results['osint']['emails'])
        technologies = len(self.results['technologies']['detected'])
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Recon Report - {self.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; text-align: center; }}
        .container {{ max-width: 1200px; margin: 20px auto; padding: 0 20px; }}
        .card {{ background: white; border-radius: 12px; padding: 25px; margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .metric {{ text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }}
        .metric-value {{ font-size: 36px; font-weight: bold; color: #667eea; }}
        .metric-label {{ color: #666; font-size: 14px; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th {{ background: #f8f9fa; padding: 12px; text-align: left; border-bottom: 2px solid #dee2e6; }}
        td {{ padding: 10px; border-bottom: 1px solid #eee; }}
        .list {{ list-style: none; max-height: 400px; overflow-y: auto; }}
        .list li {{ padding: 8px; border-bottom: 1px solid #eee; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-danger {{ background: #f8d7da; color: #721c24; }}
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .badge-info {{ background: #d1ecf1; color: #0c5460; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Pure Reconnaissance Report</h1>
        <p style="font-size: 1.2em; margin-top: 10px;">Target: {self.target}</p>
        <p>Scan ID: {scan_id} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="container">
        <div class="card">
            <h2>📊 Intelligence Summary</h2>
            <div class="metrics">
                <div class="metric">
                    <div class="metric-value">{total_subs}</div>
                    <div class="metric-label">Subdomains Discovered</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{verified_subs}</div>
                    <div class="metric-label">Verified Alive</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{emails}</div>
                    <div class="metric-label">Email Addresses</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{technologies}</div>
                    <div class="metric-label">Technologies</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🌐 DNS Intelligence</h2>
            <p><strong>Apex Domain:</strong> {self.apex_domain}</p>
            <p><strong>Nameservers:</strong> {len(self.results['dns']['nameservers'])}</p>
            <p><strong>MX Records:</strong> {len(self.results['dns']['mx_records'])}</p>
            <p><strong>DNSSEC:</strong> {'Enabled' if self.results['dns']['dnssec']['enabled'] else 'Disabled'}</p>
            <p><strong>Zone Transfer Attempts:</strong> {len(self.results['dns']['zone_transfer_attempts'])}</p>
        </div>
        
        <div class="card">
            <h2>🔗 Subdomain Intelligence</h2>
            <p><strong>Total:</strong> {total_subs} | <strong>Verified:</strong> {verified_subs}</p>
            <ul class="list">
"""
        
        for sub in sorted(self.results['subdomains']['discovered'])[:100]:
            html += f"<li>{sub}</li>\n"
        
        html += """
            </ul>
        </div>
    </div>
</body>
</html>"""
        
        with open(filename, 'w') as f:
            f.write(html)
        
        return filename
    
    def _print_summary(self):
        """Print final summary"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}RECONNAISSANCE COMPLETE")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}Intelligence Gathered:{Style.RESET_ALL}")
        print(f"  • Subdomains: {len(self.results['subdomains']['discovered'])} ({len(self.results['subdomains']['verified'])} verified)")
        print(f"  • Email Addresses: {len(self.results['osint']['emails'])}")
        print(f"  • Employees: {len(self.results['osint']['employees'])}")
        print(f"  • Technologies: {len(self.results['technologies']['detected'])}")
        print(f"  • DNS Records: {sum(len(v) if isinstance(v, list) else 1 for v in self.results['dns']['records'].values())}")
        print(f"  • Nameservers: {len(self.results['dns']['nameservers'])}")
        print(f"  • MX Records: {len(self.results['dns']['mx_records'])}")
        print(f"  • Zone Transfers: {sum(1 for a in self.results['dns']['zone_transfer_attempts'] if a['success'])}/{len(self.results['dns']['zone_transfer_attempts'])}")
        
        if self.results['security'].get('waf_detected'):
            print(f"\n{Fore.YELLOW}🛡️  WAF: {self.results['security']['waf_detected']}{Style.RESET_ALL}")
        
        if self.results['errors']:
            print(f"\n{Fore.YELLOW}⚠️  Errors: {len(self.results['errors'])}{Style.RESET_ALL}")
    
    # ==================== Main Execution ====================
    
    def run(self):
        """Run comprehensive reconnaissance"""
        try:
            self.print_banner()
            
            # Core reconnaissance
            self.dns_reconnaissance()
            self.whois_reconnaissance()
            self.infrastructure_reconnaissance()
            
            # Intelligence gathering
            self.subdomain_enumeration()
            self.technology_detection()
            self.osint_gathering()
            
            # Third-party intelligence
            self.third_party_intelligence()
            
            # Historical data
            self.historical_intelligence()
            
            # Security analysis
            self.security_analysis()
            
            # Web content analysis
            self.web_content_analysis()
            
        except KeyboardInterrupt:
            self.print_status("Scan interrupted by user", "warning")
        except Exception as e:
            self.print_status(f"Scan error: {e}", "error")
            if self.config.verbose:
                import traceback
                traceback.print_exc()
        finally:
            self.generate_report()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Pure Web Reconnaissance Tool v4.0 - Comprehensive Intelligence Gathering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 %(prog)s example.com
  python3 %(prog)s business.tiktok.com -v
  python3 %(prog)s example.com -t 20 --skip-verify
  python3 %(prog)s example.com --proxy http://proxy:8080
        """
    )
    
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0.5, help='Delay between requests (default: 0.5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('-o', '--output', default='./recon_output', help='Output directory')
    parser.add_argument('--rate-limit', type=int, default=10, help='Rate limit (default: 10)')
    parser.add_argument('--skip-verify', action='store_true', help='Skip subdomain verification')
    
    args = parser.parse_args()
    
    config = ReconConfig(
        target=args.target,
        verbose=args.verbose,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent if args.user_agent else ReconConfig.user_agent,
        output_dir=args.output,
        rate_limit=args.rate_limit,
        skip_verify=args.skip_verify
    )
    
    recon = PureWebRecon(config)
    recon.run()


if __name__ == "__main__":
    main()
