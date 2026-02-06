#!/usr/bin/env python3
"""
Enhanced Web Application Reconnaissance Tool v5.1 - Deep Recon Edition
Comprehensive intelligence gathering for authorized penetration testing
Focus: Maximum depth of data collection across all recon vectors

Features: DNS, Subdomains, OSINT, Port Scanning, Content Discovery,
          Technology Detection, Security Analysis, Third-Party APIs

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
import subprocess
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
    port_scan: bool = True
    content_discovery: bool = True


class DeepWebRecon:
    """Deep reconnaissance - maximum intelligence gathering"""
    
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
                'wildcard_dns': None,
                'spf_records': [],
                'dmarc_records': []
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
            'ports': {
                'open': [],
                'services': {},
                'banners': {}
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
                'interesting_files': [],
                'robots_txt': None,
                'sitemap': None
            },
            'content_discovery': {
                'found': [],
                'interesting': []
            },
            'parameters': {
                'discovered': [],
                'reflected': []
            },
            'third_party': {
                'shodan': {},
                'censys': {},
                'virustotal': {},
                'securitytrails': {},
                'hunter_io': {},
                'urlscan': {},
                'alienvault': {},
                'threatcrowd': {},
                'hackertarget': {}
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
            "info": ("[*]", Fore.CYAN),
            "success": ("[+]", Fore.GREEN),
            "warning": ("[!]", Fore.YELLOW),
            "error": ("[-]", Fore.RED),
            "progress": ("[~]", Fore.BLUE)
        }
        symbol, color = symbols.get(status, ("[.]", Fore.WHITE))
        try:
            print(f"{color}{symbol} {message}{Style.RESET_ALL}")
        except UnicodeEncodeError:
            print(f"{symbol} {message}")
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""{Fore.CYAN}
+===============================================================+
|                                                               |
|   Deep Reconnaissance Tool v5.1                               |
|   Maximum Intelligence Gathering                              |
|                                                               |
|   Target: {self.target:<50} |
|   Scan ID: {self.results['metadata']['scan_id']:<48} |
|                                                               |
+===============================================================+
{Style.RESET_ALL}"""
        try:
            print(banner)
        except UnicodeEncodeError:
            print(f"\n[Deep Recon v5.1] Target: {self.target} | Scan ID: {self.results['metadata']['scan_id']}\n")
        
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
        
        # SPF and DMARC
        self._get_email_security_records()
        
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
    
    def _get_email_security_records(self):
        """Get SPF and DMARC records"""
        if not self.apex_domain:
            return
        
        # SPF Records
        try:
            self._rate_limit()
            answers = dns.resolver.resolve(self.apex_domain, 'TXT')
            for rdata in answers:
                txt_str = str(rdata).strip('"')
                if txt_str.startswith('v=spf1'):
                    self.results['dns']['spf_records'].append(txt_str)
        except:
            pass
        
        # DMARC Records
        try:
            self._rate_limit()
            dmarc_domain = f"_dmarc.{self.apex_domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_str = str(rdata).strip('"')
                if txt_str.startswith('v=DMARC1'):
                    self.results['dns']['dmarc_records'].append(txt_str)
        except:
            pass
    
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

        # Reverse DNS for IP range
        self._reverse_dns_enumeration()

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
            'AWS': ['52.', '54.', '35.', '3.', '18.'],
            'Azure': ['13.', '40.', '52.', '104.'],
            'GCP': ['34.', '35.', '104.'],
            'Cloudflare': ['104.', '172.'],
            'Akamai': ['23.'],
            'DigitalOcean': ['159.', '167.', '178.', '188.'],
            'Linode': ['45.', '50.', '66.', '69.', '96.', '139.', '170.', '172.']
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
            'Incapsula': ['incapsula'],
            'Sucuri': ['sucuri'],
            'StackPath': ['stackpath']
        }

        for cname in cname_records:
            cname_lower = str(cname).lower()
            for cdn, indicators in cdn_indicators.items():
                if any(ind in cname_lower for ind in indicators):
                    self.results['infrastructure']['cdn'] = cdn
                    if self.config.verbose:
                        self.print_status(f"CDN detected: {cdn}", "info")
                    return

    def _reverse_dns_enumeration(self):
        """Enumerate nearby IPs via reverse DNS"""
        if not self.ip_address:
            return

        if self.config.verbose:
            self.print_status("Performing reverse DNS enumeration...", "info")

        # Get the /24 range
        ip_parts = self.ip_address.split('.')
        if len(ip_parts) != 4:
            return

        base_ip = '.'.join(ip_parts[:3])
        reverse_dns_results = []

        # Check a sample of IPs in the same /24
        sample_ips = [1, 2, 5, 10, 50, 100, 200, 254]

        def check_reverse_dns(last_octet):
            ip = f"{base_ip}.{last_octet}"
            try:
                reverse_name = dns.reversename.from_address(ip)
                answers = dns.resolver.resolve(reverse_name, 'PTR', lifetime=3)
                for rdata in answers:
                    hostname = str(rdata).rstrip('.')
                    return {'ip': ip, 'hostname': hostname}
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = executor.map(check_reverse_dns, sample_ips)

        for result in results:
            if result:
                reverse_dns_results.append(result)
                # Add hostname to subdomains if related
                if self.domain and result['hostname'].endswith(self.domain):
                    self.results['subdomains']['discovered'].append(result['hostname'])

        self.results['infrastructure']['reverse_dns'] = reverse_dns_results

        if self.config.verbose and reverse_dns_results:
            self.print_status(f"Reverse DNS: {len(reverse_dns_results)} hostnames found", "info")

    # ==================== Port Scanning ====================
    
    def port_scanning(self):
        """Comprehensive port scanning"""
        if not self.config.port_scan:
            return
            
        self.print_status("Starting port scanning...", "progress")
        
        if not self.ip_address:
            self.print_status("No IP address available for port scanning", "warning")
            return
        
        # Common ports
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 
            993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 
            8443, 8888, 9090, 9200, 9300, 27017, 27018, 28017
        ]
        
        self._scan_ports(common_ports)
        
        # Service detection on open ports
        if self.results['ports']['open']:
            self._detect_services()
        
        self.print_status(f"Port scan complete: {len(self.results['ports']['open'])} open ports", "success")
    
    def _scan_ports(self, ports):
        """Scan specific ports"""
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.ip_address, port))
                sock.close()
                
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(scan_port, ports)
        
        self.results['ports']['open'] = sorted([p for p in results if p])
    
    def _detect_services(self):
        """Detect services on open ports"""
        for port in self.results['ports']['open']:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.ip_address, port))
                
                # Send HTTP request for web ports
                if port in [80, 443, 8000, 8080, 8443, 8888, 9090]:
                    sock.send(b"GET / HTTP/1.0\r\n\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                if banner:
                    self.results['ports']['banners'][port] = banner[:200]
                    
                    # Extract service
                    service = self._identify_service(banner, port)
                    self.results['ports']['services'][port] = service
            except:
                pass
    
    def _identify_service(self, banner, port):
        """Identify service from banner"""
        banner_lower = banner.lower()
        
        services = {
            'ssh': 'SSH',
            'http': 'HTTP',
            'ftp': 'FTP',
            'smtp': 'SMTP',
            'mysql': 'MySQL',
            'postgresql': 'PostgreSQL',
            'mongodb': 'MongoDB',
            'redis': 'Redis',
            'elasticsearch': 'Elasticsearch'
        }
        
        for key, name in services.items():
            if key in banner_lower:
                return {'name': name, 'banner': banner}
        
        # Port-based detection
        port_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        
        if port in port_services:
            return {'name': port_services[port], 'banner': banner}
        
        return {'name': 'Unknown', 'banner': banner}
    
    # ==================== Subdomain Enumeration ====================
    
    def subdomain_enumeration(self):
        """Comprehensive subdomain enumeration"""
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
        self._subdomain_rapiddns()
        self._subdomain_alienvault()
        self._subdomain_hackertarget()
        self._subdomain_threatcrowd()
        self._subdomain_dnsdumpster()
        
        # Try external tools if available
        self._subdomain_amass()
        self._subdomain_subfinder()
        
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
            'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4', 'dashboard', 'git',
            'jenkins', 'jira', 'confluence', 'gitlab', 'bitbucket', 'docker', 'kubernetes',
            'k8s', 'grafana', 'prometheus', 'elk', 'kibana', 'splunk', 'nagios', 'zabbix'
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
    
    def _subdomain_rapiddns(self):
        """Query RapidDNS for subdomains"""
        if self.config.verbose:
            self.print_status("Querying RapidDNS...", "info")
        
        try:
            self._rate_limit()
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                pattern = r'<td>([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')</td>'
                found = list(set(re.findall(pattern, response.text, re.I)))
                
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['rapiddns'] = found
                
                if self.config.verbose and found:
                    self.print_status(f"RapidDNS: {len(found)} subdomains", "success")
        except:
            pass
    
    def _subdomain_alienvault(self):
        """Query AlienVault OTX"""
        if self.config.verbose:
            self.print_status("Querying AlienVault OTX...", "info")
        
        try:
            self._rate_limit()
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                found = []
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname', '')
                    if hostname.endswith(self.domain):
                        found.append(hostname)
                
                found = list(set(found))
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['alienvault'] = found
                self.results['third_party']['alienvault'] = data
                
                if self.config.verbose and found:
                    self.print_status(f"AlienVault: {len(found)} subdomains", "success")
        except:
            pass
    
    def _subdomain_hackertarget(self):
        """Query HackerTarget"""
        if self.config.verbose:
            self.print_status("Querying HackerTarget...", "info")
        
        try:
            self._rate_limit()
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                found = []
                for line in response.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain.endswith(self.domain):
                            found.append(subdomain)
                
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['hackertarget'] = found
                self.results['third_party']['hackertarget'] = {'count': len(found)}
                
                if self.config.verbose and found:
                    self.print_status(f"HackerTarget: {len(found)} subdomains", "success")
        except:
            pass
    
    def _subdomain_threatcrowd(self):
        """Query ThreatCrowd"""
        if self.config.verbose:
            self.print_status("Querying ThreatCrowd...", "info")
        
        try:
            self._rate_limit()
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                found = data.get('subdomains', [])
                
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['threatcrowd'] = found
                self.results['third_party']['threatcrowd'] = data
                
                if self.config.verbose and found:
                    self.print_status(f"ThreatCrowd: {len(found)} subdomains", "success")
        except:
            pass
    
    def _subdomain_dnsdumpster(self):
        """Query DNSDumpster"""
        if self.config.verbose:
            self.print_status("Querying DNSDumpster...", "info")
        
        try:
            self._rate_limit()
            # DNSDumpster requires CSRF token handling
            session = requests.Session()
            url = "https://dnsdumpster.com/"
            
            # Get CSRF token
            response = session.get(url, timeout=20)
            csrf_token = re.search(r'name=\'csrfmiddlewaretoken\' value=\'(.+?)\'', response.text)
            
            if csrf_token:
                token = csrf_token.group(1)
                
                # Submit search
                data = {
                    'csrfmiddlewaretoken': token,
                    'targetip': self.domain,
                    'user': 'free'
                }
                
                headers = {
                    'Referer': url,
                    'User-Agent': self.config.user_agent
                }
                
                response = session.post(url, data=data, headers=headers, timeout=20)
                
                if response.status_code == 200:
                    # Extract subdomains from HTML
                    pattern = r'<td class="col-md-4">([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')<br>'
                    found = list(set(re.findall(pattern, response.text, re.I)))
                    
                    self.results['subdomains']['discovered'].extend(found)
                    self.results['subdomains']['sources']['dnsdumpster'] = found
                    
                    if self.config.verbose and found:
                        self.print_status(f"DNSDumpster: {len(found)} subdomains", "success")
        except:
            pass
    
    def _subdomain_amass(self):
        """Use Amass via subprocess if installed"""
        if self.config.verbose:
            self.print_status("Running Amass...", "info")
        
        try:
            result = subprocess.run(
                ['amass', 'enum', '-passive', '-d', self.domain, '-json', '/dev/stdout'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                found = []
                for line in result.stdout.strip().split('\n'):
                    try:
                        data = json.loads(line)
                        if 'name' in data:
                            found.append(data['name'])
                    except:
                        continue
                
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['amass'] = found
                
                if self.config.verbose and found:
                    self.print_status(f"Amass: {len(found)} subdomains", "success")
        except FileNotFoundError:
            if self.config.verbose:
                self.print_status("Amass not installed, skipping", "warning")
        except Exception as e:
            if self.config.verbose:
                self.results['errors'].append(f"Amass failed: {str(e)}")
    
    def _subdomain_subfinder(self):
        """Use Subfinder via subprocess if installed"""
        if self.config.verbose:
            self.print_status("Running Subfinder...", "info")
        
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.domain, '-silent', '-json'],
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if result.returncode == 0:
                found = []
                for line in result.stdout.strip().split('\n'):
                    try:
                        data = json.loads(line)
                        if 'host' in data:
                            found.append(data['host'])
                    except:
                        continue
                
                self.results['subdomains']['discovered'].extend(found)
                self.results['subdomains']['sources']['subfinder'] = found
                
                if self.config.verbose and found:
                    self.print_status(f"Subfinder: {len(found)} subdomains", "success")
        except FileNotFoundError:
            if self.config.verbose:
                self.print_status("Subfinder not installed, skipping", "warning")
        except Exception as e:
            if self.config.verbose:
                self.results['errors'].append(f"Subfinder failed: {str(e)}")
    
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
    
    # ==================== Content Discovery ====================
    
    def content_discovery(self):
        """Discover hidden content"""
        if not self.config.content_discovery:
            return
            
        self.print_status("Starting content discovery...", "progress")
        
        target_url = self._get_target_url()
        if not target_url:
            return
        
        # Common paths
        paths = [
            'admin', 'administrator', 'login', 'wp-admin', 'dashboard', 'portal',
            'api', 'v1', 'v2', 'v3', 'swagger', 'api-docs', 'docs', 'graphql',
            'test', 'dev', 'staging', 'backup', 'old', 'temp', 'tmp',
            '.git', '.env', '.htaccess', '.DS_Store', 'config.php', 'config.json',
            'backup.sql', 'database.sql', 'db.sql', 'dump.sql',
            'phpinfo.php', 'info.php', 'test.php',
            'admin.php', 'login.php', 'upload.php',
            'readme.md', 'README.md', 'CHANGELOG', 'VERSION',
            'server-status', 'server-info',
            's3', 'status', 'health', 'ping', 'metrics', 'actuator',
            'console', 'phpmyadmin', 'pma', 'adminer',
            'jenkins', 'tomcat', 'manager', 'jmx-console'
        ]
        
        # Common extensions
        extensions = ['', '.php', '.asp', '.aspx', '.jsp', '.html', '.txt', '.bak', '.old', '.zip', '.tar.gz']
        
        # Generate full list
        full_paths = []
        for path in paths:
            for ext in extensions:
                full_paths.append(f"/{path}{ext}")
        
        self._fuzz_paths(target_url, full_paths)
        
        self.print_status(f"Content discovery: {len(self.results['content_discovery']['found'])} paths found", "success")
    
    def _fuzz_paths(self, base_url, paths):
        """Fuzz paths"""
        def check_path(path):
            try:
                url = urljoin(base_url, path)
                self._rate_limit()
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 201, 204, 301, 302, 307, 308, 401, 403]:
                    return {
                        'path': path,
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.content),
                        'redirect': response.headers.get('Location')
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            results = executor.map(check_path, paths)
        
        for result in results:
            if result:
                self.results['content_discovery']['found'].append(result)
                
                # Mark interesting findings
                if result['status'] in [200, 403] and any(x in result['path'].lower() for x in ['admin', 'config', '.env', '.git', 'backup']):
                    self.results['content_discovery']['interesting'].append(result)
    
    # ==================== Parameter Discovery ====================
    
    def parameter_discovery(self):
        """Discover URL parameters"""
        self.print_status("Discovering parameters...", "progress")
        
        target_url = self._get_target_url()
        if not target_url:
            return
        
        # Common parameters
        params = [
            'id', 'page', 'search', 'q', 'query', 'keyword', 'lang', 'language',
            'file', 'path', 'url', 'redirect', 'return', 'callback', 'debug',
            'user', 'username', 'email', 'token', 'api_key', 'key',
            'sort', 'order', 'limit', 'offset', 'start', 'end',
            'filter', 'category', 'type', 'format', 'output', 'view',
            'action', 'mode', 'module', 'controller', 'method'
        ]
        
        self._test_parameters(target_url, params)
        
        self.print_status(f"Found {len(self.results['parameters']['discovered'])} parameters", "success")
    
    def _test_parameters(self, url, params):
        """Test parameters"""
        for param in params:
            try:
                test_value = 'xss_test_123'
                test_url = f"{url}?{param}={test_value}"
                
                self._rate_limit()
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    self.results['parameters']['discovered'].append(param)
                    
                    # Check if reflected
                    if test_value in response.text:
                        self.results['parameters']['reflected'].append({
                            'param': param,
                            'url': test_url
                        })
            except:
                pass
    
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
                'WordPress': ['wp-content', 'wp-includes', '/wp-json/'],
                'Joomla': ['/components/com_', 'Joomla!'],
                'Drupal': ['Drupal.settings', '/sites/default/'],
                'Magento': ['Mage.Cookies', '/skin/frontend/'],
                'Shopify': ['cdn.shopify.com', 'myshopify.com'],
                'Wix': ['wix.com', 'parastorage'],
                'Squarespace': ['squarespace.com']
            }
            
            for cms, indicators in cms_indicators.items():
                if any(ind in html for ind in indicators):
                    self.results['technologies']['detected']['CMS'] = cms
                    break
            
            # JavaScript frameworks
            js_frameworks = {
                'React': ['react', '_react'],
                'Angular': ['ng-version', 'angular'],
                'Vue.js': ['vue', 'v-if', 'v-for'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap']
            }
            
            for framework, indicators in js_frameworks.items():
                if any(ind in html.lower() for ind in indicators):
                    if 'JavaScript Framework' not in self.results['technologies']['detected']:
                        self.results['technologies']['detected']['JavaScript Framework'] = []
                    self.results['technologies']['detected']['JavaScript Framework'].append(framework)
            
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
        self._detect_social_media()

        self.print_status(f"OSINT: {len(self.results['osint']['emails'])} emails, {len(self.results['osint']['code_mentions'])} code mentions", "success")
    
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
            f'site:{self.domain} filetype:sql',
            f'site:{self.domain} inurl:config',
            f'site:{self.domain} ext:log',
            f'site:{self.domain} intitle:"Dashboard" inurl:dashboard',
            f'site:{self.domain} intext:"api key" | intext:"api_key"'
        ]
        
        self.results['osint']['google_dorks'] = dorks

    def _detect_social_media(self):
        """Detect social media profiles"""
        if not self.domain:
            return

        if self.config.verbose:
            self.print_status("Searching for social media profiles...", "info")

        # Extract company/brand name from domain
        brand = self.domain.split('.')[0]

        social_platforms = {
            'twitter': f'https://twitter.com/{brand}',
            'linkedin': f'https://www.linkedin.com/company/{brand}',
            'facebook': f'https://www.facebook.com/{brand}',
            'instagram': f'https://www.instagram.com/{brand}',
            'github': f'https://github.com/{brand}',
            'youtube': f'https://www.youtube.com/@{brand}'
        }

        for platform, url in social_platforms.items():
            try:
                self._rate_limit()
                response = self.session.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    self.results['osint']['social_media'][platform] = {
                        'url': url,
                        'exists': True
                    }
            except:
                pass

    # ==================== Third-Party APIs ====================
    
    def third_party_intelligence(self):
        """Gather intelligence from third-party APIs"""
        self.print_status("Querying third-party intelligence sources...", "progress")
        
        self._query_shodan()
        self._query_censys()
        self._query_virustotal_domain()
        
        self.print_status("Third-party intelligence collected", "success")
    
    def _query_shodan(self):
        """Query Shodan via API"""
        api_key = self.api_keys.get('shodan')
        if not api_key:
            return

        if self.config.verbose:
            self.print_status("Querying Shodan...", "info")

        target = self.ip_address if self.ip_address else self.domain

        try:
            # Use requests API directly for consistency
            self._rate_limit()
            url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
            response = self.session.get(url, timeout=20)

            if response.status_code == 200:
                result = response.json()

                self.results['third_party']['shodan'] = {
                    'ip': result.get('ip_str'),
                    'organization': result.get('org'),
                    'os': result.get('os'),
                    'ports': result.get('ports', []),
                    'vulnerabilities': result.get('vulns', []),
                    'hostnames': result.get('hostnames', []),
                    'domains': result.get('domains', []),
                    'services': [
                        {
                            'port': svc.get('port'),
                            'transport': svc.get('transport'),
                            'product': svc.get('product'),
                            'version': svc.get('version')
                        } for svc in result.get('data', [])[:10]
                    ]
                }

                # Add hostnames to subdomains
                if self.domain:
                    for hostname in result.get('hostnames', []):
                        if hostname.endswith(self.domain):
                            self.results['subdomains']['discovered'].append(hostname)

                if self.config.verbose:
                    self.print_status(f"Shodan: {len(result.get('ports', []))} ports found", "success")

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
            
            # Extract comments
            comments = re.findall(r'<!--(.*?)-->', response.text, re.DOTALL)
            self.results['web_analysis']['comments'] = [c.strip()[:200] for c in comments if c.strip()]
            
            # Check robots.txt
            self._check_robots_txt()

            # Check sitemap
            self._check_sitemap()

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
                self.results['web_analysis']['robots_txt'] = response.text[:2000]
        except:
            pass
    
    def _check_sitemap(self):
        """Check sitemap.xml"""
        target_url = self._get_target_url()
        if not target_url:
            return

        try:
            sitemap_url = urljoin(target_url, '/sitemap.xml')
            self._rate_limit()
            response = self.session.get(sitemap_url, timeout=5)

            if response.status_code == 200:
                # Extract URLs from sitemap
                urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                self.results['web_analysis']['sitemap'] = urls[:100]
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
                    
                    # Extract subdomains from cert
                    for alt_name in cert.get('subjectAltName', []):
                        if alt_name[0] == 'DNS':
                            domain_name = alt_name[1].replace('*.', '')
                            if domain_name.endswith(self.domain):
                                self.results['subdomains']['discovered'].append(domain_name)
        except:
            pass
    
    def _detect_waf(self, response):
        """Detect WAF"""
        waf_indicators = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'AWS WAF': ['x-amzn-', 'awselb'],
            'Akamai': ['akamai', 'x-akamai'],
            'Imperva': ['incap_ses', 'visid_incap'],
            'F5 BIG-IP': ['BigIP', 'F5'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'Wordfence': ['wordfence']
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
        """Generate JSON report"""
        self.print_status("Generating report...", "progress")

        # Update metadata
        self.results['metadata']['scan_end'] = datetime.now().isoformat()
        self.results['metadata']['duration'] = str(
            datetime.fromisoformat(self.results['metadata']['scan_end']) -
            datetime.fromisoformat(self.results['metadata']['scan_start'])
        )

        # Clean up data
        self._serialize_results()

        # Generate JSON report
        json_file = self._generate_json_report()

        # Print summary
        self._print_summary()

        print(f"\n{Fore.GREEN}[+] Report saved: {json_file}{Style.RESET_ALL}")
    
    def _serialize_results(self):
        """Convert to JSON-serializable formats"""
        # Convert lists to avoid duplicates
        self.results['osint']['emails'] = list(set(self.results['osint']['emails']))
        self.results['subdomains']['discovered'] = list(set(self.results['subdomains']['discovered']))
    
    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        scan_id = self.results['metadata']['scan_id']
        filename = f"{self.config.output_dir}/recon_{self.target.replace('/', '_')}_{scan_id}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, indent=2, fp=f, default=str)

        return filename

    def _print_summary(self):
        """Print final summary"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}DEEP RECONNAISSANCE COMPLETE")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}Intelligence Gathered:{Style.RESET_ALL}")
        print(f"  - Subdomains: {len(self.results['subdomains']['discovered'])} ({len(self.results['subdomains']['verified'])} verified)")
        print(f"  - Open Ports: {len(self.results['ports']['open'])}")
        print(f"  - Content Discovered: {len(self.results['content_discovery']['found'])}")
        print(f"  - Email Addresses: {len(self.results['osint']['emails'])}")
        print(f"  - Employees: {len(self.results['osint']['employees'])}")
        print(f"  - Technologies: {len(self.results['technologies']['detected'])}")
        print(f"  - Parameters: {len(self.results['parameters']['discovered'])}")

        if self.results['security'].get('waf_detected'):
            print(f"\n{Fore.YELLOW}[!] WAF: {self.results['security']['waf_detected']}{Style.RESET_ALL}")

        if self.results['errors']:
            print(f"\n{Fore.YELLOW}[!] Errors: {len(self.results['errors'])}{Style.RESET_ALL}")
    
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
            
            # Deep analysis
            self.port_scanning()
            self.content_discovery()
            self.parameter_discovery()
            
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
        description='Deep Web Reconnaissance Tool v5.1 - Maximum Intelligence Gathering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 %(prog)s example.com
  python3 %(prog)s business.tiktok.com -v
  python3 %(prog)s example.com -t 20 --skip-verify
  python3 %(prog)s example.com --no-ports --no-content
  python3 %(prog)s example.com --proxy http://127.0.0.1:8080
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
    parser.add_argument('--no-ports', action='store_false', dest='port_scan', help='Skip port scanning')
    parser.add_argument('--no-content', action='store_false', dest='content_discovery', help='Skip content discovery')
    
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
        skip_verify=args.skip_verify,
        port_scan=args.port_scan,
        content_discovery=args.content_discovery
    )
    
    recon = DeepWebRecon(config)
    recon.run()


if __name__ == "__main__":
    main()
