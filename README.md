# Enhanced Web Reconnaissance Tool v5.1

Advanced web application reconnaissance tool for authorized security testing and bug bounty hunting.

## Features

### Core Reconnaissance Modules

#### 1. **DNS Intelligence**
- Forward and reverse DNS lookups
- All DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME, CAA)
- Nameservers and MX from apex domain
- Zone transfer vulnerability testing
- DNSSEC validation
- SPF and DMARC record analysis
- Wildcard DNS detection

#### 2. **Subdomain Discovery** (13+ Sources)
- Certificate transparency logs (crt.sh, CertSpotter)
- Bruteforce common subdomains
- SecurityTrails API
- VirusTotal API
- URLScan.io
- RapidDNS
- AlienVault OTX
- HackerTarget
- ThreatCrowd
- DNSDumpster
- External tools (Amass, Subfinder) if installed
- Subdomain verification with status codes

#### 3. **Infrastructure Mapping**
- ASN lookup via DNS
- Cloud provider detection (AWS, Azure, GCP, etc.)
- CDN detection (Cloudflare, Akamai, Fastly, etc.)
- Reverse DNS enumeration for IP ranges

#### 4. **Port Scanning**
- Common ports scanning (35+ ports)
- Service detection
- Banner grabbing

#### 5. **Technology Detection**
- CMS identification (WordPress, Joomla, Drupal, etc.)
- Web framework detection (React, Angular, Vue, etc.)
- JavaScript library identification
- Server and backend fingerprinting

#### 6. **Security Analysis**
- Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- TLS/SSL certificate examination
- WAF detection (Cloudflare, AWS WAF, Akamai, etc.)

#### 7. **OSINT Gathering**
- Email address harvesting
- Employee information discovery (Hunter.io)
- Social media profile detection
- GitHub code search
- Google dork generation

#### 8. **Web Content Analysis**
- Endpoint discovery
- Form discovery and analysis
- robots.txt and sitemap.xml parsing
- HTML comment extraction

#### 9. **Content Discovery**
- Common path fuzzing
- Backup file detection
- Admin panel discovery
- Configuration file detection

#### 10. **Parameter Discovery**
- Common parameter testing
- Reflection detection

#### 11. **Third-Party Intelligence**
- Shodan integration
- Censys integration
- VirusTotal reputation checks
- SecurityTrails historical data
- Hunter.io email discovery

#### 12. **Historical Intelligence**
- Wayback Machine snapshots

---

## API Keys (Optional but Recommended)

The tool works without API keys using passive techniques. Adding API keys significantly improves results.

### Supported APIs

| Service | Environment Variable | Free Tier | Priority |
|---------|---------------------|-----------|----------|
| Shodan | `SHODAN_API_KEY` | 100 queries/month | HIGH |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | 50 queries/month | HIGH |
| VirusTotal | `VT_API_KEY` | 500 queries/day | MEDIUM |
| Hunter.io | `HUNTER_API_KEY` | 50 searches/month | MEDIUM |
| GitHub | `GITHUB_TOKEN` | Unlimited (rate limited) | MEDIUM |
| Censys | `CENSYS_API_SECRET` | 250 queries/month | LOW |
| BinaryEdge | `BINARYEDGE_API_KEY` | 250 queries/month | LOW |
| FullHunt | `FULLHUNT_API_KEY` | Free tier available | LOW |

### Setting Up API Keys

#### Linux/Mac:
```bash
# Add to ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="your_shodan_key_here"
export SECURITYTRAILS_API_KEY="your_securitytrails_key_here"
export VT_API_KEY="your_virustotal_key_here"
export HUNTER_API_KEY="your_hunter_key_here"
export GITHUB_TOKEN="your_github_token_here"
export CENSYS_API_SECRET="your_censys_token_here"

# Reload shell
source ~/.bashrc
```

#### Windows (PowerShell):
```powershell
$env:SHODAN_API_KEY="your_shodan_key_here"
$env:SECURITYTRAILS_API_KEY="your_securitytrails_key_here"
$env:VT_API_KEY="your_virustotal_key_here"
$env:HUNTER_API_KEY="your_hunter_key_here"
$env:GITHUB_TOKEN="your_github_token_here"
```

#### Using .env file:
```bash
# Create .env file
cat > .env << EOF
SHODAN_API_KEY=your_shodan_key_here
SECURITYTRAILS_API_KEY=your_securitytrails_key_here
VT_API_KEY=your_virustotal_key_here
HUNTER_API_KEY=your_hunter_key_here
GITHUB_TOKEN=your_github_token_here
EOF

# Load with:
export $(cat .env | xargs)
```

---

## Installation

### Requirements
- Python 3.8+
- pip

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Quick Install
```bash
pip install requests dnspython python-whois colorama aiohttp
```

---

## Usage

### Basic Usage
```bash
# Scan a domain
python3 enhanced_recon_v5.py example.com

# Scan with verbose output
python3 enhanced_recon_v5.py example.com -v

# Scan an IP address
python3 enhanced_recon_v5.py 192.168.1.1
```

### Advanced Usage
```bash
# Use 20 threads with 1 second delay
python3 enhanced_recon_v5.py example.com -t 20 -d 1

# Use a proxy (e.g., Burp Suite)
python3 enhanced_recon_v5.py example.com --proxy http://127.0.0.1:8080

# Custom output directory
python3 enhanced_recon_v5.py example.com -o /tmp/recon

# Skip subdomain verification (faster)
python3 enhanced_recon_v5.py example.com --skip-verify

# Skip port scanning
python3 enhanced_recon_v5.py example.com --no-ports

# Skip content discovery
python3 enhanced_recon_v5.py example.com --no-content

# Full scan with all options
python3 enhanced_recon_v5.py example.com -v -t 15 -d 0.3 --timeout 15 -o ./results
```

### Command Line Options
```
positional arguments:
  target                Target domain or IP address

optional arguments:
  -h, --help            Show this help message and exit
  -v, --verbose         Enable verbose output
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)
  -d DELAY, --delay DELAY
                        Delay between requests in seconds (default: 0.5)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --proxy PROXY         Proxy URL (e.g., http://proxy:8080)
  --user-agent USER_AGENT
                        Custom User-Agent string
  -o OUTPUT, --output OUTPUT
                        Output directory (default: ./recon_output)
  --rate-limit RATE_LIMIT
                        Rate limit (requests per second, default: 10)
  --skip-verify         Skip subdomain verification
  --no-ports            Skip port scanning
  --no-content          Skip content discovery
```

---

## Output

Single JSON file containing all collected intelligence:

```
./recon_output/recon_<target>_<scan_id>.json
```

The JSON includes:
- Metadata (target, scan ID, duration)
- DNS records (A, AAAA, MX, NS, TXT, SOA, CAA, SPF, DMARC)
- WHOIS data
- Infrastructure (ASN, cloud provider, CDN)
- Subdomains (discovered + verified)
- Open ports and services
- Technologies detected
- OSINT (emails, employees, social media)
- Security headers and WAF detection
- Content discovery results
- Historical data (Wayback Machine)
- Third-party API data (Shodan, VirusTotal, etc.)

---

## Use Cases

### Bug Bounty Hunting
```bash
python3 enhanced_recon_v5.py target.com -v -t 15
```

### Penetration Testing (with Burp Suite)
```bash
python3 enhanced_recon_v5.py target.com --proxy http://127.0.0.1:8080 -v
```

### Security Assessments
```bash
python3 enhanced_recon_v5.py target.com -t 20 --rate-limit 5 -o ./client_reports
```

### CTF Competitions
```bash
python3 enhanced_recon_v5.py ctf.example.com -t 30 -d 0.1 --skip-verify
```

---

## Legal Disclaimer

**IMPORTANT:** This tool is for authorized security testing only.

- Only use on systems you own or have explicit permission to test
- Unauthorized scanning may be illegal in your jurisdiction
- The author is not responsible for misuse of this tool
- Always follow responsible disclosure practices
- Respect rate limits and terms of service of third-party APIs

---

## Ethical Usage Guidelines

1. **Get Permission**: Always obtain written authorization before testing
2. **Respect Scope**: Stay within the agreed-upon scope of testing
3. **Be Considerate**: Use appropriate delays to avoid DoS conditions
4. **Report Findings**: Responsibly disclose any vulnerabilities found
5. **Protect Data**: Handle discovered information with care

---

## Troubleshooting

### Common Issues

**"Module not found" errors:**
```bash
pip install -r requirements.txt
```

**SSL Certificate errors:**
- The tool disables SSL verification by default for testing purposes

**Rate limiting issues:**
```bash
python3 enhanced_recon_v5.py target.com -d 2
```

**API quota exceeded:**
- Check your API key quotas
- Consider upgrading to paid plans for heavy usage

**DNS resolution failures:**
- Check your internet connection
- Some domains may have rate limiting

---

## Performance Tips

1. **Adjust threads based on target**: More threads = faster, but may trigger rate limits
2. **Use appropriate delays**: Faster scans may get blocked
3. **Skip verification for large scopes**: Use `--skip-verify` for faster initial enumeration
4. **Use proxy for testing**: Route through Burp/ZAP for analysis
5. **API keys improve results**: More data sources = better intelligence

---

## Changelog

### v5.1 (2025)
- Added social media profile detection
- Added reverse DNS enumeration for IP ranges
- Improved Shodan integration (uses requests API directly)
- Better error handling

### v5.0 (2025)
- Deep recon edition with maximum intelligence gathering
- 13+ subdomain sources
- Port scanning and service detection
- Content and parameter discovery
- Enhanced third-party API integration

### v4.0 (2025)
- Pure reconnaissance philosophy
- Fixed DNS intelligence (apex domain handling)
- No scoring/filtering - collect everything

### v3.0 (2025)
- Complete rewrite with improved architecture
- Added async operations
- Enhanced API integration

---

## Related Tools

- Amass: https://github.com/OWASP/Amass
- Subfinder: https://github.com/projectdiscovery/subfinder
- Nuclei: https://github.com/projectdiscovery/nuclei
- httpx: https://github.com/projectdiscovery/httpx

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
