# Recon-Tools
Performs recon for web applications
# Enhanced Web Reconnaissance Tool v3.0

Advanced web application reconnaissance tool for authorized security testing and bug bounty hunting.

## 🔑 API Keys Required

The tool supports multiple third-party services for enhanced reconnaissance. While the tool works without API keys (using only passive techniques), adding API keys significantly improves results.

### Required API Keys (Environment Variables)

#### **Optional but Recommended:**

1. **Shodan** (`SHODAN_API_KEY`)
   - Get at: https://account.shodan.io/
   - Free tier: 100 queries/month
   - Used for: Infrastructure enumeration, open ports, vulnerabilities
   - Priority: **HIGH**

2. **SecurityTrails** (`SECURITYTRAILS_API_KEY`)
   - Get at: https://securitytrails.com/
   - Free tier: 50 queries/month
   - Used for: Historical DNS data, subdomains
   - Priority: **HIGH**

3. **VirusTotal** (`VT_API_KEY`)
   - Get at: https://www.virustotal.com/gui/join-us
   - Free tier: 500 queries/day
   - Used for: Domain reputation, subdomains, related domains
   - Priority: **MEDIUM**

4. **Hunter.io** (`HUNTER_API_KEY`)
   - Get at: https://hunter.io/api
   - Free tier: 50 searches/month
   - Used for: Email discovery, employee information
   - Priority: **MEDIUM**

5. **GitHub** (`GITHUB_TOKEN`)
   - Get at: https://github.com/settings/tokens
   - Free: Unlimited (with rate limits)
   - Used for: Code search, exposed secrets
   - Priority: **MEDIUM**

6. **Censys** (`CENSYS_API_SECRET`)
   - Get at: https://censys.io/register
   - Free tier: 250 queries/month
   - Used for: Certificate data, infrastructure enumeration
   - Priority: **LOW**

7. **BinaryEdge** (`BINARYEDGE_API_KEY`)
   - Get at: https://app.binaryedge.io/sign-up
   - Free tier: 250 queries/month
   - Used for: Port scanning, service detection
   - Priority: **LOW**

8. **FullHunt** (`FULLHUNT_API_KEY`)
   - Get at: https://fullhunt.io/
   - Free tier available
   - Used for: Attack surface discovery
   - Priority: **LOW**

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
export BINARYEDGE_API_KEY="your_binaryedge_key_here"
export FULLHUNT_API_KEY="your_fullhunt_key_here"

# Reload shell
source ~/.bashrc  # or source ~/.zshrc
```

#### Windows (PowerShell):
```powershell
$env:SHODAN_API_KEY="your_shodan_key_here"
$env:SECURITYTRAILS_API_KEY="your_securitytrails_key_here"
$env:VT_API_KEY="your_virustotal_key_here"
$env:HUNTER_API_KEY="your_hunter_key_here"
$env:GITHUB_TOKEN="your_github_token_here"
```

#### Or use a .env file:
```bash
# Create .env file
cat > .env << EOF
SHODAN_API_KEY=your_shodan_key_here
SECURITYTRAILS_API_KEY=your_securitytrails_key_here
VT_API_KEY=your_virustotal_key_here
HUNTER_API_KEY=your_hunter_key_here
GITHUB_TOKEN=your_github_token_here
CENSYS_API_SECRET=your_censys_token_here
BINARYEDGE_API_KEY=your_binaryedge_key_here
FULLHUNT_API_KEY=your_fullhunt_key_here
EOF

# Load with:
export $(cat .env | xargs)
```

## 📦 Installation

### Requirements
- Python 3.8+
- pip

### Install Dependencies

```bash
# Install required packages
pip install -r requirements.txt
```

### requirements.txt
```txt
requests>=2.28.0
dnspython>=2.3.0
python-whois>=0.8.0
colorama>=0.4.6
aiohttp>=3.8.0
urllib3>=1.26.0
shodan>=1.28.0
```

### Quick Install
```bash
pip install requests dnspython python-whois colorama aiohttp shodan
```

## 🚀 Usage

### Basic Usage
```bash
# Scan a domain
python3 enhanced_web_recon_v3.py example.com

# Scan with verbose output
python3 enhanced_web_recon_v3.py example.com -v

# Scan an IP address
python3 enhanced_web_recon_v3.py 192.168.1.1
```

### Advanced Usage
```bash
# Use 20 threads with 1 second delay
python3 enhanced_web_recon_v3.py example.com -t 20 -d 1

# Use a proxy
python3 enhanced_web_recon_v3.py example.com --proxy http://127.0.0.1:8080

# Custom output directory
python3 enhanced_web_recon_v3.py example.com -o /tmp/recon

# Custom User-Agent
python3 enhanced_web_recon_v3.py example.com --user-agent "Mozilla/5.0..."

# Full scan with all options
python3 enhanced_web_recon_v3.py example.com -v -t 15 -d 0.3 --timeout 15 -o ./results
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
```

## 🔍 Features

### Core Reconnaissance Modules

#### 1. **DNS Enumeration**
- Forward and reverse DNS lookups
- All DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Zone transfer vulnerability testing
- DNSSEC validation

#### 2. **Subdomain Discovery**
- Bruteforce common subdomains
- Certificate transparency logs (crt.sh, CertSpotter)
- Third-party API integration (SecurityTrails, VirusTotal)
- Subdomain verification (alive/dead checking)

#### 3. **Technology Detection**
- CMS identification (WordPress, Joomla, Drupal, etc.)
- Web framework detection (Laravel, Django, Rails, etc.)
- JavaScript library identification (jQuery, React, Vue, etc.)
- Server and backend technology fingerprinting

#### 4. **Security Analysis**
- Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- TLS/SSL certificate examination
- WAF detection (Cloudflare, AWS WAF, Akamai, etc.)
- CORS misconfiguration checking

#### 5. **OSINT Gathering**
- Email address harvesting
- Employee information discovery
- Social media profile identification
- GitHub code search
- Certificate transparency monitoring

#### 6. **Web Content Analysis**
- Endpoint discovery
- JavaScript file extraction
- API endpoint identification
- Form discovery and analysis
- Interesting file detection (robots.txt, .git, backups, etc.)
- HTML comment extraction

#### 7. **Third-Party Intelligence**
- Shodan integration (infrastructure, ports, vulnerabilities)
- VirusTotal reputation checks
- SecurityTrails historical data
- Hunter.io email discovery

## 📊 Output Formats

The tool generates three types of reports:

1. **JSON Report** - Machine-readable full data
   - File: `recon_<target>_<scan_id>.json`
   - Contains all collected data in structured format

2. **HTML Report** - Human-readable visual report
   - File: `recon_<target>_<scan_id>.html`
   - Beautiful web interface with charts and tables
   - Open in browser for best viewing

3. **Text Report** - Simple text summary
   - File: `recon_<target>_<scan_id>.txt`
   - Quick overview of findings

All reports are saved in the output directory (default: `./recon_output/`)

## 🎯 Use Cases

### Bug Bounty Hunting
```bash
# Comprehensive scan for bug bounty
python3 enhanced_web_recon_v3.py target.com -v -t 15
```

### Penetration Testing
```bash
# Detailed scan through proxy (e.g., Burp Suite)
python3 enhanced_web_recon_v3.py target.com --proxy http://127.0.0.1:8080 -v
```

### Security Assessments
```bash
# Professional assessment with custom rate limiting
python3 enhanced_web_recon_v3.py target.com -t 20 --rate-limit 5 -o ./client_reports
```

### CTF Competitions
```bash
# Fast scan with minimal delay
python3 enhanced_web_recon_v3.py ctf.example.com -t 30 -d 0.1
```

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is for authorized security testing only.

- Only use on systems you own or have explicit permission to test
- Unauthorized scanning may be illegal in your jurisdiction
- The author is not responsible for misuse of this tool
- Always follow responsible disclosure practices
- Respect rate limits and terms of service of third-party APIs

## 🛡️ Ethical Usage Guidelines

1. **Get Permission**: Always obtain written authorization before testing
2. **Respect Scope**: Stay within the agreed-upon scope of testing
3. **Be Considerate**: Use appropriate delays to avoid DoS conditions
4. **Report Findings**: Responsibly disclose any vulnerabilities found
5. **Protect Data**: Handle discovered information with care

## 🔧 Troubleshooting

### Common Issues

**"Module not found" errors:**
```bash
pip install -r requirements.txt
```

**SSL Certificate errors:**
- The tool disables SSL verification by default (for testing)
- If needed, modify `session.verify = True` in the code

**Rate limiting issues:**
```bash
# Increase delay between requests
python3 enhanced_web_recon_v3.py target.com -d 2
```

**API quota exceeded:**
- Check your API key quotas
- Use free tier limits wisely
- Consider upgrading to paid plans for heavy usage

**DNS resolution failures:**
- Check your internet connection
- Try using a different DNS server
- Some domains may have rate limiting

## 📈 Performance Tips

1. **Adjust threads based on target**: More threads = faster, but may trigger rate limits
2. **Use appropriate delays**: Faster scans may get blocked
3. **Enable only needed modules**: Comment out unused features for faster scans
4. **Use proxy for testing**: Route through Burp/ZAP for analysis
5. **API keys improve results**: More data sources = better intelligence

## 🤝 Contributing

This is a personal security research tool. Feel free to modify for your needs.

## 📝 Changelog

### v3.0 (2025)
- Complete rewrite with improved architecture
- Added async operations for better performance
- Enhanced API integration
- Better error handling and reporting
- Improved HTML report design
- Added more reconnaissance modules
- Better rate limiting and proxy support

### v2.0
- Added basic API integrations
- Improved subdomain enumeration
- Added technology detection

### v1.0
- Initial release
- Basic DNS and subdomain enumeration

## 📚 Resources

### Learning Resources
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Bug Bounty Methodology: https://www.bugbountyhunter.com/
- Penetration Testing: https://www.offensive-security.com/

### Related Tools
- Amass: https://github.com/OWASP/Amass
- Subfinder: https://github.com/projectdiscovery/subfinder
- Nuclei: https://github.com/projectdiscovery/nuclei
- httpx: https://github.com/projectdiscovery/httpx

## 📧 Contact

For security research collaboration or questions about ethical hacking, reach out through professional channels.

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
