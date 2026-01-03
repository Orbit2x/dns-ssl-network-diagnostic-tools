# DNS Lookup & SSL Certificate Checker - Network Diagnostic Tools

[![DNS Lookup](https://img.shields.io/badge/Try%20Online-DNS%20Lookup-blue)](https://orbit2x.com/lookup)
[![SSL Checker](https://img.shields.io/badge/Check-SSL%20Certificate-green)](https://orbit2x.com/ssl)
[![IP Lookup](https://img.shields.io/badge/Tool-IP%20Lookup-orange)](https://orbit2x.com/ip-lookup)

> **Troubleshooting network issues?** Use these free online tools: [DNS Lookup](https://orbit2x.com/lookup) • [SSL Checker](https://orbit2x.com/ssl) • [IP Lookup](https://orbit2x.com/ip-lookup) - No installation required!

## Quick Access - Free Online Tools

| Tool | Purpose | Link |
|------|---------|------|
| **DNS Lookup** | Query A, AAAA, MX, NS, TXT, SOA, CNAME records | [lookup](https://orbit2x.com/lookup) |
| **SSL Certificate Checker** | Verify SSL/TLS certificates, check expiration | [ssl](https://orbit2x.com/ssl) |
| **HTTP Headers Analyzer** | Analyze server headers, security, caching | [headers](https://orbit2x.com/headers) |
| **IP Address Lookup** | Geolocation, ISP, VPN/proxy detection | [ip-lookup](https://orbit2x.com/ip-lookup) |
| **Subnet Calculator** | Calculate CIDR, network ranges, subnet masks | [subnet](https://orbit2x.com/subnet) |
| **My IP Address** | View your public IP, location, ISP | [myip](https://orbit2x.com/myip) |
| **Domain Age Checker** | Check domain registration age, WHOIS data | [domain-age](https://orbit2x.com/domain-age) |
| **HTTP Status Checker** | Check website uptime, response codes | [http-status-checker](https://orbit2x.com/http-status-checker) |

---

## DNS Lookup - Command Line & Code Examples

### Using `dig` (Most Powerful)

```bash
# Install dig
sudo apt-get install dnsutils  # Ubuntu/Debian
brew install bind              # macOS

# Query A record (IPv4)
dig example.com A +short
# 93.184.216.34

# Query AAAA record (IPv6)
dig example.com AAAA +short
# 2606:2800:220:1:248:1893:25c8:1946

# Query MX records (Mail servers)
dig example.com MX +short
# 10 mail.example.com.

# Query NS records (Name servers)
dig example.com NS +short
# ns1.example.com.
# ns2.example.com.

# Query TXT records (SPF, DKIM, verification)
dig example.com TXT +short
# "v=spf1 include:_spf.google.com ~all"

# Query all records
dig example.com ANY

# Trace DNS resolution path
dig +trace example.com

# Query specific DNS server
dig @8.8.8.8 example.com

# Reverse DNS lookup (IP to domain)
dig -x 93.184.216.34
```

### Using `nslookup`

```bash
# Query A record
nslookup example.com

# Query specific record type
nslookup -type=MX example.com
nslookup -type=NS example.com
nslookup -type=TXT example.com

# Use specific DNS server
nslookup example.com 8.8.8.8
```

### Using `host`

```bash
# Simple A record lookup
host example.com
# example.com has address 93.184.216.34

# Query MX records
host -t MX example.com

# Query all records
host -a example.com

# Reverse lookup
host 93.184.216.34
```

### Python DNS Lookup

```bash
pip install dnspython
```

```python
import dns.resolver

# Query A records
answers = dns.resolver.resolve('example.com', 'A')
for rdata in answers:
    print('IP:', rdata.address)

# Query MX records
mx_records = dns.resolver.resolve('example.com', 'MX')
for mx in mx_records:
    print(f'Mail server: {mx.exchange} (priority: {mx.preference})')

# Query TXT records
txt_records = dns.resolver.resolve('example.com', 'TXT')
for txt in txt_records:
    print('TXT:', txt.to_text())

# Query with specific nameserver
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '8.8.4.4']
answers = resolver.resolve('example.com', 'A')
```

### Node.js DNS Lookup

```javascript
const dns = require('dns').promises;

// Query A records
async function lookupDNS(domain) {
  try {
    // A records (IPv4)
    const addresses = await dns.resolve4(domain);
    console.log('IPv4:', addresses);

    // AAAA records (IPv6)
    const ipv6 = await dns.resolve6(domain);
    console.log('IPv6:', ipv6);

    // MX records
    const mx = await dns.resolveMx(domain);
    console.log('MX:', mx);

    // TXT records
    const txt = await dns.resolveTxt(domain);
    console.log('TXT:', txt);

    // NS records
    const ns = await dns.resolveNs(domain);
    console.log('NS:', ns);

  } catch (err) {
    console.error('DNS lookup failed:', err);
  }
}

lookupDNS('example.com');
```

**Or use the web tool**: [DNS Lookup Online](https://orbit2x.com/lookup)

---

## SSL Certificate Verification

### Using `openssl` (Command Line)

```bash
# Check SSL certificate
openssl s_client -connect example.com:443 -servername example.com < /dev/null

# Show certificate details only
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -text

# Check certificate expiration
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -dates

# Get certificate chain
openssl s_client -showcerts -connect example.com:443 -servername example.com < /dev/null

# Check specific protocols
openssl s_client -tls1_2 -connect example.com:443
openssl s_client -tls1_3 -connect example.com:443

# Verify certificate with CA bundle
openssl s_client -connect example.com:443 -CAfile /etc/ssl/certs/ca-certificates.crt
```

### Bash Script - SSL Expiry Checker

```bash
#!/bin/bash
# Check SSL certificate expiration

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Get certificate expiry date
EXPIRY=$(echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>/dev/null | \
         openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

if [ -z "$EXPIRY" ]; then
    echo "❌ Failed to retrieve certificate for $DOMAIN"
    exit 1
fi

# Convert to Unix timestamp
EXPIRY_TIMESTAMP=$(date -d "$EXPIRY" +%s)
CURRENT_TIMESTAMP=$(date +%s)

# Calculate days until expiry
DAYS_UNTIL_EXPIRY=$(( ($EXPIRY_TIMESTAMP - $CURRENT_TIMESTAMP) / 86400 ))

echo "Domain: $DOMAIN"
echo "Expires: $EXPIRY"
echo "Days until expiry: $DAYS_UNTIL_EXPIRY"

if [ $DAYS_UNTIL_EXPIRY -lt 0 ]; then
    echo "⚠️ EXPIRED!"
elif [ $DAYS_UNTIL_EXPIRY -lt 30 ]; then
    echo "⚠️ Expires soon! Renew within 30 days"
else
    echo "✅ Certificate is valid"
fi
```

**Usage**:
```bash
chmod +x ssl-check.sh
./ssl-check.sh example.com
```

### Python SSL Checker

```python
import ssl
import socket
from datetime import datetime

def check_ssl_expiry(hostname, port=443):
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()

            # Get expiry date
            not_after = cert['notAfter']
            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')

            # Calculate days until expiry
            days_until_expiry = (expiry_date - datetime.now()).days

            print(f"Domain: {hostname}")
            print(f"Issuer: {cert['issuer']}")
            print(f"Subject: {cert['subject']}")
            print(f"Expires: {expiry_date}")
            print(f"Days until expiry: {days_until_expiry}")

            if days_until_expiry < 0:
                print("⚠️ EXPIRED!")
            elif days_until_expiry < 30:
                print("⚠️ Expires soon!")
            else:
                print("✅ Certificate is valid")

# Usage
check_ssl_expiry('example.com')
```

**Or use online tool**: [SSL Certificate Checker](https://orbit2x.com/ssl)

---

## Common DNS Record Types

| Record Type | Purpose | Example |
|-------------|---------|---------|
| **A** | IPv4 address | `example.com. 300 IN A 93.184.216.34` |
| **AAAA** | IPv6 address | `example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946` |
| **CNAME** | Canonical name (alias) | `www.example.com. IN CNAME example.com.` |
| **MX** | Mail exchange servers | `example.com. IN MX 10 mail.example.com.` |
| **TXT** | Text records (SPF, DKIM, verification) | `example.com. IN TXT "v=spf1 include:_spf.google.com ~all"` |
| **NS** | Name servers | `example.com. IN NS ns1.example.com.` |
| **SOA** | Start of authority | Contains primary nameserver, admin email |
| **PTR** | Reverse DNS (IP to domain) | `34.216.184.93.in-addr.arpa. IN PTR example.com.` |
| **SRV** | Service locator | Used for SIP, XMPP, LDAP services |
| **CAA** | Certificate Authority Authorization | Restrict which CAs can issue certificates |

**Look up any record type**: [DNS Lookup Tool](https://orbit2x.com/lookup)

---

## Troubleshooting Common DNS Issues

### Issue 1: DNS Not Resolving

```bash
# Check if DNS is working
dig google.com +short

# If no response, try different DNS servers
dig @8.8.8.8 google.com     # Google DNS
dig @1.1.1.1 google.com     # Cloudflare DNS
dig @208.67.222.222 google.com  # OpenDNS

# Check local DNS cache
sudo systemd-resolve --flush-caches  # Linux
sudo killall -HUP mDNSResponder      # macOS
ipconfig /flushdns                   # Windows
```

### Issue 2: Slow DNS Resolution

```bash
# Benchmark DNS servers
dig @8.8.8.8 google.com | grep "Query time"
dig @1.1.1.1 google.com | grep "Query time"

# Use fastest DNS server:
# Google: 8.8.8.8, 8.8.4.4
# Cloudflare: 1.1.1.1, 1.0.0.1
# OpenDNS: 208.67.222.222, 208.67.220.220
```

### Issue 3: DNS Propagation Check

```bash
# Check if DNS has propagated globally
dig @8.8.8.8 example.com A       # Google (USA)
dig @1.1.1.1 example.com A       # Cloudflare (Global)
dig @ns1.yourdomain.com example.com A  # Your authoritative NS

# Different results = Still propagating (can take 24-48 hours)
```

**Check propagation online**: [DNS Lookup Tool](https://orbit2x.com/lookup)

### Issue 4: Missing MX Records

```bash
# Check if email DNS is configured
dig example.com MX +short

# If empty, email won't work. Need to add MX records:
# Priority 10: mail.example.com
# Priority 20: mail2.example.com (backup)
```

### Issue 5: SPF/DKIM Not Set Up

```bash
# Check SPF record (prevents email spoofing)
dig example.com TXT | grep "v=spf1"

# Check DKIM record
dig default._domainkey.example.com TXT

# If missing, email may go to spam
```

---

## SSL/TLS Troubleshooting

### Common SSL Errors & Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| **NET::ERR_CERT_DATE_INVALID** | Certificate expired | Renew certificate (Let's Encrypt: 90 days) |
| **NET::ERR_CERT_COMMON_NAME_INVALID** | Wrong domain in cert | Regenerate for correct domain |
| **NET::ERR_CERT_AUTHORITY_INVALID** | Self-signed or untrusted CA | Use trusted CA (Let's Encrypt, DigiCert) |
| **SSL_ERROR_NO_CYPHER_OVERLAP** | Weak/outdated ciphers | Update server cipher suites |
| **ERR_SSL_VERSION_OR_CIPHER_MISMATCH** | Old TLS version | Enable TLS 1.2/1.3, disable TLS 1.0/1.1 |
| **ERR_SSL_PROTOCOL_ERROR** | Server misconfiguration | Check Apache/Nginx SSL config |

**Test SSL configuration**: [SSL Certificate Checker](https://orbit2x.com/ssl)

### Check SSL Strength

```bash
# Test SSL/TLS versions supported
nmap --script ssl-enum-ciphers -p 443 example.com

# Check SSL Labs grade (A+ is best)
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=example.com

# Or use our tool:
# https://orbit2x.com/ssl
```

---

## Network Diagnostic Scripts

### Complete Network Diagnostic Tool (Bash)

```bash
#!/bin/bash
# Complete network diagnostic tool

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

echo "========================================="
echo "Network Diagnostics for: $DOMAIN"
echo "========================================="

# 1. DNS Lookup
echo -e "\n[1] DNS LOOKUP"
echo "A records (IPv4):"
dig +short $DOMAIN A
echo "MX records (Mail):"
dig +short $DOMAIN MX
echo "NS records (Nameservers):"
dig +short $DOMAIN NS

# 2. Ping test
echo -e "\n[2] PING TEST"
ping -c 4 $DOMAIN

# 3. Traceroute
echo -e "\n[3] TRACEROUTE"
traceroute -m 15 $DOMAIN

# 4. HTTP Status
echo -e "\n[4] HTTP STATUS"
curl -I -s https://$DOMAIN | head -1

# 5. SSL Certificate
echo -e "\n[5] SSL CERTIFICATE"
echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>/dev/null | \
      openssl x509 -noout -dates -issuer -subject

# 6. Port Scan (common ports)
echo -e "\n[6] PORT SCAN"
nmap -F $DOMAIN

echo -e "\n========================================="
echo "Diagnostic complete!"
echo "========================================="
```

---

## Best DNS Servers (2024)

| Provider | Primary | Secondary | Speed | Privacy | Filtering |
|----------|---------|-----------|-------|---------|-----------|
| **Cloudflare** | 1.1.1.1 | 1.0.0.1 | ⚡⚡⚡ Fastest | ✅ No logging | ❌ No |
| **Google** | 8.8.8.8 | 8.8.4.4 | ⚡⚡ Fast | ⚠️ Logs queries | ❌ No |
| **Quad9** | 9.9.9.9 | 149.112.112.112 | ⚡⚡ Fast | ✅ No logging | ✅ Malware blocking |
| **OpenDNS** | 208.67.222.222 | 208.67.220.220 | ⚡ Good | ⚠️ Some logging | ✅ Customizable |
| **AdGuard** | 94.140.14.14 | 94.140.15.15 | ⚡ Good | ✅ No logging | ✅ Ad blocking |

**Change DNS (Linux)**:
```bash
# Edit /etc/resolv.conf
sudo nano /etc/resolv.conf

# Add:
nameserver 1.1.1.1
nameserver 1.0.0.1
```

**Change DNS (macOS)**:
```bash
# System Preferences → Network → Advanced → DNS
# Add: 1.1.1.1 and 1.0.0.1
```

---

## Tools & Resources

### Free Online Tools
- **[DNS Lookup](https://orbit2x.com/lookup)** - Query all DNS record types
- **[SSL Certificate Checker](https://orbit2x.com/ssl)** - Verify certificates, check expiry
- **[HTTP Headers Analyzer](https://orbit2x.com/headers)** - Analyze server headers
- **[IP Address Lookup](https://orbit2x.com/ip-lookup)** - Geolocation, ISP, security
- **[Subnet Calculator](https://orbit2x.com/subnet)** - CIDR, IP ranges
- **[My IP Address](https://orbit2x.com/myip)** - View your public IP
- **[Domain Age Checker](https://orbit2x.com/domain-age)** - WHOIS, registration date
- **[HTTP Status Checker](https://orbit2x.com/http-status-checker)** - Website uptime

### Command Line Tools
- **dig** - DNS lookup (most powerful)
- **nslookup** - Simple DNS queries
- **host** - Lightweight DNS tool
- **openssl** - SSL/TLS testing
- **curl** - HTTP client
- **nmap** - Port scanning
- **traceroute** - Network path tracing

### Libraries
- **Node.js**: `dns` module (built-in)
- **Python**: `dnspython`, `ssl` module
- **Go**: `net` package
- **PHP**: `dns_get_record()`

---

## FAQ

### Q: Why is my DNS not updating?
**A**: DNS propagation takes 24-48 hours globally. Check with: [DNS Lookup](https://orbit2x.com/lookup)

### Q: How do I check if my SSL certificate is valid?
**A**: Use [SSL Certificate Checker](https://orbit2x.com/ssl) - shows expiry, issuer, and errors

### Q: What DNS server should I use?
**A**:
- **Fastest**: Cloudflare (1.1.1.1)
- **Privacy**: Quad9 (9.9.9.9) or Cloudflare
- **Ad-blocking**: AdGuard (94.140.14.14)

### Q: How often should I renew SSL certificates?
**A**: Let's Encrypt: 90 days. Paid certs: 1 year. Auto-renew recommended.

### Q: Can I use free SSL certificates?
**A**: Yes! Let's Encrypt provides free, auto-renewable SSL certificates trusted by all browsers.

---

## Related Tools

- **[URL Redirect Checker](https://orbit2x.com/redirect-checker)** - Trace redirect chains
- **[Website Safety Checker](https://orbit2x.com/scam-detector)** - Detect phishing sites
- **[TLS Version Checker](https://orbit2x.com/tls-checker)** - Check TLS protocols
- **[All Network Tools](https://orbit2x.com/tools)** - Complete toolkit

---

**Made with ❤️ by [Orbit2x](https://orbit2x.com) - Free Network Diagnostic Tools**

**Try now**: [DNS Lookup](https://orbit2x.com/lookup) • [SSL Checker](https://orbit2x.com/ssl) • [IP Lookup](https://orbit2x.com/ip-lookup)
