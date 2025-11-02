import whois
import socket
import ssl
import requests
from datetime import datetime
import json
import time
import pyfiglet
from colorama import init, Fore, Back, Style
import sys
import re
from urllib.parse import urlparse
import warnings
import threading
import random
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

# Initialize colorama
init(autoreset=True)

# ================ CONFIGURATION ================
# Get a free API key from https://virustotal.com
VT_API_KEY = "******"

# Optional: Get a free API key from https://ipinfo.io/ for richer IP data
IPINFO_API_KEY = """"""""""  # If empty, uses ip-api.com

# PhishTank API (no key required)
PHISHTANK_API = "http://checkurl.phishtank.com/checkurl/"

# Timeout settings (in seconds)
WHOIS_TIMEOUT = 15
SSL_TIMEOUT = 10
REQUEST_TIMEOUT = 10

# ================ KNOWN BAD DOMAINS DATABASE ================
KNOWN_BAD_DOMAINS = {
    "example-fake-bank.com", "phishing-site.xyz", "malware-download.com", 
    "free-bitcoin-scam.com", "fake-login-page.com", "credit-card-stealer.org",
    "paypal-phishing.com", "facebook-hack.ru", "instagram-login.xyz",
    "twitter-verify.com", "amazon-security-alert.com", "netflix-payment.com",
    "apple-id-verify.com", "microsoft-support.com", "bankofamerica-security.com",
    "wellsfargo-alert.com", "chase-verify.com", "citi-bank-security.com",
    "ebay-phishing.com", "paypal-security.com", "whatsapp-hack.com"
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".loan", ".download", ".gq", ".ml", ".cf", ".tk", ".pw", ".icu"}

FREE_HOSTING_DOMAINS = {
    "000webhostapp.com", "github.io", "herokuapp.com", "netlify.app", 
    "vercel.app", "firebaseapp.com", "awsapps.com", "web.app",
    "blogspot.com", "wordpress.com", "tumblr.com", "weebly.com"
}

# ================ ANIMATION FUNCTIONS ================
def animate_text(text, delay=0.03, color=Fore.WHITE):
    """Animate text printing with a typing effect"""
    for char in text:
        print(color + char, end='', flush=True)
        time.sleep(delay)
    print()

def scrolling_animation(text, width=50, delay=0.1):
    """Create a scrolling animation effect"""
    padding = " " * width
    scrolling_text = padding + text + padding
    for i in range(len(scrolling_text) - width):
        print(Fore.CYAN + "\r" + scrolling_text[i:i+width], end='', flush=True)
        time.sleep(delay)
    print()

def bouncing_text_animation(text, width=30, delay=0.1):
    """Create a bouncing text animation"""
    padding = " " * width
    text_with_padding = padding + text + padding
    direction = 1
    position = 0
    
    for _ in range(30):
        print(Fore.MAGENTA + "\r" + text_with_padding[position:position+width], end='', flush=True)
        position += direction
        if position + width >= len(text_with_padding) or position <= 0:
            direction *= -1
        time.sleep(delay)
    print()

def case_alternating_animation(text, delay=0.1):
    """Animate text with alternating case"""
    original_text = text
    for _ in range(10):
        alternated = ''.join(
            char.upper() if i % 2 == 0 else char.lower() 
            for i, char in enumerate(original_text)
        )
        print(Fore.YELLOW + "\r" + alternated, end='', flush=True)
        time.sleep(delay)
        
        alternated = ''.join(
            char.lower() if i % 2 == 0 else char.upper() 
            for i, char in enumerate(original_text)
        )
        print(Fore.YELLOW + "\r" + alternated, end='', flush=True)
        time.sleep(delay)
    print("\r" + original_text)

def spinning_animation(delay=0.1, duration=3, message="Processing"):
    """Show a spinning animation for a specific duration"""
    spinner = ['|', '/', '-', '\\']
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(Fore.CYAN + f"\r{message} {spinner[i % len(spinner)]}", end='', flush=True)
        time.sleep(delay)
        i += 1
    print("\r" + " " * (len(message) + 2))

# ================ BANNER ANIMATION ================
def display_animated_banner():
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    banner_text = pyfiglet.figlet_format("Gray Protector", font="slant")
    banner_lines = banner_text.split('\n')
    
    print("\n" * 2)
    for i, line in enumerate(banner_lines):
        color = colors[i % len(colors)]
        for char in line:
            print(color + char, end='', flush=True)
            time.sleep(0.001)
        print()
    
    subtitle = "Author: Subir (Gray Code) | Ver 2.0 | Domain Investigation Tool"
    print(Fore.WHITE + " " * 15, end='')
    for char in subtitle:
        print(char, end='', flush=True)
        time.sleep(0.03)
    print("\n")
    
    border = "═" * 70
    for char in border:
        print(Fore.CYAN + char, end='', flush=True)
        time.sleep(0.005)
    print()
    
    title = "DOMAIN INVESTIGATION & FRAUD DETECTION"
    case_alternating_animation(" " * 20 + title)
    
    for char in border:
        print(Fore.CYAN + char, end='', flush=True)
        time.sleep(0.005)
    print("\n")

# ================ DOMAIN REPUTATION FUNCTIONS ================
def check_known_bad_domains(domain):
    """Check against our database of known bad domains"""
    spinning_animation(message="Checking known bad domains", duration=1)
    
    if domain in KNOWN_BAD_DOMAINS:
        return {
            "status": "KNOWN_BAD",
            "message": "Domain found in known malicious domains database",
            "severity": "HIGH"
        }
    
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return {
                "status": "SUSPICIOUS_TLD",
                "message": f"Domain uses suspicious TLD: {tld}",
                "severity": "MEDIUM"
            }
    
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        base_domain = '.'.join(domain_parts[-2:])
        if base_domain in FREE_HOSTING_DOMAINS:
            return {
                "status": "FREE_HOSTING",
                "message": f"Domain uses free hosting service: {base_domain}",
                "severity": "LOW"
            }
    
    popular_domains = ["facebook", "google", "amazon", "apple", "microsoft", 
                       "paypal", "twitter", "instagram", "whatsapp", "netflix"]
    
    for popular_domain in popular_domains:
        if popular_domain in domain and domain != popular_domain + ".com":
            if domain.startswith(popular_domain + "-") or \
               domain.startswith("www-" + popular_domain) or \
               domain.endswith("-" + popular_domain + ".com"):
                return {
                    "status": "TYPO_SQUATTING",
                    "message": f"Possible typo-squatting on {popular_domain}.com",
                    "severity": "HIGH"
                }
    
    return {
        "status": "CLEAN",
        "message": "No matches in known bad domains database",
        "severity": "NONE"
    }

def check_phish_tank(domain):
    """Check domain against PhishTank database"""
    spinning_animation(message="Checking PhishTank database", duration=2)
    
    try:
        response = requests.post(
            PHISHTANK_API,
            data={
                'url': f'https://{domain}',
                'format': 'json'
            },
            headers={
                'User-Agent': 'GrayProtector/2.0'
            },
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            if data['results']['in_database']:
                return {
                    "status": "PHISHING",
                    "message": "Domain found in PhishTank phishing database",
                    "severity": "HIGH"
                }
        
        return {
            "status": "CLEAN",
            "message": "Domain not found in PhishTank database",
            "severity": "NONE"
        }
            
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Error checking PhishTank: {str(e)}",
            "severity": "UNKNOWN"
        }

def check_domain_reputation(domain):
    """Comprehensive domain reputation check"""
    print(f"\n{Fore.GREEN}[🛡️  DOMAIN REPUTATION CHECK]")
    
    known_bad_result = check_known_bad_domains(domain)
    severity_color = Fore.GREEN
    if known_bad_result["severity"] == "HIGH":
        severity_color = Fore.RED
    elif known_bad_result["severity"] == "MEDIUM":
        severity_color = Fore.YELLOW
        
    print(f"{Fore.WHITE}   Known Bad DB: {severity_color}{known_bad_result['message']}")
    
    phish_tank_result = check_phish_tank(domain)
    severity_color = Fore.GREEN
    if phish_tank_result["severity"] == "HIGH":
        severity_color = Fore.RED
        
    print(f"{Fore.WHITE}   PhishTank: {severity_color}{phish_tank_result['message']}")
    
    if known_bad_result["severity"] == "HIGH" or phish_tank_result["severity"] == "HIGH":
        overall_status = "MALICIOUS"
        status_color = Fore.RED
    elif known_bad_result["severity"] == "MEDIUM":
        overall_status = "SUSPICIOUS"
        status_color = Fore.YELLOW
    else:
        overall_status = "CLEAN"
        status_color = Fore.GREEN
        
    print(f"{Fore.WHITE}   Overall Reputation: {status_color}{overall_status}")
    
    return {
        "known_bad": known_bad_result,
        "phish_tank": phish_tank_result,
        "overall_status": overall_status
    }

# ================ ENHANCED TOOL FUNCTIONS WITH ERROR HANDLING ================
def get_whois_info(domain, retries=2):
    """Fetches WHOIS information with retry mechanism and fallbacks"""
    spinning_animation(message="Fetching WHOIS data")
    
    for attempt in range(retries + 1):
        try:
            # Method 1: python-whois library
            try:
                w = whois.whois(domain)
                if w and (w.creation_date or w.registrar):
                    return w
            except Exception as e:
                pass
            
            # Method 2: Direct WHOIS query using socket
            try:
                whois_data = direct_whois_query(domain)
                if whois_data:
                    # Create a mock whois object with the data
                    whois_obj = type('obj', (object,), whois_data)()
                    return whois_obj
            except Exception as e:
                pass
                
        except Exception as e:
            if attempt == retries:
                return f"Error fetching WHOIS: {str(e)}"
            time.sleep(1)  # Wait before retry
    
    return "Error fetching WHOIS: All methods failed after retries"

def direct_whois_query(domain):
    """Direct WHOIS query using socket connection to WHOIS servers"""
    whois_servers = ["whois.verisign-grs.com", "whois.iana.org", "whois.internic.net"]
    
    for server in whois_servers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(WHOIS_TIMEOUT)
                s.connect((server, 43))
                s.sendall((domain + "\r\n").encode())
                
                response = b""
                while True:
                    data = s.recv(1024)
                    if not data:
                        break
                    response += data
                
                whois_text = response.decode()
                return parse_whois_response(whois_text)
                
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            continue
    
    return None

def parse_whois_response(whois_text):
    """Parse raw WHOIS response into structured data"""
    result = {}
    lines = whois_text.split('\n')
    
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower().replace(' ', '_')
            value = value.strip()
            
            if key and value:
                if key in result:
                    if isinstance(result[key], list):
                        result[key].append(value)
                    else:
                        result[key] = [result[key], value]
                else:
                    result[key] = value
    
    # Try to extract creation date from various formats
    for date_key in ['creation_date', 'created', 'registered', 'registration']:
        if date_key in result:
            try:
                if isinstance(result[date_key], list):
                    date_str = result[date_key][0]
                else:
                    date_str = result[date_key]
                
                # Try various date formats
                for fmt in ['%Y-%m-%d', '%d-%b-%Y', '%Y/%m/%d', '%m/%d/%Y']:
                    try:
                        result['creation_date'] = datetime.strptime(date_str.split()[0], fmt)
                        break
                    except ValueError:
                        continue
            except:
                pass
    
    return result

def get_ssl_info(domain, retries=2):
    """Checks SSL certificate details with retry mechanism"""
    spinning_animation(message="Checking SSL certificate")
    
    for attempt in range(retries + 1):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try multiple ports if needed
            ports = [443, 8443, 4433]
            for port in ports:
                try:
                    with socket.create_connection((domain, port), timeout=SSL_TIMEOUT) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            
                            issuer_dict = {}
                            if cert.get('issuer'):
                                issuer_dict = dict(x[0] for x in cert['issuer'])
                            issuer_str = issuer_dict.get('organizationName', 'Unknown Issuer')
                            
                            subject_dict = {}
                            if cert.get('subject'):
                                subject_dict = dict(x[0] for x in cert['subject'])
                            
                            return {
                                "issuer": issuer_str,
                                "valid_from": cert.get('notBefore', 'N/A'),
                                "valid_until": cert.get('notAfter', 'N/A'),
                                "subject": subject_dict,
                            }
                except (socket.timeout, ConnectionRefusedError, socket.gaierror):
                    continue
                    
        except Exception as e:
            if attempt == retries:
                return f"No SSL info: {str(e)}"
            time.sleep(1)  # Wait before retry
    
    return "No SSL info: All connection attempts failed"

def get_ip_info(domain):
    """Performs a DNS lookup and gets geolocation/ISP info."""
    spinning_animation(message="Resolving IP and location")
    try:
        ip = socket.gethostbyname(domain)
        
        if IPINFO_API_KEY and IPINFO_API_KEY != "YOUR_IPINFO_API_KEY_HERE":
            url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            geo_data = response.json()
            return {
                "ip": ip,
                "hostname": geo_data.get('hostname', 'N/A'),
                "city": geo_data.get('city', 'N/A'),
                "region": geo_data.get('region', 'N/A'),
                "country": geo_data.get('country', 'N/A'),
                "org": geo_data.get('org', 'N/A'),
                "asn": geo_data.get('asn', 'N/A'),
            }
        else:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            geo_data = response.json()
            if geo_data.get('status') == 'success':
                return {
                    "ip": ip,
                    "country": geo_data.get('country'),
                    "region": geo_data.get('regionName'),
                    "city": geo_data.get('city'),
                    "isp": geo_data.get('isp'),
                    "asn": geo_data.get('as'),
                    "org": geo_data.get('org')
                }
            else:
                return {"ip": ip, "error": "Geo lookup failed"}
    except Exception as e:
        return f"Error fetching IP info: {str(e)}"

def check_blacklist(domain):
    """Checks VirusTotal for known malicious activity."""
    VT_URL = "https://www.virustotal.com/api/v3/domains/{}"
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"error": "VirusTotal API key not set. Skipping blacklist check."}
    
    spinning_animation(message="Checking VirusTotal blacklist", duration=2)
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(VT_URL.format(domain), headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values())
            reputation = data["data"]["attributes"].get("reputation", 0)
            
            result = {
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total_engines,
                "reputation_score": reputation,
                "status": "CLEAN" if malicious == 0 else "FLAGGED"
            }
            return result
        else:
            return {"error": f"Error {response.status_code} from VirusTotal: {response.text}"}
    except Exception as e:
        return {"error": f"Error checking blacklist: {str(e)}"}

def check_website_content(domain):
    """Attempts to fetch the website content and check for common scam patterns."""
    spinning_animation(message="Analyzing website content")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(
            f"https://{domain}", 
            headers=headers, 
            timeout=REQUEST_TIMEOUT, 
            verify=True
        )
        
        scam_keywords = [
            'vote', 'earn money', 'investment', 'lottery', 'prize', 
            'claim now', 'limited time', 'congratulations', 'you won',
            'free gift', 'urgent', 'account suspension', 'verify your account'
        ]
        content = response.text.lower()
        found_keywords = [keyword for keyword in scam_keywords if keyword in content]
        
        return {
            "status_code": response.status_code,
            "content_type": response.headers.get('content-type', 'Unknown'),
            "server": response.headers.get('server', 'Unknown'),
            "scam_keywords_found": found_keywords if found_keywords else "None detected"
        }
    except Exception as e:
        return f"Error fetching website content: {str(e)}"

def format_contacts(whois_info):
    """Formats the owner contact information clearly for reporting."""
    contacts = {}
    
    if hasattr(whois_info, 'emails'):
        emails = whois_info.emails
        if isinstance(emails, list):
            contacts['emails'] = ', '.join([str(e) for e in emails if e])
        else:
            contacts['emails'] = str(emails) if emails else "Redacted/Not Found"
    else:
        contacts['emails'] = "Redacted/Not Found"

    if hasattr(whois_info, 'phone'):
        contacts['phone'] = whois_info.phone
    else:
        contacts['phone'] = "Redacted/Not Found"

    contacts['name'] = getattr(whois_info, 'name', 'Redacted/Not Found')
    contacts['org'] = getattr(whois_info, 'org', 'Redacted/Not Found')
    contacts['address'] = getattr(whois_info, 'address', 'Redacted/Not Found')

    return contacts

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# MISSING HELPER ADDED: get_domain_age (no other changes made)
def get_domain_age(creation_date):
    """Return human-friendly age string from a creation_date (datetime/str/list)."""
    if not creation_date:
        return "Unknown"
    # If list (common from python-whois), take earliest
    if isinstance(creation_date, (list, tuple)) and creation_date:
        creation_date = creation_date[0]
    # If string, try parse a few common formats
    if isinstance(creation_date, str):
        for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y/%m/%d", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%S"):
            try:
                creation_date = datetime.strptime(creation_date.split()[0], fmt)
                break
            except ValueError:
                continue
        else:
            return "Unknown"
    try:
        age_days = (datetime.now() - creation_date).days
        years = age_days // 365
        months = (age_days % 365) // 30
        return f"{age_days} days ({years} years, {months} months)"
    except Exception:
        return "Unknown"
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

def investigate_domain(domain):
    """Main function to run the investigation and print the report."""
    print(f"\n{Fore.YELLOW}🔍 Investigating: {Fore.CYAN}{domain}")
    case_alternating_animation("=" * 60)
    
    # 0. DOMAIN REPUTATION CHECK
    reputation_data = check_domain_reputation(domain)
    
    # 1. WHOIS & Registration Data
    print(f"\n{Fore.GREEN}[📋 REGISTRATION INFORMATION]")
    whois_info = get_whois_info(domain)
    if isinstance(whois_info, str):
        print(f"{Fore.RED}   {whois_info}")
        # Create a minimal whois_info object for later use
        whois_info = type('obj', (object,), {})()
    else:
        print(f"{Fore.WHITE}   Registrar: {Fore.CYAN}{getattr(whois_info, 'registrar', 'Unknown')}")
        print(f"{Fore.WHITE}   Creation Date: {Fore.CYAN}{getattr(whois_info, 'creation_date', 'Unknown')}")
        print(f"{Fore.WHITE}   Expiry Date: {Fore.CYAN}{getattr(whois_info, 'expiration_date', 'Unknown')}")
        print(f"{Fore.WHITE}   WHOIS Country: {Fore.CYAN}{getattr(whois_info, 'country', 'Unknown')}")
        
        creation_date = getattr(whois_info, 'creation_date', None)
        age_text = get_domain_age(creation_date)
        print(f"{Fore.WHITE}   Domain Age: {Fore.CYAN}{age_text}")
        
        if isinstance(age_text, str) and "days" in age_text and "0 years" in age_text:
            try:
                days = int(age_text.split(" ")[0])
                if days < 30:
                    print(f"{Fore.RED}   ⚠️  WARNING: Domain is very new ({days} days) - potential red flag!")
            except Exception:
                pass
        
        contacts = format_contacts(whois_info)
        print(f"\n{Fore.WHITE}   [👤 REGISTRANT CONTACTS (For Reporting)]")
        print(f"{Fore.WHITE}   Name: {Fore.CYAN}{contacts['name']}")
        print(f"{Fore.WHITE}   Organization: {Fore.CYAN}{contacts['org']}")
        print(f"{Fore.WHITE}   Address: {Fore.CYAN}{contacts['address']}")
        print(f"{Fore.WHITE}   Email(s): {Fore.CYAN}{contacts['emails']}")
        print(f"{Fore.WHITE}   Phone: {Fore.CYAN}{contacts['phone']}")

    # 2. SSL Certificate Information
    print(f"\n{Fore.GREEN}[🔐 SSL CERTIFICATE]")
    ssl_info = get_ssl_info(domain)
    if isinstance(ssl_info, dict):
        print(f"{Fore.WHITE}   Issuer: {Fore.CYAN}{ssl_info.get('issuer', 'N/A')}")
        print(f"{Fore.WHITE}   Valid From: {Fore.CYAN}{ssl_info.get('valid_from', 'N/A')}")
        print(f"{Fore.WHITE}   Valid Until: {Fore.CYAN}{ssl_info.get('valid_until', 'N/A')}")
        subject = ssl_info.get('subject', {})
        print(f"{Fore.WHITE}   Subject: {Fore.CYAN}{subject.get('organizationName', 'N/A')}")
        
        if "Let's Encrypt" in ssl_info.get('issuer', '') or "Cloudflare" in ssl_info.get('issuer', ''):
            print(f"{Fore.YELLOW}   ⚠️  NOTE: Domain uses free SSL certificate - common for phishing sites")
    else:
        print(f"{Fore.RED}   {ssl_info}")

    # 3. DNS & IP Information
    print(f"\n{Fore.GREEN}[🌐 NETWORK & HOSTING]")
    ip_info = get_ip_info(domain)
    if isinstance(ip_info, dict):
        for key, value in ip_info.items():
            print(f"{Fore.WHITE}   {key.upper():<10}: {Fore.CYAN}{value}")
        
        suspicious_hosting_keywords = ["bulletproof", "offshore", "cloudflare", "amazonaws"]
        org = (ip_info.get('org') or '').lower()
        isp = (ip_info.get('isp') or '').lower()
        
        for keyword in suspicious_hosting_keywords:
            if keyword in org or keyword in isp:
                print(f"{Fore.YELLOW}   ⚠️  NOTE: Domain uses {keyword} hosting - common for malicious sites")
                break
                
    else:
        print(f"{Fore.RED}   {ip_info}")

    # 4. Website Content Analysis
    print(f"\n{Fore.GREEN}[🌐 WEBSITE CONTENT ANALYSIS]")
    content_info = check_website_content(domain)
    if isinstance(content_info, dict):
        print(f"{Fore.WHITE}   Status Code: {Fore.CYAN}{content_info.get('status_code', 'N/A')}")
        print(f"{Fore.WHITE}   Content Type: {Fore.CYAN}{content_info.get('content_type', 'N/A')}")
        print(f"{Fore.WHITE}   Server: {Fore.CYAN}{content_info.get('server', 'N/A')}")
        keywords = content_info.get('scam_keywords_found', 'N/A')
        if keywords != "None detected":
            print(f"{Fore.RED}   Scam Keywords: {keywords}")
        else:
            print(f"{Fore.GREEN}   Scam Keywords: {keywords}")
    else:
        print(f"{Fore.RED}   {content_info}")

    # 5. SECURITY & REPUTATION
    print(f"\n{Fore.GREEN}[🚨 SECURITY ASSESSMENT]")
    blacklist_status = check_blacklist(domain)
    if isinstance(blacklist_status, dict) and 'error' not in blacklist_status:
        status = blacklist_status['status']
        status_color = Fore.GREEN if status == "CLEAN" else Fore.RED
        print(f"{Fore.WHITE}   Status: {status_color}{status}")
        print(f"{Fore.WHITE}   Reputation Score: {Fore.CYAN}{blacklist_status['reputation_score']}")
        print(f"{Fore.WHITE}   Malicious Detections: {Fore.CYAN}{blacklist_status['malicious']}/{blacklist_status['total_engines']}")
        print(f"{Fore.WHITE}   Suspicious Detections: {Fore.CYAN}{blacklist_status['suspicious']}/{blacklist_status['total_engines']}")
        if blacklist_status['malicious'] > 2:
            print(f"{Fore.RED}   ⚠️  WARNING: Domain has multiple malicious flags!")
    else:
        error_msg = blacklist_status.get('error', 'Unknown error') if isinstance(blacklist_status, dict) else blacklist_status
        print(f"{Fore.YELLOW}   {error_msg}")

    # Final assessment
    print(f"\n{Fore.GREEN}[🔍 FINAL ASSESSMENT]")
    
    risk_score = 0
    risk_factors = []
    
    if reputation_data['overall_status'] == 'MALICIOUS':
        risk_score += 80
        risk_factors.append("Known malicious domain")
    elif reputation_data['overall_status'] == 'SUSPICIOUS':
        risk_score += 40
        risk_factors.append("Suspicious domain characteristics")
    
    age_text = get_domain_age(getattr(whois_info, 'creation_date', None))
    if isinstance(age_text, str) and "days" in age_text and "0 years" in age_text:
        try:
            days = int(age_text.split(" ")[0])
            if days < 7:
                risk_score += 30
                risk_factors.append("Very new domain (<7 days)")
            elif days < 30:
                risk_score += 15
                risk_factors.append("New domain (<30 days)")
        except Exception:
            pass
    
    if isinstance(blacklist_status, dict) and 'error' not in blacklist_status:
        if blacklist_status['malicious'] > 0:
            risk_score += blacklist_status['malicious'] * 10
            risk_factors.append(f"Blacklisted by {blacklist_status['malicious']} engines")
    
    if isinstance(content_info, dict) and content_info.get('scam_keywords_found') != "None detected":
        risk_score += 20
        risk_factors.append("Contains scam keywords")
    
    if risk_score >= 70:
        risk_level = "HIGH RISK"
        risk_color = Fore.RED
    elif risk_score >= 40:
        risk_level = "MEDIUM RISK"
        risk_color = Fore.YELLOW
    elif risk_score >= 20:
        risk_level = "LOW RISK"
        risk_color = Fore.BLUE
    else:
        risk_level = "MINIMAL RISK"
        risk_color = Fore.GREEN
    
    print(f"{Fore.WHITE}   Risk Score: {risk_color}{risk_score}/100")
    print(f"{Fore.WHITE}   Risk Level: {risk_color}{risk_level}")
    
    if risk_factors:
        print(f"{Fore.WHITE}   Risk Factors:")
        for factor in risk_factors:
            print(f"{Fore.WHITE}     - {Fore.YELLOW}{factor}")
    
    if risk_score >= 70:
        print(f"{Fore.RED}   🚫 RECOMMENDATION: AVOID THIS DOMAIN - High likelihood of malicious activity")
    elif risk_score >= 40:
        print(f"{Fore.YELLOW}   ⚠️  RECOMMENDATION: Exercise caution with this domain")
    else:
        print(f"{Fore.GREEN}   ✅ RECOMMENDATION: Domain appears safe")

    print(f"\n{Fore.CYAN}" + "=" * 60)
    scrolling_animation("Investigation complete. Review the data above.")
    scrolling_animation("Redacted info may require a formal request to the registrar for law enforcement.")
    print(f"{Fore.CYAN}" + "=" * 60)

# ================ MAIN EXECUTION ================
if __name__ == "__main__":
    display_animated_banner()
    
    print(Fore.YELLOW, end='')
    animate_text("Enter the domain to investigate (e.g., 'suspicious-site.com'): ", 0.02, Fore.YELLOW)
    domain_input = input(Fore.WHITE).strip()
    
    if domain_input.startswith(('http://', 'https://')):
        parsed_url = urlparse(domain_input)
        domain_to_check = parsed_url.netloc
    else:
        domain_to_check = domain_input
    
    domain_to_check = domain_to_check.replace('www.', '').split('/')[0]
    
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    if not re.match(domain_pattern, domain_to_check):
        print(f"{Fore.RED}Invalid domain format. Please enter a valid domain name.")
        sys.exit(1)
    
    bouncing_text_animation("Starting Investigation")
    investigate_domain(domain_to_check)
