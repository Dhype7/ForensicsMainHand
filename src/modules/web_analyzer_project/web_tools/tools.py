import requests
import socket
import whois
import urllib.parse
import dns.resolver
import dns.exception
from bs4 import BeautifulSoup

# ✅ جلب الهيدر
def get_headers(url: str) -> dict:
    try:
        response = requests.get(url, timeout=5)
        return dict(response.headers)
    except Exception as e:
        return {'Error': str(e)}

# ✅ تحويل دومين إلى IP (Advanced)
def resolve_domain(domain: str) -> dict:
    try:
        if not domain:
            return {'Error': 'No domain provided.'}
        parsed = urllib.parse.urlparse(domain)
        domain_only = parsed.netloc if parsed.netloc else parsed.path
        domain_only = domain_only.strip("/")
        if not domain_only:
            return {'Error': 'Invalid domain.'}
        result = {'Domain': domain_only}
        # IPv4
        try:
            a_records = dns.resolver.resolve(domain_only, 'A')
            result['IPv4'] = ', '.join([r.to_text() for r in a_records])  # type: ignore
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            result['IPv4'] = 'No A records found'
        except Exception as e:
            result['IPv4'] = f'Error: {str(e)}'
        # IPv6
        try:
            aaaa_records = dns.resolver.resolve(domain_only, 'AAAA')
            result['IPv6'] = ', '.join([r.to_text() for r in aaaa_records])  # type: ignore
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            result['IPv6'] = 'No AAAA records found'
        except Exception as e:
            result['IPv6'] = f'Error: {str(e)}'
        # CNAME
        try:
            cname = dns.resolver.resolve(domain_only, 'CNAME')
            result['CNAME'] = ', '.join([str(r) for r in cname])  # type: ignore
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            result['CNAME'] = 'No CNAME records found'
        except Exception as e:
            result['CNAME'] = f'Error: {str(e)}'
        # MX
        try:
            mx = dns.resolver.resolve(domain_only, 'MX')
            result['MX'] = ', '.join([str(r) for r in mx])  # type: ignore
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            result['MX'] = 'No MX records found'
        except Exception as e:
            result['MX'] = f'Error: {str(e)}'
        return result
    except Exception as e:
        return {'Error': str(e)}

# ✅ استعلام WHOIS (Advanced)
def whois_lookup(domain: str) -> dict:
    try:
        if not domain:
            return {'Error': 'No domain provided.'}
        parsed = urllib.parse.urlparse(domain)
        domain_only = parsed.netloc if parsed.netloc else parsed.path
        domain_only = domain_only.strip("/")
        if not domain_only:
            return {'Error': 'Invalid domain.'}
        
        # Set timeout for WHOIS lookup
        import socket
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(10)  # 10 second timeout
        
        try:
            info = whois.whois(domain_only)
            if info is None:
                return {'Error': 'No WHOIS information found.'}
            # Friendly fields
            result = {}
            for key in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers', 'status', 'emails']:
                if hasattr(info, key):
                    value = getattr(info, key)
                    if value is not None and value != []:
                        result[key] = value
            # Fallback to raw if no friendly fields found
            if not result:
                result['raw'] = str(info)
            return result
        except TimeoutError:
            return {'Error': 'WHOIS lookup timed out. Please try again.'}
        except Exception as e:
            return {'Error': f'WHOIS lookup failed: {str(e)}'}
        finally:
            socket.setdefaulttimeout(original_timeout)
    except Exception as e:
        return {'Error': str(e)}

# ✅ كشف XSS (Advanced)
def detect_xss(url: str, param: str = 'q') -> dict:
    payloads = [
        "<script>alert(1)</script>",
        "'><svg/onload=alert(1)>",
        '";alert(1);//',
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<svg><script>alert(1)</script>",
        "<details open ontoggle=alert(1)>"
    ]
    results = {}
    for payload in payloads:
        full_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        try:
            res = requests.get(full_url, timeout=5)
            snippet = res.text[:200].replace("\n", " ")
            found = payload in res.text
            results[full_url] = {
                "Status": "🚨 Reflected XSS Detected" if found else "No XSS",
                "HTTP Status": res.status_code,
                "Snippet": snippet
            }
        except Exception as e:
            results[full_url] = {"Error": str(e)}
    return results

# ✅ فحص المنافذ (Advanced)
def port_scan(domain: str, ports=None, udp=False) -> dict:
    import socket
    if not domain:
        return {0: "No domain provided."}
    domain = domain.replace("http://", "").replace("https://", "").strip("/")
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {0: f"Error: {e}"}
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]
    result = {}
    for port in ports:
        try:
            if udp:
                sock_type = socket.SOCK_DGRAM
            else:
                sock_type = socket.SOCK_STREAM
            with socket.socket(socket.AF_INET, sock_type) as s:
                s.settimeout(0.5)
                if udp:
                    try:
                        s.sendto(b"", (ip, port))
                        s.recvfrom(1024)
                        result[port] = "🟢 Open (UDP)"
                    except Exception:
                        result[port] = "🔴 Closed (UDP)"
                else:
                    code = s.connect_ex((ip, port))
                    if code == 0:
                        # Try to grab banner
                        try:
                            s.send(b'\r\n')
                            banner = s.recv(1024).decode(errors='ignore').strip()
                        except Exception:
                            banner = ''
                        service = socket.getservbyport(port, 'tcp') if port < 1024 else 'unknown'
                        result[port] = f"🟢 Open ({service}) Banner: {banner}"
                    else:
                        result[port] = "🔴 Closed"
        except Exception as e:
            result[port] = f"Error: {e}"
    return result

def check_security_headers(url: str) -> dict:
    required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers
        result = {}
        for header in required_headers:
            if header in headers:
                result[header] = f"✅ Present: {headers[header]}"
            else:
                result[header] = "❌ Missing"
        return result
    except Exception as e:
        return {'Error': str(e)}

def discover_login_pages(base_url: str) -> dict:
    """
    Tries to discover common login pages on the target website.
    """
    common_paths = [
        'login', 'admin', 'user/login', 'account/login', 'signin', 'users/sign_in', 'administrator', 'auth/login'
    ]
    found = {}
    for path in common_paths:
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                # Look for forms with password fields
                if soup.find('input', {'type': 'password'}):
                    found[url] = "Login form found"
                else:
                    found[url] = "Page exists, but no login form detected"
            elif res.status_code in [301, 302]:
                found[url] = f"Redirected ({res.status_code})"
        except Exception as e:
            found[url] = f"Error: {e}"
    return found

def brute_force_login(login_url: str, username_field: str, password_field: str, usernames: list, passwords: list) -> dict:
    """
    Attempts to brute-force a login form using provided usernames and passwords.
    Enhanced: Checks for success indicators like 'Sign Off', 'signoff', 'signoff.jsp', 'hello', 'welcome', or the username, and combines with redirect logic.
    """
    results = {}
    session = requests.Session()
    for username in usernames:
        for password in passwords:
            data = {username_field: username, password_field: password}
            try:
                res = session.post(login_url, data=data, timeout=5, allow_redirects=True)
                text = res.text.lower()
                if ("sign off" in text or "signoff" in text or "signoff.jsp" in text or "hello" in text or "welcome" in text or username.lower() in text) and res.status_code == 200:
                    results[f"{username}:{password}"] = "Success"
                elif "incorrect" in text or "invalid" in text:
                    results[f"{username}:{password}"] = "Failed"
                elif res.history and res.status_code == 200:
                    results[f"{username}:{password}"] = "Possible Success (Redirect)"
                else:
                    results[f"{username}:{password}"] = "Possible Success or Unknown"
            except Exception as e:
                results[f"{username}:{password}"] = f"Error: {e}"
    return results
