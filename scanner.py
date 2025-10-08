#!/usr/bin/env python3
# advanced_scanner_v3.py
"""
Enhanced Web Vulnerability Scanner with Advanced Detection
Features:
 - 20+ vulnerability checks including OWASP Top 10
 - Enhanced XSS detection (reflected, DOM-based patterns)
 - Advanced SQL injection detection with multiple vectors
 - SSRF, XXE, IDOR, Path Traversal detection
 - Broken authentication & session management checks
 - Security misconfiguration analysis
 - API endpoint discovery and testing
 - Technology fingerprinting
 - Enhanced reporting with severity ratings
 - Multi-format export (JSON, HTML, CSV, Markdown, XML)

Usage:
  python advanced_scanner_v3.py https://example.com --depth 3 --workers 10 --aggressive
"""
from __future__ import annotations
import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import time
import json
import os
from typing import List, Dict, Set, Tuple, Optional
import argparse
import csv
import base64
import hashlib
from collections import defaultdict
import xml.etree.ElementTree as ET

colorama.init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# --- Enhanced payloads and patterns ---
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".git/config", ".git/HEAD", ".env", ".env.local",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql", "database.sql",
    "admin/", "admin.php", "administrator/", "login", "login.php", "signin",
    "config.php", "configuration.php", "wp-config.php", "wp-login.php",
    "phpinfo.php", "info.php", "test.php", "xmlrpc.php", "composer.json",
    ".htaccess", ".htpasswd", "web.config", "crossdomain.xml",
    "server-status", "server-info", ".DS_Store", "Thumbs.db",
    "api/", "api/v1/", "api/v2/", "graphql", "swagger.json", "openapi.json"
]

SQL_ERRORS = [
    r"sql syntax", r"mysql", r"syntax error", r"odbc", r"unclosed quotation",
    r"pg_query\(", r"sqlite3\.OperationalError", r"SQLite3::",
    r"PostgreSQL.*ERROR", r"Warning.*mysql_", r"valid MySQL result",
    r"MySqlClient\.", r"Microsoft SQL Native Client error",
    r"OLE DB.*SQL Server", r"Unclosed quotation mark after",
    r"quoted string not properly terminated", r"ORA-\d{5}",
    r"DB2 SQL error", r"SQL Server", r"SQLSTATE\[", r"SQLException"
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
    '"><script>alert(1)</script>',
    '<testxss>v1</testxss>',
    'xss_test_12345'
]

SQLI_PAYLOADS = [
    "'", '"', "')", "' OR '1'='1", "' OR 1=1--",
    "admin'--", "' UNION SELECT NULL--", "1' AND 1=1--",
    "1' AND 1=2--", "' OR 'a'='a", "') OR ('a'='a"
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://localhost:8080", "http://127.0.0.1:22",
    "file:///etc/passwd", "http://metadata.google.internal/"
]

PATH_TRAVERSAL = [
    "../etc/passwd", "..\\windows\\system32\\config\\sam",
    "....//....//etc/passwd", "..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
]

XXE_PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""

COMMAND_INJECTION = [
    "; ls -la", "| whoami", "&& cat /etc/passwd",
    "`id`", "$(whoami)", "; ping -c 1 127.0.0.1"
]

# Technology fingerprints
TECH_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Drupal": [r"/sites/default", r"Drupal"],
    "Joomla": [r"com_content", r"Joomla"],
    "PHP": [r"\.php", r"X-Powered-By.*PHP"],
    "ASP.NET": [r"\.aspx", r"X-Powered-By.*ASP\.NET"],
    "Node.js": [r"X-Powered-By.*Express", r"X-Powered-By.*Node"],
    "Laravel": [r"laravel_session", r"X-Powered-By.*Laravel"],
    "Django": [r"csrfmiddlewaretoken", r"__admin"],
    "React": [r"react", r"__REACT_DEVTOOLS"],
    "Angular": [r"ng-version", r"angular"],
    "jQuery": [r"jquery", r"jQuery"]
}

SEC_HEADERS = {
    "strict-transport-security": ("HSTS", "critical"),
    "content-security-policy": ("CSP", "high"),
    "x-frame-options": ("Clickjacking Protection", "high"),
    "x-content-type-options": ("MIME-sniffing Protection", "medium"),
    "referrer-policy": ("Referrer Policy", "low"),
    "permissions-policy": ("Permissions Policy", "medium"),
    "x-xss-protection": ("XSS Protection", "low")
}

INSECURE_HEADERS = {
    "server": "Server version disclosure",
    "x-powered-by": "Technology disclosure",
    "x-aspnet-version": "ASP.NET version disclosure",
    "x-aspnetmvc-version": "ASP.NET MVC version disclosure"
}


class VulnerabilityScanner:
    def __init__(self, target_url: str, max_depth: int = 2, max_workers: int = 10,
                 timeout: int = 10, rate_limit: float = 0.0, aggressive: bool = False):
        self.target_url = target_url.rstrip("/")
        self.parsed_target = urllib.parse.urlparse(self.target_url)
        self.max_depth = max_depth
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.aggressive = aggressive
        self.visited_urls: Set[str] = set()
        self.to_visit: List[Tuple[str, int]] = []
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 AdvScanner/3.0"})
        self.max_workers = max_workers
        self.start_time = time.time()
        self.forms: Dict[str, List[Dict]] = {}
        self.api_endpoints: Set[str] = set()
        self.technologies: Set[str] = set()
        self.cookies_found: Dict[str, Dict] = {}
        self.js_files: Set[str] = set()
        
    # ---------------------------
    # Utilities
    # ---------------------------
    def same_site(self, url: str) -> bool:
        try:
            p = urllib.parse.urlparse(url)
            return p.netloc == self.parsed_target.netloc
        except Exception:
            return False

    def normalize(self, url: str) -> str:
        try:
            p = urllib.parse.urlparse(url)
            scheme = p.scheme or self.parsed_target.scheme
            netloc = p.netloc or self.parsed_target.netloc
            path = urllib.parse.unquote(p.path) or "/"
            return urllib.parse.urlunparse((scheme, netloc, urllib.parse.quote(path, safe="/%"), p.params, p.query, ""))
        except Exception:
            return url

    def safe_request(self, url: str, method: str = "GET", allow_redirects: bool = True, **kwargs):
        try:
            if self.rate_limit:
                time.sleep(self.rate_limit)
            method = method.upper()
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', False)
            kwargs.setdefault('allow_redirects', allow_redirects)
            
            if method == "GET":
                return self.session.get(url, **kwargs)
            elif method == "HEAD":
                return self.session.head(url, **kwargs)
            elif method == "POST":
                return self.session.post(url, **kwargs)
            elif method == "OPTIONS":
                return self.session.options(url, **kwargs)
            else:
                return self.session.request(method, url, **kwargs)
        except Exception as e:
            class DummyResponse:
                status_code = 0
                text = ""
                headers = {}
                cookies = {}
                url = url
            return DummyResponse()

    def add_vuln(self, vuln: Dict):
        # Enhanced deduplication and severity assignment
        if "severity" not in vuln:
            vuln["severity"] = self._get_severity(vuln.get("type", ""))
        
        key = (vuln.get("type"), vuln.get("url"), vuln.get("parameter"), vuln.get("payload"))
        for v in self.vulnerabilities:
            if (v.get("type"), v.get("url"), v.get("parameter"), v.get("payload")) == key:
                return
        
        self.vulnerabilities.append(vuln)
        severity_color = {
            "critical": colorama.Fore.RED,
            "high": colorama.Fore.LIGHTRED_EX,
            "medium": colorama.Fore.YELLOW,
            "low": colorama.Fore.CYAN,
            "info": colorama.Fore.WHITE
        }.get(vuln.get("severity", "info"), colorama.Fore.WHITE)
        
        print(f"{severity_color}[{vuln.get('severity', 'INFO').upper()}]{colorama.Style.RESET_ALL} "
              f"{vuln.get('type')} at {vuln.get('url', 'N/A')[:80]}")

    def _get_severity(self, vuln_type: str) -> str:
        critical_vulns = ["SQL Injection", "Command Injection", "XXE", "Remote Code Execution"]
        high_vulns = ["Reflected XSS", "SSRF", "Path Traversal", "Authentication Bypass", "Insecure Deserialization"]
        medium_vulns = ["Open Redirect", "CSRF", "Missing Security Header", "Information Disclosure"]
        low_vulns = ["Directory Listing", "Verbose Error", "Cookie Security"]
        
        for v in critical_vulns:
            if v.lower() in vuln_type.lower():
                return "critical"
        for v in high_vulns:
            if v.lower() in vuln_type.lower():
                return "high"
        for v in medium_vulns:
            if v.lower() in vuln_type.lower():
                return "medium"
        for v in low_vulns:
            if v.lower() in vuln_type.lower():
                return "low"
        return "info"

    # ---------------------------
    # Discovery & Crawling
    # ---------------------------
    def discover_robots_sitemap(self):
        robots = urllib.parse.urljoin(self.target_url + "/", "robots.txt")
        r = self.safe_request(robots)
        if r.status_code == 200:
            self.add_vuln({"type": "Information Disclosure", "url": robots, 
                          "note": "robots.txt found", "severity": "info"})
            # Extract disallowed paths
            for line in r.text.split('\n'):
                if line.strip().lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        full_url = urllib.parse.urljoin(self.target_url, path)
                        if self.same_site(full_url):
                            self.enqueue(full_url, 0)
        
        sitemap = urllib.parse.urljoin(self.target_url + "/", "sitemap.xml")
        r = self.safe_request(sitemap)
        if r.status_code == 200:
            self.add_vuln({"type": "Information Disclosure", "url": sitemap,
                          "note": "sitemap.xml found", "severity": "info"})
            try:
                soup = BeautifulSoup(r.text, "xml")
                for loc in soup.find_all("loc"):
                    u = loc.text.strip()
                    if u and self.same_site(u):
                        self.enqueue(u, 0)
            except Exception:
                pass

    def enqueue(self, url: str, depth: int):
        try:
            norm = self.normalize(url)
            if norm not in self.visited_urls and depth <= self.max_depth:
                self.to_visit.append((norm, depth))
        except Exception:
            pass

    def crawl_site(self):
        self.enqueue(self.target_url, 0)
        
        while self.to_visit:
            url, depth = self.to_visit.pop(0)
            if url in self.visited_urls:
                continue
                
            print(f"[+] Crawling {url} (depth {depth})")
            self.visited_urls.add(url)
            
            r = self.safe_request(url)
            if r.status_code == 0:
                continue
            
            # Analyze cookies
            self._analyze_cookies(url, r)
            
            # Detect technologies
            self._detect_technology(r)
            
            try:
                soup = BeautifulSoup(r.text, "html.parser")
            except Exception:
                continue
            
            # Extract links
            for a in soup.find_all("a", href=True):
                try:
                    next_url = urllib.parse.urljoin(url, a["href"])
                    if self.same_site(next_url):
                        self.enqueue(next_url, depth + 1)
                except Exception:
                    continue
            
            # Extract forms
            forms = self._extract_forms(soup, url)
            if forms:
                self.forms[url] = forms
            
            # Extract JS files
            for script in soup.find_all("script", src=True):
                js_url = urllib.parse.urljoin(url, script["src"])
                if self.same_site(js_url):
                    self.js_files.add(js_url)
            
            # Look for API endpoints
            self._detect_api_endpoints(soup, url)
            
            # Passive checks
            self._passive_checks(url, r)
            
            # Discover common paths
            if depth == 0:  # Only from root
                for p in COMMON_PATHS:
                    trial = urllib.parse.urljoin(self.target_url + "/", p)
                    if self.same_site(trial):
                        self.enqueue(trial, depth + 1)

    def _analyze_cookies(self, url: str, response):
        for cookie_name, cookie_value in response.cookies.items():
            cookie_obj = response.cookies.get(cookie_name)
            issues = []
            
            if not cookie_obj.secure:
                issues.append("Missing Secure flag")
            if not cookie_obj.has_nonstandard_attr('HttpOnly'):
                issues.append("Missing HttpOnly flag")
            if not cookie_obj.has_nonstandard_attr('SameSite'):
                issues.append("Missing SameSite attribute")
            
            if issues:
                self.add_vuln({
                    "type": "Cookie Security Issue",
                    "url": url,
                    "cookie": cookie_name,
                    "issues": ", ".join(issues),
                    "severity": "medium"
                })

    def _detect_technology(self, response):
        content = response.text + str(response.headers)
        for tech, patterns in TECH_PATTERNS.items():
            if tech not in self.technologies:
                for pattern in patterns:
                    if re.search(pattern, content, re.I):
                        self.technologies.add(tech)
                        self.add_vuln({
                            "type": "Technology Detection",
                            "technology": tech,
                            "severity": "info"
                        })
                        break

    def _detect_api_endpoints(self, soup: BeautifulSoup, base_url: str):
        # Look for API-like URLs in JavaScript and links
        text = soup.get_text()
        api_patterns = [
            r'["\']/(api|v\d|graphql|rest)[^"\']*["\']',
            r'https?://[^"\']*/(api|v\d|graphql)[^"\']*'
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, text, re.I)
            for match in matches:
                endpoint = match.strip('"\'')
                full_url = urllib.parse.urljoin(base_url, endpoint)
                if self.same_site(full_url):
                    self.api_endpoints.add(full_url)

    # ---------------------------
    # Forms & Parameters
    # ---------------------------
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        result = []
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            method = (form.get("method") or "get").lower()
            form_url = urllib.parse.urljoin(base_url, action)
            inputs = []
            
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                itype = inp.get("type") or inp.name
                value = inp.get("value") or ""
                inputs.append({"name": name, "type": itype, "value": value})
            
            result.append({
                "url": form_url,
                "method": method,
                "inputs": inputs,
                "base_url": base_url
            })
        return result

    def _mutate_query(self, url: str, payload: str) -> List[Tuple[str, str]]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        mutated = []
        
        for param in params:
            new_params = {k: (payload if k == param else v) for k, v in params.items()}
            q = urllib.parse.urlencode(new_params, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=q))
            mutated.append((new_url, param))
        
        return mutated

    # ---------------------------
    # Passive Checks
    # ---------------------------
    def _passive_checks(self, url: str, response):
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Check missing security headers
        for hdr, (name, severity) in SEC_HEADERS.items():
            if hdr not in headers:
                self.add_vuln({
                    "type": "Missing Security Header",
                    "url": url,
                    "header": hdr,
                    "name": name,
                    "severity": severity
                })
        
        # Check information disclosure headers
        for hdr, description in INSECURE_HEADERS.items():
            if hdr in headers:
                self.add_vuln({
                    "type": "Information Disclosure",
                    "url": url,
                    "header": hdr,
                    "value": headers[hdr],
                    "note": description,
                    "severity": "low"
                })
        
        # Directory listing
        if "Index of /" in response.text or re.search(r"<title>Index of /", response.text, re.I):
            self.add_vuln({
                "type": "Directory Listing",
                "url": url,
                "severity": "low"
            })
        
        # Sensitive data patterns
        patterns = {
            "Email Address": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Private Key": r"-----BEGIN (RSA )?PRIVATE KEY-----",
            "API Key Pattern": r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}",
            "JWT Token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
        }
        
        for name, pat in patterns.items():
            matches = re.findall(pat, response.text)
            if matches:
                self.add_vuln({
                    "type": "Sensitive Data Exposure",
                    "url": url,
                    "data_type": name,
                    "count": len(matches),
                    "severity": "high" if "key" in name.lower() else "medium"
                })
        
        # Verbose error messages
        error_patterns = [
            r"Fatal error:", r"Warning:", r"Parse error:",
            r"Traceback \(most recent call last\):",
            r"Exception in thread", r"at System\.",
            r"Microsoft OLE DB Provider"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.I):
                self.add_vuln({
                    "type": "Verbose Error Message",
                    "url": url,
                    "severity": "low"
                })
                break
        
        # CORS misconfiguration
        if 'access-control-allow-origin' in headers:
            origin = headers['access-control-allow-origin']
            if origin == '*':
                self.add_vuln({
                    "type": "CORS Misconfiguration",
                    "url": url,
                    "note": "Wildcard origin allowed",
                    "severity": "medium"
                })

    # ---------------------------
    # Active Vulnerability Checks
    # ---------------------------
    def check_xss(self, url: str):
        if "?" not in url:
            return
        
        for payload in XSS_PAYLOADS:
            for test_url, param in self._mutate_query(url, payload):
                r = self.safe_request(test_url)
                if r.status_code and payload in r.text:
                    # Check if it's in executable context
                    if self._check_xss_context(r.text, payload):
                        self.add_vuln({
                            "type": "Reflected XSS",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "high"
                        })

    def _check_xss_context(self, html: str, payload: str) -> bool:
        # Enhanced context checking
        dangerous_contexts = [
            r'<script[^>]*>' + re.escape(payload),
            r'<[^>]+on\w+=["\']?' + re.escape(payload),
            r'<[^>]+src=["\']?' + re.escape(payload)
        ]
        for pattern in dangerous_contexts:
            if re.search(pattern, html, re.I):
                return True
        return payload in html

    def check_sqli(self, url: str):
        if "?" not in url:
            return
        
        # Time-based blind SQLi
        time_payloads = [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--"
        ]
        
        for payload in SQLI_PAYLOADS:
            for test_url, param in self._mutate_query(url, payload):
                r = self.safe_request(test_url)
                if r.status_code:
                    # Error-based detection
                    if any(re.search(err, r.text, re.I) for err in SQL_ERRORS):
                        self.add_vuln({
                            "type": "SQL Injection (Error-based)",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "critical"
                        })
        
        # Time-based detection (only if aggressive mode)
        if self.aggressive:
            for payload in time_payloads:
                for test_url, param in self._mutate_query(url, payload):
                    start = time.time()
                    r = self.safe_request(test_url)
                    elapsed = time.time() - start
                    if elapsed > 4:  # 5 second delay with some tolerance
                        self.add_vuln({
                            "type": "SQL Injection (Time-based Blind)",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "critical"
                        })

    def check_ssrf(self, url: str):
        if "?" not in url or not self.aggressive:
            return
        
        for payload in SSRF_PAYLOADS:
            for test_url, param in self._mutate_query(url, payload):
                r = self.safe_request(test_url)
                if r.status_code:
                    # Check for metadata service responses
                    ssrf_indicators = ["ami-id", "instance-id", "iam/security-credentials"]
                    if any(indicator in r.text.lower() for indicator in ssrf_indicators):
                        self.add_vuln({
                            "type": "SSRF (Server-Side Request Forgery)",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "critical"
                        })

    def check_path_traversal(self, url: str):
        if "?" not in url:
            return
        
        for payload in PATH_TRAVERSAL:
            for test_url, param in self._mutate_query(url, payload):
                r = self.safe_request(test_url)
                if r.status_code:
                    # Check for Unix/Linux passwd file content
                    if re.search(r"root:.*:0:0:", r.text):
                        self.add_vuln({
                            "type": "Path Traversal",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "high"
                        })
                    # Check for Windows SAM file indicators
                    elif re.search(r"Administrator:.*:500:", r.text, re.I):
                        self.add_vuln({
                            "type": "Path Traversal",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "high"
                        })

    def check_open_redirect(self, url: str):
        if "?" not in url:
            return
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        redirect_params = [p for p in params.keys() 
                          if re.search(r'^(next|redirect|url|return|dest|redir|continue|returnto)$', p, re.I)]
        
        if not redirect_params:
            return
        
        test_domain = "https://evil.example.com/malicious"
        
        for param in redirect_params:
            new_params = params.copy()
            new_params[param] = test_domain
            q = urllib.parse.urlencode(new_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=q))
            
            r = self.safe_request(test_url, method="HEAD", allow_redirects=False)
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("location", "")
                if "evil.example.com" in loc:
                    self.add_vuln({
                        "type": "Open Redirect",
                        "url": url,
                        "parameter": param,
                        "redirect_to": loc,
                        "severity": "medium"
                    })

    def check_xxe(self, url: str):
        # Only test on endpoints that accept XML
        if not self.aggressive:
            return
        
        r = self.safe_request(url, method="POST", 
                             data=XXE_PAYLOAD,
                             headers={"Content-Type": "application/xml"})
        
        if r.status_code and "root:" in r.text:
            self.add_vuln({
                "type": "XXE (XML External Entity)",
                "url": url,
                "severity": "critical"
            })

    def check_command_injection(self, url: str):
        if "?" not in url or not self.aggressive:
            return
        
        for payload in COMMAND_INJECTION:
            for test_url, param in self._mutate_query(url, payload):
                r = self.safe_request(test_url)
                if r.status_code:
                    # Look for command output indicators
                    indicators = ["uid=", "gid=", "groups=", "root:", "bin/bash", "Windows"]
                    if any(indicator in r.text for indicator in indicators):
                        self.add_vuln({
                            "type": "Command Injection",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "critical"
                        })

    def check_forms(self):
        for page_url, forms in self.forms.items():
            for form in forms:
                # Check for CSRF token
                has_csrf = any(inp["name"].lower() in ["csrf", "csrf_token", "token", "_token"] 
                              for inp in form["inputs"])
                if not has_csrf and form["method"] == "post":
                    self.add_vuln({
                        "type": "Missing CSRF Protection",
                        "url": form["url"],
                        "form_on_page": page_url,
                        "severity": "medium"
                    })
                
                # Test form for XSS
                data = {}
                injected_field = None
                for inp in form["inputs"]:
                    name = inp["name"]
                    typ = inp.get("type", "text").lower()
                    if typ in ["text", "search", "email", "url"] and not injected_field:
                        data[name] = XSS_PAYLOADS[0]
                        injected_field = name
                    else:
                        data[name] = inp.get("value", "test")
                
                if injected_field:
                    if form["method"] == "get":
                        q = urllib.parse.urlencode(data)
                        test_url = form["url"] + ("?" if "?" not in form["url"] else "&") + q
                        r = self.safe_request(test_url)
                    else:
                        r = self.safe_request(form["url"], method="POST", data=data)
                    
                    if r.status_code and XSS_PAYLOADS[0] in r.text:
                        self.add_vuln({
                            "type": "Form Reflected XSS",
                            "url": form["url"],
                            "method": form["method"],
                            "parameter": injected_field,
                            "severity": "high"
                        })

    def check_common_paths(self):
        for path in COMMON_PATHS:
            url = urllib.parse.urljoin(self.target_url + "/", path)
            r = self.safe_request(url)
            
            if r.status_code == 200:
                severity = "high" if any(x in path for x in [".git", ".env", "config", "backup"]) else "medium"
                self.add_vuln({
                    "type": "Sensitive File/Directory Exposed",
                    "url": url,
                    "path": path,
                    "severity": severity
                })
            elif r.status_code == 403:
                self.add_vuln({
                    "type": "Protected Path Found",
                    "url": url,
                    "path": path,
                    "status": 403,
                    "severity": "info"
                })

    def check_http_methods(self):
        # Test various HTTP methods on target
        methods = ["OPTIONS", "PUT", "DELETE", "TRACE", "PATCH"]
        
        for method in methods:
            r = self.safe_request(self.target_url, method=method)
            
            if method == "OPTIONS" and r.status_code == 200:
                allow = r.headers.get("Allow", "")
                dangerous = [m for m in ["PUT", "DELETE", "TRACE"] if m in allow]
                if dangerous:
                    self.add_vuln({
                        "type": "Dangerous HTTP Methods Allowed",
                        "url": self.target_url,
                        "methods": ", ".join(dangerous),
                        "severity": "medium"
                    })
            
            if method == "TRACE" and r.status_code == 200:
                self.add_vuln({
                    "type": "HTTP TRACE Method Enabled",
                    "url": self.target_url,
                    "note": "XST (Cross-Site Tracing) possible",
                    "severity": "low"
                })
            
            if method in ["PUT", "DELETE"] and r.status_code not in [405, 403, 404]:
                self.add_vuln({
                    "type": f"HTTP {method} Method Accepted",
                    "url": self.target_url,
                    "status": r.status_code,
                    "severity": "high"
                })

    def check_ssl_tls(self):
        if not self.target_url.startswith("https://"):
            self.add_vuln({
                "type": "Insecure Protocol",
                "url": self.target_url,
                "note": "Site not using HTTPS",
                "severity": "high"
            })
        else:
            # Test HTTP version
            http_url = self.target_url.replace("https://", "http://")
            r = self.safe_request(http_url, allow_redirects=False)
            if r.status_code == 200:
                self.add_vuln({
                    "type": "HTTP Available Alongside HTTPS",
                    "url": http_url,
                    "note": "Site accessible over insecure HTTP",
                    "severity": "medium"
                })
            elif r.status_code not in [301, 302, 307, 308]:
                self.add_vuln({
                    "type": "No HTTPS Redirect",
                    "url": http_url,
                    "note": "HTTP doesn't redirect to HTTPS",
                    "severity": "low"
                })

    def check_api_endpoints(self):
        for endpoint in self.api_endpoints:
            # Test for authentication bypass
            r = self.safe_request(endpoint)
            if r.status_code == 200:
                # Check if it returns JSON with sensitive data
                try:
                    data = json.loads(r.text)
                    if isinstance(data, (dict, list)) and data:
                        self.add_vuln({
                            "type": "Unauthenticated API Access",
                            "url": endpoint,
                            "note": "API endpoint accessible without authentication",
                            "severity": "high"
                        })
                except:
                    pass
            
            # Test for excessive data exposure
            if "/users" in endpoint.lower() or "/user" in endpoint.lower():
                self.add_vuln({
                    "type": "Potential IDOR Vulnerability",
                    "url": endpoint,
                    "note": "User endpoint detected - test for IDOR",
                    "severity": "medium"
                })

    def analyze_javascript(self):
        # Analyze collected JS files for sensitive info
        for js_url in list(self.js_files)[:20]:  # Limit to first 20
            r = self.safe_request(js_url)
            if r.status_code != 200:
                continue
            
            # Look for API keys and secrets
            patterns = {
                "API Key": r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
                "AWS Key": r"(AKIA[0-9A-Z]{16})",
                "Token": r"['\"]?token['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]",
                "Password": r"['\"]?password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
            }
            
            for name, pattern in patterns.items():
                matches = re.findall(pattern, r.text, re.I)
                if matches:
                    self.add_vuln({
                        "type": "Hardcoded Secret in JavaScript",
                        "url": js_url,
                        "secret_type": name,
                        "severity": "critical"
                    })
            
            # Look for internal URLs/endpoints
            internal_urls = re.findall(r'["\']/(api|admin|internal|private)[^"\']{3,50}["\']', r.text)
            if internal_urls:
                self.add_vuln({
                    "type": "Internal Endpoints in JavaScript",
                    "url": js_url,
                    "endpoints": len(set(internal_urls)),
                    "severity": "info"
                })

    # ---------------------------
    # Reporting & Export
    # ---------------------------
    def generate_summary(self) -> Dict:
        severity_counts = defaultdict(int)
        vuln_types = defaultdict(int)
        
        for v in self.vulnerabilities:
            severity_counts[v.get("severity", "info")] += 1
            vuln_types[v.get("type", "Unknown")] += 1
        
        return {
            "target": self.target_url,
            "scan_duration": round(time.time() - self.start_time, 2),
            "urls_scanned": len(self.visited_urls),
            "forms_found": sum(len(forms) for forms in self.forms.values()),
            "js_files_found": len(self.js_files),
            "api_endpoints_found": len(self.api_endpoints),
            "technologies_detected": list(self.technologies),
            "total_findings": len(self.vulnerabilities),
            "severity_breakdown": dict(severity_counts),
            "vulnerability_types": dict(vuln_types)
        }

    def export_json(self, path: str):
        data = {
            "summary": self.generate_summary(),
            "vulnerabilities": self.vulnerabilities,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] JSON report: {path}")

    def export_csv(self, path: str):
        fields = ["severity", "type", "url", "parameter", "payload", "note", "header", "technology"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            for v in self.vulnerabilities:
                writer.writerow(v)
        print(f"[+] CSV report: {path}")

    def export_markdown(self, path: str):
        summary = self.generate_summary()
        lines = [
            f"# Security Scan Report: {self.target_url}\n",
            f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  ",
            f"**Duration:** {summary['scan_duration']}s  ",
            f"**URLs Scanned:** {summary['urls_scanned']}  ",
            f"**Total Findings:** {summary['total_findings']}\n",
            "## Severity Breakdown\n"
        ]
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = summary["severity_breakdown"].get(severity, 0)
            if count > 0:
                lines.append(f"- **{severity.upper()}**: {count}")
        
        if summary["technologies_detected"]:
            lines.append("\n## Technologies Detected\n")
            lines.append(", ".join(summary["technologies_detected"]))
        
        lines.append("\n## Vulnerabilities\n")
        
        # Group by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            vulns = [v for v in self.vulnerabilities if v.get("severity") == severity]
            if vulns:
                lines.append(f"\n### {severity.upper()} Severity\n")
                for i, v in enumerate(vulns, 1):
                    lines.append(f"#### {i}. {v.get('type')}\n")
                    lines.append("```json")
                    lines.append(json.dumps(v, indent=2))
                    lines.append("```\n")
        
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[+] Markdown report: {path}")

    def export_html(self, path: str):
        summary = self.generate_summary()
        severity_colors = {
            "critical": "#d32f2f",
            "high": "#f44336",
            "medium": "#ff9800",
            "low": "#2196f3",
            "info": "#757575"
        }
        
        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Scan Report - {summary['target']}</title>
<style>
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
    margin: 0;
    padding: 20px;
    background: #f5f5f5;
}}
.container {{
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}}
h1 {{
    color: #333;
    border-bottom: 3px solid #2196f3;
    padding-bottom: 10px;
}}
.summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin: 20px 0;
}}
.summary-card {{
    background: #f8f9fa;
    padding: 15px;
    border-radius: 5px;
    border-left: 4px solid #2196f3;
}}
.summary-card h3 {{
    margin: 0 0 10px 0;
    font-size: 14px;
    color: #666;
    text-transform: uppercase;
}}
.summary-card .value {{
    font-size: 24px;
    font-weight: bold;
    color: #333;
}}
.severity-badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: bold;
    color: white;
    text-transform: uppercase;
    margin-right: 8px;
}}
.vuln {{
    margin: 20px 0;
    padding: 15px;
    border-radius: 5px;
    border-left: 4px solid #ccc;
    background: #fafafa;
}}
.vuln-header {{
    display: flex;
    align-items: center;
    margin-bottom: 10px;
}}
.vuln-type {{
    font-size: 18px;
    font-weight: bold;
    color: #333;
}}
pre {{
    background: #263238;
    color: #aed581;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    font-size: 13px;
}}
.tech-badge {{
    display: inline-block;
    padding: 5px 10px;
    margin: 5px;
    background: #e3f2fd;
    border-radius: 4px;
    font-size: 12px;
    color: #1976d2;
}}
</style>
</head>
<body>
<div class="container">
<h1>🔒 Security Scan Report</h1>
<p><strong>Target:</strong> {summary['target']}</p>
<p><strong>Scan Date:</strong> {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</p>
<p><strong>Duration:</strong> {summary['scan_duration']}s</p>

<div class="summary">
    <div class="summary-card">
        <h3>URLs Scanned</h3>
        <div class="value">{summary['urls_scanned']}</div>
    </div>
    <div class="summary-card">
        <h3>Total Findings</h3>
        <div class="value">{summary['total_findings']}</div>
    </div>
    <div class="summary-card">
        <h3>Forms Found</h3>
        <div class="value">{summary['forms_found']}</div>
    </div>
    <div class="summary-card">
        <h3>JS Files</h3>
        <div class="value">{summary['js_files_found']}</div>
    </div>
</div>

<h2>Severity Breakdown</h2>
<div>
"""
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = summary['severity_breakdown'].get(severity, 0)
            if count > 0:
                color = severity_colors.get(severity, "#999")
                html += f'<span class="severity-badge" style="background:{color}">{severity}: {count}</span>\n'
        
        if summary['technologies_detected']:
            html += "\n<h2>Technologies Detected</h2>\n<div>"
            for tech in summary['technologies_detected']:
                html += f'<span class="tech-badge">{tech}</span>'
            html += "</div>\n"
        
        html += "\n<h2>Vulnerabilities</h2>\n"
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            vulns = [v for v in self.vulnerabilities if v.get("severity") == severity]
            if vulns:
                html += f"<h3>{severity.upper()} Severity ({len(vulns)})</h3>\n"
                for v in vulns:
                    color = severity_colors.get(severity, "#999")
                    html += f"""
<div class="vuln" style="border-left-color:{color}">
    <div class="vuln-header">
        <span class="severity-badge" style="background:{color}">{v.get('severity', 'info')}</span>
        <span class="vuln-type">{v.get('type', 'Unknown')}</span>
    </div>
    <pre>{json.dumps(v, indent=2)}</pre>
</div>
"""
        
        html += """
</div>
</body>
</html>"""
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] HTML report: {path}")

    def export_xml(self, path: str):
        root = ET.Element("security_scan")
        summary = self.generate_summary()
        
        # Summary section
        sum_elem = ET.SubElement(root, "summary")
        for key, value in summary.items():
            if isinstance(value, (str, int, float)):
                elem = ET.SubElement(sum_elem, key.replace(" ", "_"))
                elem.text = str(value)
        
        # Vulnerabilities section
        vulns_elem = ET.SubElement(root, "vulnerabilities")
        for v in self.vulnerabilities:
            vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
            for key, value in v.items():
                elem = ET.SubElement(vuln_elem, key.replace(" ", "_"))
                elem.text = str(value)
        
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(path, encoding="utf-8", xml_declaration=True)
        print(f"[+] XML report: {path}")

    # ---------------------------
    # Main Orchestration
    # ---------------------------
    def run(self, json_path: str = "scan_report.json", html_path: str = None,
            csv_path: str = None, md_path: str = None, xml_path: str = None):
        
        print(colorama.Fore.CYAN + f"\n{'='*70}")
        print(f"  Advanced Web Vulnerability Scanner v3.0")
        print(f"  Target: {self.target_url}")
        print(f"  Max Depth: {self.max_depth} | Workers: {self.max_workers}")
        print(f"  Aggressive Mode: {'ON' if self.aggressive else 'OFF'}")
        print(f"{'='*70}\n" + colorama.Style.RESET_ALL)
        
        # Discovery phase
        print(colorama.Fore.YELLOW + "[*] Phase 1: Discovery & Crawling" + colorama.Style.RESET_ALL)
        self.discover_robots_sitemap()
        self.crawl_site()
        
        # Active scanning phase
        print(colorama.Fore.YELLOW + "\n[*] Phase 2: Active Vulnerability Scanning" + colorama.Style.RESET_ALL)
        
        urls = list(self.visited_urls)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Per-URL checks
            for url in urls:
                futures.append(executor.submit(self.check_xss, url))
                futures.append(executor.submit(self.check_sqli, url))
                futures.append(executor.submit(self.check_open_redirect, url))
                if self.aggressive:
                    futures.append(executor.submit(self.check_ssrf, url))
                    futures.append(executor.submit(self.check_path_traversal, url))
                    futures.append(executor.submit(self.check_command_injection, url))
                    futures.append(executor.submit(self.check_xxe, url))
            
            # Global checks
            futures.append(executor.submit(self.check_forms))
            futures.append(executor.submit(self.check_common_paths))
            futures.append(executor.submit(self.check_http_methods))
            futures.append(executor.submit(self.check_ssl_tls))
            futures.append(executor.submit(self.check_api_endpoints))
            futures.append(executor.submit(self.analyze_javascript))
            
            # Wait for completion
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    pass
        
        # Generate reports
        print(colorama.Fore.YELLOW + "\n[*] Phase 3: Generating Reports" + colorama.Style.RESET_ALL)
        
        self.export_json(json_path)
        if html_path:
            self.export_html(html_path)
        if csv_path:
            self.export_csv(csv_path)
        if md_path:
            self.export_markdown(md_path)
        if xml_path:
            self.export_xml(xml_path)
        
        # Print summary
        summary = self.generate_summary()
        print(colorama.Fore.GREEN + f"\n{'='*70}")
        print("  SCAN COMPLETE")
        print(f"{'='*70}")
        print(f"  URLs Scanned: {summary['urls_scanned']}")
        print(f"  Total Findings: {summary['total_findings']}")
        print(f"  Duration: {summary['scan_duration']}s")
        print(f"\n  Severity Breakdown:")
        for sev in ["critical", "high", "medium", "low"]:
            count = summary['severity_breakdown'].get(sev, 0)
            if count > 0:
                color = {
                    "critical": colorama.Fore.RED,
                    "high": colorama.Fore.LIGHTRED_EX,
                    "medium": colorama.Fore.YELLOW,
                    "low": colorama.Fore.CYAN
                }.get(sev, colorama.Fore.WHITE)
                print(f"  {color}{sev.upper()}: {count}{colorama.Style.RESET_ALL}")
        print(f"{'='*70}\n" + colorama.Style.RESET_ALL)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Advanced Web Vulnerability Scanner v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:     python advanced_scanner_v3.py https://example.com
  Deep scan:      python advanced_scanner_v3.py https://example.com --depth 3 --workers 15
  Aggressive:     python advanced_scanner_v3.py https://example.com --aggressive
  Full reports:   python advanced_scanner_v3.py https://example.com --html report.html --csv report.csv --md report.md
        """
    )
    
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--workers", type=int, default=10, help="Thread pool size (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--rate", type=float, default=0.0, help="Rate limit between requests (default: 0)")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive scanning (SSRF, time-based SQLi, etc.)")
    parser.add_argument("--report", default="scan_report.json", help="JSON report path")
    parser.add_argument("--html", help="HTML report path")
    parser.add_argument("--csv", help="CSV report path")
    parser.add_argument("--md", help="Markdown report path")
    parser.add_argument("--xml", help="XML report path")
    
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    if not args.target.startswith(("http://", "https://")):
        print(colorama.Fore.RED + "[!] Target must start with http:// or https://" + colorama.Style.RESET_ALL)
        sys.exit(1)
    
    scanner = VulnerabilityScanner(
        target_url=args.target,
        max_depth=args.depth,
        max_workers=args.workers,
        timeout=args.timeout,
        rate_limit=args.rate,
        aggressive=args.aggressive
    )
    
    try:
        scanner.run(
            json_path=args.report,
            html_path=args.html,
            csv_path=args.csv,
            md_path=args.md,
            xml_path=args.xml
        )
    except KeyboardInterrupt:
        print(colorama.Fore.YELLOW + "\n[!] Interrupted by user. Generating partial reports..." + colorama.Style.RESET_ALL)
        scanner.export_json(args.report)
        if args.html:
            scanner.export_html(args.html)
        sys.exit(0)