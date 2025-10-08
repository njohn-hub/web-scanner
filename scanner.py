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
                        "form_on_page": page