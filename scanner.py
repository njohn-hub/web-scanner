#!/usr/bin/env python3
# advanced_scanner_v2.py
"""
Advanced non-destructive web scanner (single-file).
Features:
 - Crawl same-origin pages up to a configurable depth
 - Passive checks: security headers, directory listing, leaked secrets
 - Active (non-destructive) checks: reflected XSS, SQL error heuristics, Open Redirect heuristics
 - Form extraction and safe submission (GET/POST)
 - Export results to JSON, CSV, Markdown, and simple HTML
 - Configurable concurrency, timeouts, and rate limiting
Usage:
  python advanced_scanner_v2.py https://example.com --depth 2 --workers 8 --timeout 8 --report report.json --html report.html --csv report.csv --md report.md
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

colorama.init(autoreset=True)
requests.packages.urllib3.disable_warnings()  # for demo: silence insecure warnings


# --- Configurable defaults ---
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".git/config", ".env", "backup.zip", "backup.tar.gz",
    "admin/", "login", "config.php", "wp-login.php", "xmlrpc.php"
]
SQL_ERRORS = [
    r"sql syntax", r"mysql", r"syntax error", r"odbc", r"unclosed quotation", r"pg_query\(", r"sqlite3.OperationalError"
]
XSS_PAYLOADS = ['<testxss>v1</testxss>', 'xss_injection_test_12345']
SQLI_PAYLOADS = ["'", "\"", "')", "' OR '1'='1"]
SEC_HEADERS = {
    "strict-transport-security": ("HSTS", "Ensure long max-age and includeSubDomains"),
    "content-security-policy": ("CSP", "Content-Security-Policy present"),
    "x-frame-options": ("X-Frame-Options", "Clickjacking protection"),
    "referrer-policy": ("Referrer-Policy", "Referrer policy set"),
    "x-content-type-options": ("X-Content-Type-Options", "No MIME sniffing (nosniff)"),
}


class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 2, max_workers: int = 8,
                 timeout: int = 8, rate_limit: float = 0.0):
        self.target_url = target_url.rstrip("/")
        self.parsed_target = urllib.parse.urlparse(self.target_url)
        self.max_depth = max_depth
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.visited_urls: Set[str] = set()
        self.to_visit: List[Tuple[str, int]] = []
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "AdvScanner/2.0"})
        self.max_workers = max_workers
        self.start_time = time.time()
        self.forms: Dict[str, List[Dict]] = {}

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
        p = urllib.parse.urlparse(url)
        scheme = p.scheme or self.parsed_target.scheme
        netloc = p.netloc or self.parsed_target.netloc
        # keep query for uniqueness but normalize path
        path = urllib.parse.unquote(p.path) or "/"
        # preserve query and fragment stripped
        return urllib.parse.urlunparse((scheme, netloc, urllib.parse.quote(path, safe="/%"), p.params, p.query, ""))

    def safe_get(self, url: str, method: str = "GET", allow_redirects: bool = True, **kwargs):
        # wrapper with timeout and rate limit
        try:
            if self.rate_limit:
                time.sleep(self.rate_limit)
            if method.upper() == "GET":
                return self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=allow_redirects, **kwargs)
            elif method.upper() == "HEAD":
                return self.session.head(url, timeout=self.timeout, verify=False, allow_redirects=allow_redirects, **kwargs)
            elif method.upper() == "POST":
                return self.session.post(url, timeout=self.timeout, verify=False, allow_redirects=allow_redirects, **kwargs)
            else:
                return self.session.request(method, url, timeout=self.timeout, verify=False, allow_redirects=allow_redirects, **kwargs)
        except Exception:
            class Dummy:
                status_code = 0
                text = ""
                headers = {}
            return Dummy()

    def add_vuln(self, vuln: Dict):
        # deduplicate by (type, url, parameter, payload) tuple
        key = (vuln.get("type"), vuln.get("url"), vuln.get("parameter"), vuln.get("payload"))
        for v in self.vulnerabilities:
            if (v.get("type"), v.get("url"), v.get("parameter"), v.get("payload")) == key:
                return
        self.vulnerabilities.append(vuln)
        print(f"{colorama.Fore.RED}[VULN]{colorama.Style.RESET_ALL} {vuln.get('type')} at {vuln.get('url')}")

    # ---------------------------
    # Crawling & discovery
    # ---------------------------
    def discover_robots_sitemap(self):
        robots = urllib.parse.urljoin(self.target_url + "/", "robots.txt")
        sitemap = urllib.parse.urljoin(self.target_url + "/", "sitemap.xml")
        r = self.safe_get(robots)
        if getattr(r, "status_code", 0) == 200:
            self.report_info({"type": "robots.txt", "url": robots, "content": r.text[:2000]})
        r = self.safe_get(sitemap)
        if getattr(r, "status_code", 0) == 200:
            self.report_info({"type": "sitemap", "url": sitemap, "content": r.text[:2000]})
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
        except Exception:
            norm = url
        if norm not in self.visited_urls:
            self.to_visit.append((norm, depth))

    def crawl_site(self):
        self.enqueue(self.target_url, 0)
        while self.to_visit:
            url, depth = self.to_visit.pop(0)
            if url in self.visited_urls or depth > self.max_depth:
                continue
            print(f"[+] Crawling {url} (depth {depth})")
            self.visited_urls.add(url)
            r = self.safe_get(url)
            if getattr(r, "status_code", 0) == 0:
                continue
            try:
                soup = BeautifulSoup(r.text, "html.parser")
            except Exception:
                continue
            # extract links
            for a in soup.find_all("a", href=True):
                try:
                    next_url = urllib.parse.urljoin(url, a["href"])
                    if self.same_site(next_url):
                        self.enqueue(next_url, depth + 1)
                except Exception:
                    continue
            # extract forms
            forms = self.extract_forms(soup, url)
            if forms:
                self.forms[url] = forms
            # passive checks
            self.passive_checks(url, r)
            # discover common paths (enqueue)
            for p in COMMON_PATHS:
                trial = urllib.parse.urljoin(self.target_url + "/", p)
                if self.same_site(trial):
                    self.enqueue(trial, depth + 1)

    # ---------------------------
    # Forms & parameter mutation
    # ---------------------------
    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
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
            result.append({"url": form_url, "method": method, "inputs": inputs})
        return result

    def mutate_query(self, url: str, payload: str) -> List[Tuple[str, str]]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        mutated = []
        for param in params:
            new_params = {k: (payload if k == param else v) for k, v in params.items()}
            q = urllib.parse.urlencode(new_params, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=q))
            mutated.append((new_url, param))
        return mutated

    def mutate_form_submission(self, form: Dict, payload: str) -> Tuple[str, str, Dict]:
        data = {}
        injected_field = None
        for inp in form["inputs"]:
            name = inp["name"]
            typ = inp["type"].lower() if inp.get("type") else inp.get("type", "text")
            if typ in ["text", "search", "textarea", "email", "tel", "url", "input"]:
                if injected_field is None:
                    data[name] = payload
                    injected_field = name
                else:
                    data[name] = inp.get("value", "")
            elif typ in ["hidden"]:
                data[name] = inp.get("value", "")
            elif typ in ["checkbox", "radio"]:
                data[name] = inp.get("value", "on")
            else:
                data[name] = inp.get("value", "")
        return (form["url"], form["method"], data)

    # ---------------------------
    # Passive checks
    # ---------------------------
    def passive_checks(self, url: str, response):
        headers = {k.lower(): v for k, v in response.headers.items()}
        for hdr, meta in SEC_HEADERS.items():
            if hdr not in headers:
                self.add_vuln({
                    "type": "Missing Security Header",
                    "url": url,
                    "header": hdr,
                    "note": meta[1]
                })
        # Directory listing heuristic
        if "Index of /" in response.text or re.search(r"<title>Index of /", response.text, re.I):
            self.add_vuln({
                "type": "Directory Listing",
                "url": url,
                "note": "Potential directory listing detected"
            })
        patterns = {
            "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "private_key": r"-----BEGIN (RSA )?PRIVATE KEY-----"
        }
        for name, pat in patterns.items():
            if re.search(pat, response.text):
                self.add_vuln({
                    "type": "Sensitive Data Exposure",
                    "url": url,
                    "info": name
                })

    # ---------------------------
    # Active checks (non-destructive)
    # ---------------------------
    def check_common_paths(self):
        for p in COMMON_PATHS:
            url = urllib.parse.urljoin(self.target_url + "/", p)
            r = self.safe_get(url)
            if getattr(r, "status_code", 0) == 200:
                self.add_vuln({"type": "Discovered File/Path", "url": url, "note": "Common path returned 200"})

    def check_params_for_xss_and_sqli(self, url: str):
        if "?" in url:
            for payload in XSS_PAYLOADS:
                for test_url, param in self.mutate_query(url, payload):
                    r = self.safe_get(test_url)
                    if getattr(r, "status_code", 0) and payload in r.text:
                        self.add_vuln({
                            "type": "Reflected XSS",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload
                        })
            for payload in SQLI_PAYLOADS:
                for test_url, param in self.mutate_query(url, payload):
                    r = self.safe_get(test_url)
                    if getattr(r, "status_code", 0) and any(re.search(err, r.text, re.I) for err in SQL_ERRORS):
                        self.add_vuln({
                            "type": "SQL Error Disclosure (possible SQLi)",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload
                        })

    def check_forms(self):
        for page_url, forms in self.forms.items():
            for form in forms:
                url, method, data = self.mutate_form_submission(form, XSS_PAYLOADS[0])
                if method == "get":
                    q = urllib.parse.urlencode(data)
                    full = url + ("?" if "?" not in url else "&") + q
                    r = self.safe_get(full)
                    if getattr(r, "status_code", 0) and XSS_PAYLOADS[0] in r.text:
                        self.add_vuln({
                            "type": "Form Reflected XSS",
                            "url": url,
                            "method": method,
                            "payload": XSS_PAYLOADS[0]
                        })
                else:
                    r = self.safe_get(url, method="POST", data=data)
                    if getattr(r, "status_code", 0) and XSS_PAYLOADS[0] in r.text:
                        self.add_vuln({
                            "type": "Form Reflected XSS (POST)",
                            "url": url,
                            "method": method,
                            "payload": XSS_PAYLOADS[0]
                        })
                    for payload in SQLI_PAYLOADS:
                        _, _, data2 = self.mutate_form_submission(form, payload)
                        r2 = self.safe_get(url, method="POST", data=data2)
                        if getattr(r2, "status_code", 0) and any(re.search(err, r2.text, re.I) for err in SQL_ERRORS):
                            self.add_vuln({
                                "type": "SQL Error Disclosure (form)",
                                "url": url,
                                "method": method,
                                "payload": payload
                            })

    def check_open_redirects_on_url(self, url: str) -> None:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            target_param_names = [p for p in params.keys() if re.search(r'^(next|redirect|url|return|dest|redir)$', p, re.I)]
            if not target_param_names:
                return
            test_external = "https://example.com/.well-known/redirect-test"
            for param in target_param_names:
                new_params = params.copy()
                new_params[param] = test_external
                q = urllib.parse.urlencode(new_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=q))
                r = self.safe_get(test_url, method="HEAD", allow_redirects=False)
                if getattr(r, "status_code", 0) in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location", "")
                    if loc and "example.com" in loc:
                        self.add_vuln({
                            "type": "Open Redirect",
                            "url": url,
                            "parameter": param,
                            "redirect_location": loc,
                            "note": "Reflected redirect to external domain detected (HEAD)"
                        })
                else:
                    r2 = self.safe_get(test_url, method="GET", allow_redirects=False)
                    if getattr(r2, "status_code", 0) in (301, 302, 303, 307, 308):
                        loc2 = r2.headers.get("location", "")
                        if loc2 and "example.com" in loc2:
                            self.add_vuln({
                                "type": "Open Redirect",
                                "url": url,
                                "parameter": param,
                                "redirect_location": loc2,
                                "note": "Reflected redirect to external domain detected (GET)"
                            })
        except Exception:
            pass

    # ---------------------------
    # Reporting & exports
    # ---------------------------
    def report_info(self, info: Dict):
        entry = {"type": "info", **info}
        self.vulnerabilities.append(entry)

    def export_csv(self, csv_path: str = "scan_report.csv") -> None:
        fields = ["type", "url", "parameter", "payload", "note", "redirect_location", "info", "header"]
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for v in self.vulnerabilities:
                row = {k: v.get(k, "") for k in fields}
                writer.writerow(row)
        print(f"[+] CSV report written to {csv_path}")

    def export_markdown(self, md_path: str = "scan_report.md") -> None:
        lines = []
        lines.append(f"# Scan report: {self.target_url}\n")
        lines.append(f"- Scanned URLs: {len(self.visited_urls)}")
        lines.append(f"- Findings: {len(self.vulnerabilities)}\n")
        for i, v in enumerate(self.vulnerabilities, 1):
            lines.append(f"## {i}. {v.get('type')}\n")
            lines.append("```json")
            lines.append(json.dumps(v, indent=2))
            lines.append("```")
            lines.append("\n")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        print(f"[+] Markdown report written to {md_path}")

    def _write_html_report(self, payload: Dict, html_path: str):
        html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Scan report - {payload['target']}</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;padding:20px}}
h1{{color:#333}}
.vuln{{border-left:4px solid #c00;padding:8px;margin:10px 0;background:#fff8f8}}
.info{{background:#f7f7f7;padding:8px;margin:10px 0}}
pre{{white-space:pre-wrap;word-wrap:break-word}}
</style>
</head><body>
<h1>Scan report: {payload['target']}</h1>
<p>Scanned URLs: {len(payload['scanned_urls'])}</p>
<p>Vulnerabilities/Findings: {len(payload['vulnerabilities'])}</p>
<hr/>
"""
        for v in payload['vulnerabilities']:
            cls = "vuln" if not str(v.get("type", "")).lower().startswith("info") else "info"
            html += f"<div class='{cls}'><strong>{v.get('type')}</strong><pre>{json.dumps(v, indent=2)}</pre></div>\n"
        html += "</body></html>"
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html)

    def generate_reports(self, json_path: str = "scan_report.json", html_path: Optional[str] = None,
                         csv_path: Optional[str] = None, md_path: Optional[str] = None):
        payload = {
            "target": self.target_url,
            "scanned_urls": list(self.visited_urls),
            "vulnerabilities": self.vulnerabilities,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"[+] JSON report written to {json_path}")
        if csv_path:
            self.export_csv(csv_path)
        if md_path:
            self.export_markdown(md_path)
        if html_path:
            self._write_html_report(payload, html_path)
            print(f"[+] HTML report written to {html_path}")

    # ---------------------------
    # Orchestration
    # ---------------------------
    def run(self, json_report: str = "scan_report.json", html_report: Optional[str] = None,
            csv_report: Optional[str] = None, md_report: Optional[str] = None):
        print(colorama.Fore.CYAN + f"[+] Starting scan on {self.target_url} (depth={self.max_depth})" + colorama.Style.RESET_ALL)
        self.discover_robots_sitemap()
        self.crawl_site()

        urls = list(self.visited_urls)
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = []
            for u in urls:
                futures.append(ex.submit(self.check_params_for_xss_and_sqli, u))
                futures.append(ex.submit(self.check_open_redirects_on_url, u))
            # submit form checks and common path checks once
            futures.append(ex.submit(self.check_forms))
            futures.append(ex.submit(self.check_common_paths))

            for f in as_completed(futures):
                # just wait for completion; functions add_vuln when they find things
                try:
                    _ = f.result()
                except Exception:
                    pass

        # finished, write reports
        self.generate_reports(json_path=json_report, html_path=html_report, csv_path=csv_report, md_path=md_report)
        print(colorama.Fore.GREEN + "[+] Scan finished" + colorama.Style.RESET_ALL)


# ---------------------------
# CLI
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Advanced non-destructive web scanner")
    p.add_argument("target", help="Target base URL (e.g. https://example.com)")
    p.add_argument("--depth", type=int, default=2, help="Crawl depth")
    p.add_argument("--workers", type=int, default=8, help="Thread pool workers")
    p.add_argument("--timeout", type=int, default=8, help="HTTP timeout (seconds)")
    p.add_argument("--rate", type=float, default=0.0, help="Rate limit (seconds) between requests")
    p.add_argument("--report", default="scan_report.json", help="JSON report path")
    p.add_argument("--html", default=None, help="Write simple HTML report path")
    p.add_argument("--csv", default=None, help="Write CSV report path")
    p.add_argument("--md", default=None, help="Write markdown report path")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if not args.target.startswith("http://") and not args.target.startswith("https://"):
        print("Target must start with http:// or https://")
        sys.exit(1)

    scanner = WebSecurityScanner(
        target_url=args.target,
        max_depth=args.depth,
        max_workers=args.workers,
        timeout=args.timeout,
        rate_limit=args.rate
    )
    try:
        scanner.run(json_report=args.report, html_report=args.html, csv_report=args.csv, md_report=args.md)
    except KeyboardInterrupt:
        print("\nInterrupted by user, writing partial report...")
        scanner.generate_reports(json_path=args.report, html_path=args.html, csv_path=args.csv, md_path=args.md)
        sys.exit(0)
