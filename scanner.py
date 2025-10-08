# advanced_scanner.py
import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from typing import List, Dict, Set

colorama.init(autoreset=True)


class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3, max_workers: int = 10):
        self.target_url = target_url.rstrip("/")
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "AdvancedScanner/1.0"})
        self.max_workers = max_workers

    def normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("a", href=True):
                next_url = urllib.parse.urljoin(url, link["href"])
                if next_url.startswith(self.target_url) and next_url not in self.visited_urls:
                    self.crawl(next_url, depth + 1)

        except Exception as e:
            print(f"[ERROR] Crawling {url}: {str(e)}")

    def mutate_params(self, url: str, payload: str) -> List[str]:
        """Generate new URLs with injected payloads for each parameter."""
        mutated_urls = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param in params:
            new_params = params.copy()
            new_params[param] = payload
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            new_url = urllib.parse.urlunparse(
                parsed._replace(query=new_query)
            )
            mutated_urls.append((new_url, param))
        return mutated_urls

    def check_sql_injection(self, url: str) -> None:
        sql_payloads = ["'", "' OR '1'='1", "' UNION SELECT NULL,NULL--", '" OR "a"="a']

        for payload in sql_payloads:
            for test_url, param in self.mutate_params(url, payload):
                try:
                    r = self.session.get(test_url, timeout=8)
                    if any(error in r.text.lower() for error in [
                        "sql syntax", "mysql", "syntax error", "odbc", "unclosed quotation"
                    ]):
                        self.report_vulnerability({
                            "type": "SQL Injection",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload
                        })
                except Exception as e:
                    pass

    def check_xss(self, url: str) -> None:
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><svg onload=alert(1)>"
        ]

        for payload in xss_payloads:
            for test_url, param in self.mutate_params(url, payload):
                try:
                    r = self.session.get(test_url, timeout=8)
                    if payload in r.text:
                        self.report_vulnerability({
                            "type": "XSS",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload
                        })
                except Exception as e:
                    pass

    def check_sensitive_info(self, url: str) -> None:
        sensitive_patterns = {
            "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
            "API Key": r"(?i)(api[_-]?key)[\s:=]+[0-9a-zA-Z]{16,45}",
            "Private Key": r"-----BEGIN PRIVATE KEY-----",
        }

        try:
            r = self.session.get(url, timeout=10)
            for info_type, pattern in sensitive_patterns.items():
                if re.search(pattern, r.text):
                    self.report_vulnerability({
                        "type": "Sensitive Data Exposure",
                        "url": url,
                        "info_type": info_type
                    })
        except Exception:
            pass

    def scan(self) -> List[Dict]:
        print(f"{colorama.Fore.BLUE}[+] Starting scan on {self.target_url}{colorama.Style.RESET_ALL}\n")
        self.crawl(self.target_url)

        tasks = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for url in self.visited_urls:
                tasks.append(executor.submit(self.check_sql_injection, url))
                tasks.append(executor.submit(self.check_xss, url))
                tasks.append(executor.submit(self.check_sensitive_info, url))

            for future in as_completed(tasks):
                pass  # we don't need the return, just execution

        return self.vulnerabilities

    def report_vulnerability(self, vuln: Dict) -> None:
        self.vulnerabilities.append(vuln)
        print(f"{colorama.Fore.RED}[!] Vulnerability Found:{colorama.Style.RESET_ALL}")
        for k, v in vuln.items():
            print(f"  {k}: {v}")
        print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    scanner = WebSecurityScanner(target_url)
    vulns = scanner.scan()

    print(f"\n{colorama.Fore.GREEN}Scan complete!{colorama.Style.RESET_ALL}")
    print(f"  URLs scanned: {len(scanner.visited_urls)}")
    print(f"  Vulnerabilities found: {len(vulns)}")
