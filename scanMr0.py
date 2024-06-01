import requests
from concurrent.futures import ThreadPoolExecutor
import time

def load_payloads(file_name):
    with open(file_name, 'r') as file:
        return [line.strip() for line in file]

def scan_vulnerability(url, payloads, param):
    def make_request(payload):
        target_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(target_url)
            if payload in response.text:
                print(f"[+] Potential vulnerability found: {target_url} with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Request failed for payload {payload}: {e}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        for payload in payloads:
            executor.submit(make_request, payload)
            time.sleep(0.1)  # تأخير قصير بين الطلبات

def sql_injection_scan(url):
    payloads = load_payloads('sql_injection_payloads.txt')
    print("Scanning for SQL Injection vulnerabilities...")
    scan_vulnerability(url, payloads, 'id')

def xss_scan(url):
    payloads = load_payloads('xss_payloads.txt')
    print("Scanning for XSS vulnerabilities...")
    scan_vulnerability(url, payloads, 'q')

def dir_traversal_scan(url):
    payloads = load_payloads('dir_traversal_payloads.txt')
    print("Scanning for Directory Traversal vulnerabilities...")
    scan_vulnerability(url, payloads, 'file')

def rce_scan(url):
    payloads = load_payloads('rce_payloads.txt')
    print("Scanning for RCE vulnerabilities...")
    scan_vulnerability(url, payloads, 'cmd')

def csrf_scan(url):
    payloads = load_payloads('csrf_payloads.txt')
    print("Scanning for CSRF vulnerabilities...")
    scan_vulnerability(url, payloads, 'action')

def lfi_scan(url):
    payloads = load_payloads('lfi_payloads.txt')
    print("Scanning for LFI vulnerabilities...")
    scan_vulnerability(url, payloads, 'page')

def cmd_injection_scan(url):
    payloads = load_payloads('cmd_injection_payloads.txt')
    print("Scanning for Command Injection vulnerabilities...")
    scan_vulnerability(url, payloads, 'cmd')

def open_redirect_scan(url):
    payloads = load_payloads('open_redirect_payloads.txt')
    print("Scanning for Open Redirect vulnerabilities...")
    scan_vulnerability(url, payloads, 'url')

def rfi_scan(url):
    payloads = load_payloads('rfi_payloads.txt')
    print("Scanning for Remote File Inclusion vulnerabilities...")
    scan_vulnerability(url, payloads, 'file')

def ssrf_scan(url):
    payloads = load_payloads('ssrf_payloads.txt')
    print("Scanning for SSRF vulnerabilities...")
    scan_vulnerability(url, payloads, 'url')

def path_traversal_scan(url):
    payloads = load_payloads('path_traversal_payloads.txt')
    print("Scanning for Path Traversal vulnerabilities...")
    scan_vulnerability(url, payloads, 'path')

def main():
    url = input("Enter the target URL: ")
    sql_injection_scan(url)
    xss_scan(url)
    dir_traversal_scan(url)
    rce_scan(url)
    csrf_scan(url)
    lfi_scan(url)
    cmd_injection_scan(url)
    open_redirect_scan(url)
    rfi_scan(url)
    ssrf_scan(url)
    path_traversal_scan(url)

if __name__ == "__main__":
    main()
