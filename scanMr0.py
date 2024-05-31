import requests

def load_payloads(file_name):
    with open(file_name, 'r') as file:
        return [line.strip() for line in file]

def scan_vulnerability(url, payloads, param):
    vulnerable = False
    for payload in payloads:
        target_url = f"{url}?{param}={payload}"
        response = requests.get(target_url)
        if payload in response.text:
            print(f"[+] Potential vulnerability found: {target_url}")
            vulnerable = True
    if not vulnerable:
        print(f"[-] No vulnerability found using payloads from {param}.")

def sql_injection_scan(url):
    payloads = load_payloads('sql_injection_payloads.txt')
    scan_vulnerability(url, payloads, 'id')

def xss_scan(url):
    payloads = load_payloads('xss_payloads.txt')
    scan_vulnerability(url, payloads, 'q')

def dir_traversal_scan(url):
    payloads = load_payloads('dir_traversal_payloads.txt')
    scan_vulnerability(url, payloads, 'file')

def rce_scan(url):
    payloads = load_payloads('rce_payloads.txt')
    scan_vulnerability(url, payloads, 'cmd')

def csrf_scan(url):
    payloads = load_payloads('csrf_payloads.txt')
    scan_vulnerability(url, payloads, 'action')

def main():
    url = input("Enter the target URL: ")
    sql_injection_scan(url)
    xss_scan(url)
    dir_traversal_scan(url)
    rce_scan(url)
    csrf_scan(url)

if __name__ == "__main__":
    main()
