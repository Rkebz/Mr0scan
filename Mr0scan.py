import urllib.request
from html.parser import HTMLParser
from urllib.parse import urlparse

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr in attrs:
                if attr[0] == 'href':
                    self.links.append(attr[1])

def check_index_of(url, paths_files):
    try:
        response = urllib.request.urlopen(url)
        html_content = response.read().decode('utf-8')
        parser = LinkParser()
        parser.feed(html_content)
        for link in parser.links:
            parsed_url = urlparse(link)
            if parsed_url.path.endswith('/') and link.endswith('/'):
                for paths_file in paths_files:
                    with open(paths_file, "r") as file:
                        common_paths = file.readlines()
                    for path in common_paths:
                        path = path.strip()
                        index_of_url = link + '/' + path
                        response = urllib.request.urlopen(index_of_url)
                        if response.status == 200:
                            print("[+] Vulnerable: ", index_of_url)
                            print("[+] Target URL: ", url)
                            print("[+] Page Content: ", html_content[:1000])
                            print("--------------------------------------------------")
    except Exception as e:
        pass

def main():
    target_url = input("Enter the target URL: ")
    paths_files = input("Enter comma-separated paths files: ").split(",")
    check_index_of(target_url, paths_files)

if __name__ == "__main__":
    main()
