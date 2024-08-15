import requests
import socket
import nmap
from bs4 import BeautifulSoup

class WebEnumerationCLI:
    def __init__(self):
        self.url = None
        self.directory_list_path = None

    def run(self):
        while True:
            print("\nWeb Enumeration Tool")
            print("1. Directory Scan")
            print("2. Gather Website Info")
            print("3. Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                self.directory_scan()
            elif choice == '2':
                self.gather_info()
            elif choice == '3':
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

    def directory_scan(self):
        self.url = input("Enter the base URL (e.g., http://example.com): ").strip()
        self.directory_list_path = input("Enter the path to the directory list file: ").strip()

        try:
            with open(self.directory_list_path, 'r') as f:
                directories = f.read().splitlines()
            self.scan_directories(directories)
        except FileNotFoundError:
            print(f"Error: File '{self.directory_list_path}' not found.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def scan_directories(self, directories):
        directories_dont_exist = []
        try:
            for directory in directories:
                response = requests.get(f'{self.url}/{directory}')
                if response.status_code == 200:
                    print(f'{self.url}/{directory} exists')
                else:
                    print(f'{self.url}/{directory} does not exist')
                    directories_dont_exist.append(directory)
        except requests.exceptions.RequestException as e:
            print(f"Error: Unable to connect to {self.url}. {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def gather_info(self):
        self.url = input("Enter the URL (e.g., http://example.com): ").strip()

        try:
            response = requests.get(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')

            print(f"Status code: {response.status_code}")
            server = response.headers.get('Server')
            if server:
                print(f"Server: {server}")
            technologies = response.headers.get('X-Powered-By')
            if technologies:
                print(f"Technologies: {technologies}")
            title = soup.find('title')
            if title:
                print(f"Title: {title.text}")
            links = soup.find_all('a')
            print(f"Number of links: {len(links)}")
            forms = soup.find_all('form')
            for form in forms:
                print(f"Form name: {form.get('name')}")
                print(f"Form action: {form.get('action')}")
                inputs = form.find_all('input')
                print(f"Number of input fields in form {form.get('name')}: {len(inputs)}")
            images = soup.find_all('img')
            for image in images:
                print(f"Image URL: {image['src']}")
            print(f"Headers: {response.headers}")
            
            # Port scanning
            self.port_scan()

        except requests.exceptions.RequestException as e:
            print(f"Error: Unable to connect to {self.url}. {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def port_scan(self):
        try:
            scanner = nmap.PortScanner()
            target_host = "testphp.vulnweb.com"  # Replace this with the actual target host
            target_ports = "1-1000"
            result = scanner.scan(target_host, target_ports)
            print(f"\nPort Scan Results for {target_host}:")
            for host in result["scan"]:
                for port in result["scan"][host]["tcp"]:
                    port_info = result["scan"][host]["tcp"][port]
                    print(f"Port {port}: {port_info['state']}")
        except nmap.PortScannerError as e:
            print(f"Port scanner error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    app = WebEnumerationCLI()
    app.run()
