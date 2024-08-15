import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
import socket
from bs4 import BeautifulSoup
import nmap
import subprocess

class WebEnumerationTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Enumeration Tool")
        self.root.geometry("1050x700")

        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        window_width = 1050
        window_height = 750
        x = (self.screen_width - window_width) // 2
        y = (self.screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # Initialize frames
        self.first_frame = tk.Frame(self.root, bg="black")
        self.directory_scan_frame = tk.Frame(self.root, bg="black")
        self.info_frame = tk.Frame(self.root, bg="black")

        self.file_path = ""

        # Configure frames
        self.configure_first_frame()
        self.configure_directory_scan_frame()
        self.configure_info_frame()

        # Show the first frame
        self.show_frame(self.first_frame)  # Show the initial frame

    def show_frame(self, frame):
        # Hide all frames
        self.first_frame.grid_forget()
        self.directory_scan_frame.grid_forget()
        self.info_frame.grid_forget()

        # Show the selected frame
        frame.grid(row=0, column=0, rowspan=12, columnspan=12, sticky="nsew")

    def configure_first_frame(self):
        self.first_frame.grid(row=0, column=0, rowspan=12, columnspan=12, sticky="nsew")
        for i in range(12):
            self.first_frame.rowconfigure(i, minsize=50)
            self.first_frame.columnconfigure(i, minsize=70)

        project_text = ttk.Label(self.first_frame, text="Web Enumeration Tool", font=("Anton", 50, "bold"), foreground="#000000", background="#920303")
        project_text.grid(row=2, column=2, columnspan=3, pady=20, padx=40)

        login_button = tk.Button(self.first_frame, text="Login as Admin", command=self.run_admin_program, font=("Helvetica", 13), 
                                 foreground="#000000", relief="raised", bd=3, activebackground="#144552", activeforeground="#1985a1")
        login_button.grid(row=7, column=2, columnspan=3, sticky="s", pady=20)
        login_button.config(width=14)

        directory_scan_button = tk.Button(self.first_frame, text="Directory Scan", command=self.directory_scan, font=("Helvetica", 13), 
                                          foreground="#000000", relief="raised", bd=3, activebackground="#144552", activeforeground="#1985a1")
        directory_scan_button.grid(row=8, column=2, columnspan=3, sticky="s", pady=20)
        directory_scan_button.config(width=14)

        gather_info_button = tk.Button(self.first_frame, text="Get Info", command=self.gather_info, font=("Helvetica", 13),
                                       foreground="#000000", relief="raised", bd=3, activebackground="#144552", activeforeground="#c5c3c6")
        gather_info_button.grid(row=9, column=2, columnspan=3, sticky="s", pady=20)
        gather_info_button.config(width=14)

        exit_button = tk.Button(self.first_frame, text="Exit", command=self.root.quit, font=("Helvetica", 13),
                                foreground="#000000", relief="raised", bd=3, activebackground="#144552", activeforeground="red")
        exit_button.grid(row=10, column=2, columnspan=3, sticky="s", pady=20)
        exit_button.config(width=14)

    def run_admin_program(self):
        try:
            subprocess.Popen(['python', r"C:\Users\user\OneDrive\Documents\sem 3\Algo2\admin.py"])
        except FileNotFoundError:
            print("Program not found.")
        except Exception as e:
            print(f"An error occurred: {e}")

    def directory_scan(self):
        self.first_frame.grid_forget()
        self.configure_directory_scan_frame()

    def gather_info(self):
        self.first_frame.grid_forget()
        self.configure_info_frame()

    def back_to_main(self):
        self.directory_scan_frame.grid_forget()
        self.info_frame.grid_forget()
        self.first_frame.grid(row=0, column=0, rowspan=12, columnspan=12, sticky="nsew")

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if self.file_path:
            print(self.file_path)
        return self.file_path

    def check_directories(self, file_path):
        url = self.ip_address_entry.get()
        directory = file_path
        directories = self.read_directory_list(directory)
        self.scan_directories(url, directories)

    def read_directory_list(self, directory):
        try:
            with open(directory, 'r') as f:
                directories = f.read().splitlines()
            return directories
        except FileNotFoundError:
            self.output_field.insert(tk.END, f'{directory} does not exist\n')
            self.output_field.update()
            return []

    def scan_directories(self, url, directories):
        directories_dont_exist = []
        try:
            response = requests.get(url)
            for directory in directories:
                response = requests.get(f'{url}/{directory}')
                if response.status_code == 200:
                    self.output_field.insert(tk.END, f'{url}/{directory} exists\n')
                    self.output_field.update()
                else:
                    self.output_field.insert(tk.END, f'{url}/{directory} does not exist\n')
                    directories_dont_exist.append(directory)
                    self.output_field.update()
        except socket.gaierror:
            self.output_field.insert(tk.END, f'Unable to resolve the hostname of {url}\n')
            self.output_field.update()

    

    def save_output(self):
        content = self.output_field_info.get("1.0", tk.END)
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])    
        if filename:
            with open(filename, "w") as f:
                f.write(content)

    def start_gather_info(self):
        url = self.url_entry.get()
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            current_text = self.output_field_info.get("1.0", tk.END)

            self.output_field_info.delete("1.0", tk.END)
            self.output_field_info.insert(tk.END, current_text + f"Status code: {response.status_code}\n")

            server = response.headers.get('Server')
            if server:
                self.output_field_info.insert(tk.END, f"Server: {server}\n")

            technologies = response.headers.get('X-Powered-By')
            if technologies:
                self.output_field_info.insert(tk.END, f"Technologies: {technologies}\n")

            title = soup.find('title')
            if title:
                self.output_field_info.insert(tk.END, f"Title: {title.text}\n")

            links = soup.find_all('a')
            self.output_field_info.insert(tk.END, f"Number of links: {len(links)}\n")

            forms = soup.find_all('form')
            for form in forms:
                self.output_field_info.insert(tk.END, f"Form name: {form.get('name')}\n")
                self.output_field_info.insert(tk.END, f"Form action: {form.get('action')}\n")
                inputs = form.find_all('input')
                self.output_field_info.insert(tk.END, f"Number of input fields in form {form.get('name')}: {len(inputs)}\n")

            images = soup.find_all('img')
            for image in images:
                self.output_field_info.insert(tk.END, f"Image URL: {image['src']}\n")

            self.output_field_info.insert(tk.END, f"Headers: {response.headers}\n")
            
            scanner = nmap.PortScanner()
            target_host = "testphp.vulnweb.com"
            target_ports = "1-1000"
            result = scanner.scan(target_host, target_ports)

            self.output_field_info.insert(tk.END, f"\nPort Scan Results for {target_host}:\n")
            for host in result["scan"]:
                for port in result["scan"][host]["tcp"]:
                    port_info = result["scan"][host]["tcp"]
        except requests.exceptions.RequestException as e:
            self.output_field_info.insert(tk.END, f"Error: {e}\n")
    
    def configure_directory_scan_frame(self):
        self.directory_scan_frame.grid(row=0, column=0, rowspan=12, columnspan=12, sticky="nsew")
        for i in range(12):
            self.directory_scan_frame.rowconfigure(i, minsize=50)
            self.directory_scan_frame.columnconfigure(i, minsize=70)
        ip_label = tk.Label(self.directory_scan_frame, text="URL/IP ADDRESS:", font=("Helvetica", 12), background="black", foreground="white")
        ip_label.grid(row=1, column=2, pady=10, sticky="e")

        self.ip_address_entry = tk.Entry(self.directory_scan_frame, width=40)
        self.ip_address_entry.grid(row=1, column=3, columnspan=3, pady=10, sticky="w")

        directory_button = tk.Button(self.directory_scan_frame, text="Select Directory List", command=self.browse_file)
        directory_button.grid(row=2, column=3, columnspan=3, pady=20, sticky="w")

        check_button = tk.Button(self.directory_scan_frame, text="Check Directories", command=lambda: self.check_directories(self.file_path))
        check_button.grid(row=3, column=3, columnspan=3, pady=20, sticky= "w")

        self.output_field = tk.Text(self.directory_scan_frame, wrap=tk.WORD, width=80, height=15)
        self.output_field.grid(row=4, column=3, columnspan=3, pady=20)

        back_button = tk.Button(self.directory_scan_frame, text="Back", command=lambda: self.show_frame(self.first_frame), font=("Helvetica", 12),
                                foreground="#000000", relief="raised", bd=3, activebackground="#144552", activeforeground="red")
        back_button.grid(row=5, column=3, sticky="w", padx=10, pady=20)
        back_button.config(width=8)

    def configure_info_frame(self):
        self.info_frame.grid(row=0, column=0, rowspan=12, columnspan=12, sticky="nsew")
        for i in range(12):
            self.info_frame.rowconfigure(i, minsize=50)
            self.info_frame.columnconfigure(i, minsize=70)
        
        self.url_entry = tk.Entry(self.info_frame, width=40)
        self.url_entry.grid(row=1, column=3, columnspan=3, pady=10, sticky= "w")

        url_label = tk.Label(self.info_frame, text="URL:", font=("Helvetica", 12), background="black", foreground="white")
        url_label.grid(row=1, column=2, pady=13, sticky="e")

        start_button = tk.Button(self.info_frame, text="Start", command=self.start_gather_info)
        start_button.grid(row=2, column=3, columnspan=3, pady=20)

        save_button = tk.Button(self.info_frame, text="Save Output", command=self.save_output)
        save_button.grid(row=3, column=3, columnspan=3, pady=20)

        self.output_field_info = tk.Text(self.info_frame, wrap=tk.WORD, width=80, height=15)
        self.output_field_info.grid(row=4, column=3, columnspan=3, pady=20)

        back_button_info = tk.Button(self.info_frame, text="Back", command=lambda: self.show_frame(self.first_frame), font=("Helvetica", 12),
                                     foreground="#000000", relief="raised", bd=3, activebackground="#144552", activeforeground="red")
        back_button_info.grid(row=5, column=3, sticky="w", padx=10, pady=20)
        back_button_info.config(width=8)

    

if __name__ == "__main__":
    root = tk.Tk()
    app = WebEnumerationTool(root)
    root.mainloop()
