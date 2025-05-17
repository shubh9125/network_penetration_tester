import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
import socket
import threading
import ipaddress
import subprocess
import os

# ---------- Scanner Logic (same as before) ----------

def scan_port(ip, port, results):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((ip, port))
        results.append(f"[+] Port {port} is open on {ip}")
        s.close()
    except:
        pass

def scan_ip_range_gui(network, output_text):
    results = []
    try:
        net = ipaddress.ip_network(network, strict=False)
        for ip in net.hosts():
            output_text.insert(tk.END, f"Scanning {ip}...\n")
            output_text.see(tk.END)
            output_text.update()
            threads = []
            for port in range(1, 1025):
                t = threading.Thread(target=scan_port, args=(str(ip), port, results))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")
    for r in results:
        output_text.insert(tk.END, r + "\n")

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return None

vuln_db = {
    "vsFTPd 2.3.4": "Backdoor vulnerability (CVE-2011-2523)",
    "Apache/2.2.8": "Multiple vulnerabilities (CVE-2009-3555)",
    "OpenSSH 5.3": "Potential RCE risk"
}

def detect_vulnerabilities(banner):
    for service, warning in vuln_db.items():
        if service in banner:
            return f"[!] Vulnerability detected: {warning}"
    return "[+] No known vulnerabilities."

weak_passwords = ["123456", "admin", "password", "letmein", "qwerty"]

def check_password_strength(pw):
    if pw in weak_passwords:
        return "[!] Weak password detected."
    elif len(pw) < 8:
        return "[!] Password too short."
    else:
        return "[+] Password strength acceptable."

def generate_report(data, output_text):
    filename = "pentest_report.txt"
    with open(filename, "w") as f:
        f.write("---- Penetration Test Report ----\n")
        for line in data:
            f.write(line + "\n")
    output_text.insert(tk.END, f"[+] Report saved to {filename}\n")

def use_c_scanner(ip, port, output_text):
    if not os.path.exists("./portscanner"):
        output_text.insert(tk.END, "[-] C scanner not found. Compile 'portscanner.c' first.\n")
        return
    try:
        output = subprocess.check_output(["./portscanner", ip, str(port)]).decode()
        output_text.insert(tk.END, output.strip() + "\n")
    except subprocess.CalledProcessError:
        output_text.insert(tk.END, "[-] C scanner error occurred.\n")

# ---------- GUI Setup ----------

def main_gui():
    root = tk.Tk()
    root.title("Network Penetration Testing System")
    root.geometry("700x500")

    output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=85, height=25)
    output_text.pack(pady=10)

    # --- Buttons ---
    def scan_network():
        subnet = simpledialog.askstring("Subnet", "Enter subnet (e.g., 192.168.1.0/24):")
        if subnet:
            threading.Thread(target=scan_ip_range_gui, args=(subnet, output_text)).start()

    def banner_check():
        ip = simpledialog.askstring("IP Address", "Enter IP address:")
        port = simpledialog.askinteger("Port", "Enter port number:")
        if ip and port:
            banner = banner_grab(ip, port)
            if banner:
                output_text.insert(tk.END, f"[+] Banner: {banner}\n")
                result = detect_vulnerabilities(banner)
                output_text.insert(tk.END, result + "\n")
            else:
                output_text.insert(tk.END, "[-] No banner found.\n")

    def check_password():
        pw = simpledialog.askstring("Password", "Enter password to check:")
        if pw:
            result = check_password_strength(pw)
            output_text.insert(tk.END, result + "\n")

    def run_c_scanner():
        ip = simpledialog.askstring("IP Address", "Enter IP address:")
        port = simpledialog.askstring("Port", "Enter port number:")
        if ip and port:
            use_c_scanner(ip, port, output_text)

    def create_sample_report():
        sample_data = [
            "Scanned IP: 192.168.1.10",
            "Open Port: 22 (SSH)",
            "Banner: OpenSSH 5.3",
            "Vulnerability: Potential RCE"
        ]
        generate_report(sample_data, output_text)

    tk.Button(root, text="Scan IP Range & Ports", command=scan_network).pack(fill=tk.X)
    tk.Button(root, text="Banner Grab & Vulnerability Check", command=banner_check).pack(fill=tk.X)
    tk.Button(root, text="Password Strength Checker", command=check_password).pack(fill=tk.X)
    tk.Button(root, text="Use C-based Port Scanner", command=run_c_scanner).pack(fill=tk.X)
    tk.Button(root, text="Generate Sample Report", command=create_sample_report).pack(fill=tk.X)
    tk.Button(root, text="Exit", command=root.quit).pack(fill=tk.X)

    root.mainloop()

if __name__ == "__main__":
    main_gui()
