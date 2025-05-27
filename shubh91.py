import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
import socket
import threading
import ipaddress
import os
from datetime import datetime

# ---------- Global Data for Report ----------
scan_results = []
banner_results = []
vulnerability_results = []
password_checks = []

# ---------- Core Functions ----------
def scan_port(ip, port, results):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((ip, port))
        banner = banner_grab(ip, port)
        result = f"[+] {ip}:{port} is open"
        results.append(result)
        scan_results.append(result)
        if banner:
            banner_info = f"[BANNER] {ip}:{port} => {banner}"
            banner_results.append(banner_info)
            vuln_info = detect_vulnerabilities(banner)
            if vuln_info:
                vuln_msg = f"[!] {ip}:{port} {vuln_info}"
                vulnerability_results.append(vuln_msg)
        s.close()
    except:
        pass

def scan_ip_range_gui(network, output_text):
    results = []
    try:
        net = ipaddress.ip_network(network, strict=False)
        for ip in net.hosts():
            output_text.insert(tk.END, f"\n[~] Scanning {ip}\n")
            output_text.update()
            threads = []
            for port in range(1, 100):  # Faster scan limit
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
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except:
        return None

vuln_db = {
    "vsFTPd 2.3.4": "Backdoor vulnerability (CVE-2011-2523)",
    "Apache/2.2.8": "Multiple vulnerabilities (CVE-2009-3555)",
    "OpenSSH 5.3": "Potential RCE risk",
    "Microsoft-IIS/6.0": "Buffer overflow vulnerability"
}

def detect_vulnerabilities(banner):
    for service, warning in vuln_db.items():
        if service in banner:
            return f"Vulnerability detected: {warning}"
    return None

weak_passwords = ["123456", "admin", "password", "letmein", "qwerty"]

def check_password_strength(pw):
    if pw in weak_passwords:
        msg = "[!] Weak password detected."
    elif len(pw) < 8:
        msg = "[!] Password too short."
    else:
        msg = "[+] Password strength acceptable."
    password_checks.append(f"Password '{pw}': {msg}")
    return msg

def generate_report(output_text):
    filename = "pentest_report.txt"
    with open(filename, "w") as f:
        f.write("========= Penetration Test Report =========\n")
        f.write(f"Generated on: {datetime.now()}\n\n")

        f.write("---- Port Scan Results ----\n")
        for line in scan_results:
            f.write(line + "\n")

        f.write("\n---- Banner Grabbing Results ----\n")
        for line in banner_results:
            f.write(line + "\n")

        f.write("\n---- Vulnerability Results ----\n")
        for line in vulnerability_results:
            f.write(line + "\n")

        f.write("\n---- Password Strength Checks ----\n")
        for line in password_checks:
            f.write(line + "\n")

    output_text.insert(tk.END, f"\n[✓] Report saved as {filename}\n")

# ---------- GUI Setup ----------
def main_gui():
    root = tk.Tk()
    root.title("Advanced Penetration Testing Tool")
    root.geometry("800x600")

    output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
    output_text.pack(pady=10)

    # --- Buttons ---
    button_frame = tk.Frame(root)
    button_frame.pack()

    def scan_network():
        subnet = simpledialog.askstring("Subnet", "Enter subnet (e.g., 192.168.1.0/30):")
        if subnet:
            threading.Thread(target=scan_ip_range_gui, args=(subnet, output_text)).start()

    def banner_manual():
        ip = simpledialog.askstring("IP Address", "Enter IP address:")
        port = simpledialog.askinteger("Port", "Enter port number:")
        if ip and port:
            banner = banner_grab(ip, port)
            if banner:
                output_text.insert(tk.END, f"[+] Banner: {banner}\n")
                banner_results.append(f"{ip}:{port} => {banner}")
                vuln = detect_vulnerabilities(banner)
                if vuln:
                    output_text.insert(tk.END, f"[!] {vuln}\n")
                    vulnerability_results.append(f"{ip}:{port} => {vuln}")
                else:
                    output_text.insert(tk.END, "[+] No known vulnerabilities found.\n")
            else:
                output_text.insert(tk.END, "[-] No banner detected.\n")

    def password_check():
        pw = simpledialog.askstring("Password", "Enter password to check:")
        if pw:
            result = check_password_strength(pw)
            output_text.insert(tk.END, result + "\n")

    def generate_final_report():
        generate_report(output_text)

    tk.Button(button_frame, text="1. Scan IP Range & Ports", command=scan_network, width=30).grid(row=0, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="2. Manual Banner Grab & Vuln Check", command=banner_manual, width=30).grid(row=0, column=1, padx=5, pady=5)
    tk.Button(button_frame, text="3. Password Strength Checker", command=password_check, width=30).grid(row=1, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="4. Generate Final Report", command=generate_final_report, width=30).grid(row=1, column=1, padx=5, pady=5)
    tk.Button(button_frame, text="5. Exit", command=root.quit, width=30, fg="red").grid(row=2, column=0, columnspan=2, pady=10)

    root.mainloop()

# ---------- Entry ----------
if __name__ == "__main__":
     main_gui()
