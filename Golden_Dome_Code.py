from tkinter import *
from tkinter import font
from PIL import ImageTk, Image,  ImageOps
from tkinter import scrolledtext
import subprocess
from urllib.parse import urlparse
from tkinter import ttk, messagebox
import requests
from bs4 import BeautifulSoup
import socket
import google.generativeai as genai
import sys
import ssl, re
import os

def resource_path(relative_path):
    """
    Get absolute path to resource, works for dev and for PyInstaller
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # For development, use the current working directory
        base_path = os.path.abspath(".")

    # Construct the full path to the resource
    return os.path.join(base_path, relative_path)

genai.configure(api_key="")
model = genai.GenerativeModel('gemini-2.0-flash')

root = Tk()
root.title("Golden Dome")
root.configure(background="black")
root.geometry("900x685")
root.resizable(False, False)

photo = resource_path("Gemini_Generated_Image.png")
if os.path.exists(photo): #check if file exists before trying to load
    try:
        icon = PhotoImage(file=photo)
        root.iconphoto(False, icon)
    except TclError as e:
        print(f"Error loading icon: {e}")
else:
    print(f"Icon not found at {photo}")
#Funcs
def leave():
    root.destroy()

def next1():
    global peek, sniff, dig, select
    image_label.destroy()
    cont.destroy()
    no.destroy()

    select = Label(root, text="PLEASE SELECT MODE: ", font=la, fg='yellow', bg='black')
    select.place(x=309, y=40)

    #Pictues
    original_img1 = Image.open(resource_path("mag.png"))
    resized_img1 = original_img1.resize((25, 25))  # (width, height) in pixels

    padded_img = ImageOps.expand(
    resized_img1,
    border=(85, 0, 0, 0),  # (Left, Top, Right, Bottom)
    fill=(0, 0, 0, 0)       # Transparent (RGBA)
)
    
    original_img2 = Image.open(resource_path("nose.png"))
    resized_img2 = original_img2.resize((25, 25))  # (width, height) in pixels

    padded_img2 = ImageOps.expand(
    resized_img2,
    border=(85, 0, 0, 0),  # (Left, Top, Right, Bottom)
    fill=(0, 0, 0, 0)       # Transparent (RGBA)
)
    
    original_img3 = Image.open(resource_path("pick.png"))
    resized_img3 = original_img3.resize((25, 25))  # (width, height) in pixels

    padded_img3 = ImageOps.expand(
    resized_img3,
    border=(85, 0, 0, 0),  # (Left, Top, Right, Bottom)
    fill=(0, 0, 0, 0)       # Transparent (RGBA)
)

# 3. Convert to Tkinter PhotoImage
    mag = ImageTk.PhotoImage(padded_img)  # ← Correct conversion
    mag2 = ImageTk.PhotoImage(padded_img2)  # ← Correct conversion
    mag3 = ImageTk.PhotoImage(padded_img3)  # ← Correct conversion

    peek = Button(root, font=b, image=mag, text="PEEK MODE: Basic scan for ports/files", compound="left", anchor="w",  bg='#D5D5EB', width=700, height=35, justify=LEFT, padx=20, pady=20)
    peek.place(x=85, y=140)
    peek.config(command=p_run)
    peek.image = mag
  
    sniff = Button(root, font=b, image=mag2, text="SNIFF MODE: Tests forms & security flaws", compound="left", anchor="w",  bg='#D5D5EB', width=700, height=35, justify=LEFT, padx=20, pady=20)
    sniff.config(command=s_run)
    sniff.place(x=85, y=220)
    sniff.image = mag2

    dig = Button(root, font=b, image=mag3, text="DIG MODE: Advanced attack simulation", compound="left", anchor="w",  bg='#D5D5EB', width=700, height=35, justify=LEFT, padx=20, pady=20)
    dig.config(command=d_run)
    dig.place(x=85, y=300)
    dig.image = mag3

    
def p_run():
    global site_1
    peek.destroy()
    sniff.destroy()
    dig.destroy()
    select.destroy()

    webs = Label(root, text="WEB SCANNER", font=l1, fg='yellow', bg='black')
    webs.place(x=5, y=10)

    disc = Label(root, text="(Note: This software is proprietary to Ekyarele, Inc. Unauthorized reproduction\nor distribution may result in legal action.)", font=l1, fg='red',  justify=LEFT, bg='black')
    disc.place(x=5, y=40)

    signs = Label(root, text="+--------------------------------------------------------------------------------------+", font=l1, fg='lightgrey', bg='black')
    signs.place(x=5, y=100)

    site = Label(root, text="Website: ", font=l2, fg='yellow', bg='black')
    site.place(x=5, y=140)

    site_1 = Entry(root, font=l2, fg='yellow', bg='black', insertbackground="yellow")
    site_1.place(x=90, y=140)
    site_1.focus_set()


    run = Button(root, text="Run Command", font=l2, fg='yellow', bg='black')
    run.place(x=5, y=190)
    run.config(command=p2_run)

def s_run():
    global site_e2
    peek.destroy()
    sniff.destroy()
    dig.destroy()
    select.destroy()

    webs = Label(root, text="WEB SCANNER", font=l1, fg='yellow', bg='black')
    webs.place(x=5, y=10)

    disc = Label(root, text="(Note: This software is proprietary to Ekyarele, Inc. Unauthorized reproduction\nor distribution may result in legal action.)", font=l1, fg='red',  justify=LEFT, bg='black')
    disc.place(x=5, y=40)

    signs = Label(root, text="+--------------------------------------------------------------------------------------+", font=l1, fg='lightgrey', bg='black')
    signs.place(x=5, y=100)

    site = Label(root, text="Website: ", font=l2, fg='yellow', bg='black')
    site.place(x=5, y=140)

    site_e2 = Entry(root, font=l2, fg='yellow', bg='black', insertbackground="yellow")
    site_e2.place(x=90, y=140)
    site_e2.focus_set()

    run = Button(root, text="Run Command", font=l2, fg='yellow', bg='black')
    run.place(x=5, y=190)
    run.config(command=s2_run)

def d_run():
    global site_3
    peek.destroy()
    sniff.destroy()
    dig.destroy()
    select.destroy()

    webs = Label(root, text="WEB SCANNER", font=l1, fg='yellow', bg='black')
    webs.place(x=5, y=10)

    disc = Label(root, text="(Note: This software is proprietary to Ekyarele, Inc. Unauthorized reproduction\nor distribution may result in legal action.)", font=l1, fg='red',  justify=LEFT, bg='black')
    disc.place(x=5, y=40)

    signs = Label(root, text="+--------------------------------------------------------------------------------------+", font=l1, fg='lightgrey', bg='black')
    signs.place(x=5, y=100)

    site = Label(root, text="Website: ", font=l2, fg='yellow', bg='black')
    site.place(x=5, y=140)

    site_3 = Entry(root, font=l2, fg='yellow', bg='black', insertbackground="yellow")
    site_3.place(x=90, y=140)
    site_3.focus_set()


    run = Button(root, text="Run Command", font=l2, fg='yellow', bg='black')
    run.place(x=5, y=190)
    run.config(command=d2_run)


def p2_run():
    if not site_1.get():
        messagebox.showwarning("No Website Was Given", "Please provide url in order to run web scanner.")
    else:
        target_url = site_1.get()
    timeout = 3 # seconds
    # --- SCAN STARTS HERE ---
    results = []

    # Add http:// if missing (more concise version)
    if not target_url.startswith(('http://', 'https://')):
        target_url = f'http://{target_url}'

    try:
        # 1. Server Header Check (inlined)
        response = requests.get(target_url, timeout=timeout)
        results.append(f"[+] Server: {response.headers.get('Server', 'Not detected')}")

        # 2. Common Files Check
        common_files = ['robots.txt', 'sitemap.xml', '.env', 'admin.php']
        for file in common_files:
            try:
                if requests.get(f"{target_url}/{file}", timeout=timeout).status_code == 200:
                    results.append(f"[!] Exposed: /{file}")
            except requests.exceptions.RequestException: # Be more specific with exceptions
                pass # Suppress connection errors for individual files

        # 3. Port Scanner (Basic)
        domain = urlparse(target_url).hostname # Robust domain extraction
        if domain:
            ports = [80, 443, 8080, 22]  # Common ports
            open_ports = []
            for port in ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock: # Auto-closes socket
                    sock.settimeout(1)
                    if sock.connect_ex((domain, port)) == 0:
                        open_ports.append(str(port))
            if open_ports:
                results.append(f"[!] Open ports: {', '.join(open_ports)}")
        else:
            results.append(f"[X] Could not determine domain for port scan from {target_url}")

    except requests.exceptions.RequestException as e: # Catch request-specific errors for main URL
        results.append(f"[X] Network/HTTP Error: {str(e)}")
    except Exception as e: # Catch any other unexpected errors
        results.append(f"[X] General Error: {str(e)}")

    raw_data_for_api = "\n".join(results)

    # Now, embed raw_data_for_api into your prompt string
    # (This is conceptual, as API calls vary)
    prompt = f"""
    **Role:** Cybersecurity Analyst and Educator.

    **Task:** Summarize web application penetration test findings from Beautiful Soup output. Explain all findings and potential exploitations in simple, easy-to-understand terms, suitable for someone new to hacking. Keep explanations short, concise, and avoid overly technical jargon.

    **Input:** Raw parsed data (HTML, forms, links, scripts, etc.) from web reconnaissance.

    **Output:** Two sections: "Key Findings" and "Possible Exploitations."

    --- START RAW DATA ---
    {raw_data_for_api}
    --- END RAW DATA ---

    **Desired Output Format:**

    [A]. Key Findings:

    - [Short, simple explanation of observation 1 uppercase, not bold]
    - [Short, simple explanation of observation 2 uppercase, not bold]
    - ...

    [B]. Possible Exploitations:

    - [Short, simple explanation of exploitation method 1 in uppercase, not bold] - [Brief potential impact, all in lower case, letter]
    - [Short, simple explanation of exploitation method 2 in uppercase, not bold] - [Brief potential impact, all in lower case, except first letter]
    - ...

    [C]. Possible Solutions:
    - [Short, simple explanation of solution to patch exploitation method 1 in uppercase, not bold] - [Brief potential solution, all in lower case, letter]
    - [Short, simple explanation of solution to patch exploitation method 2 in uppercase, not bold] - [Brief potential solution, all in lower case, except first letter]
    - ...

    Note: if one the keyfindings is that the website timed out, then give instead of [B]. Possible Exploitations:

    - [Short, simple explanation of exploitation method 1 in uppercase, not bold] - [Brief potential impact, all in lower case, except the first letter, in the sentence]
    - [Short, simple explanation of exploitation method 2 in uppercase, not bold] - [Brief potential impact, all in lower case, except first letter, in the sentence]
    - ...

    Do:

    [B]. Possible Reasons For Timeout:

    - [Short, simple explanation of reason of timeout, uppercase not bold] - [Brief explanation, all in lower case, except the first letter in the sentence]
    - ...

    [C]. Due to timeout, no solutions be generated

    AND GIVE ME NOTHIGN ELSE, JSUT WHAT I ASKED 4!!!!!!!!!!!!!!!
    """
    frame = Frame(root, width=225, height=0.3)
    frame.place(x=5, y=240)

    # Create Text widget
    text_widget = Text(frame, wrap="word", font=("Courier", 12), bg='lightgrey')
    text_widget.pack(side=LEFT, fill=BOTH)

    # Create Scrollbar
    scrollbar = Scrollbar(frame, command=text_widget.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    scan_results = model.generate_content([prompt], stream=False)
    text_widget.config(state=NORMAL)
    text_widget.insert(END, f"Scan Report:\n===============================================================================\nWebsite: {target_url}\n\n{scan_results.text.strip()}")
    text_widget.config(state=DISABLED)


def s2_run():
    # --- CONFIG ---
    if not site_e2.get():
        messagebox.showwarning("No Website Was Given", "Please provide url in order to run web scanner.")
    else:
        target_url = site_e2.get()

    timeout = 10
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # --- CAPTURE RESULTS LIST ---
    results = [] # This list will store all your findings

    # --- SCAN STARTS HERE ---
    # These initial prints can stay as they are just informative

    try:
        # 1. Check HTTPS and Redirects
        # Ensure URL has scheme
        target_url = f'http://{target_url}' if not target_url.startswith(('http://', 'https://')) else target_url

        session = requests.Session()
        session.headers = {'User-Agent': user_agent}
        response = session.get(target_url, timeout=timeout, allow_redirects=True)
        response.raise_for_status()

        final_url = response.url
        results.append(f"[+] Server: {response.headers.get('Server', 'Not detected')}") # Capture Server Header
        results.append(f"[✓] HTTPS Enabled (Secure)" if final_url.startswith('https://') else "[!] HTTP Only (Insecure)")
        if final_url != target_url:
            results.append(f"[→] Redirects to: {final_url}")

        # 2. Security Headers Check
        results.append("\n[🔒 Security Headers]") # Append header line to results
        security_headers = [
            'Content-Security-Policy', 'X-Frame-Options',
            'X-Content-Type-Options', 'Strict-Transport-Security'
        ]
        for header in security_headers:
            results.append(f"[✓] {header}: {response.headers[header]}" if header in response.headers else f"[!] Missing: {header}")

        # 3. Form Vulnerability Checks
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        results.append(f"\n[📝 Found {len(forms)} Forms]") # Append header line to results
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                results.append("[!] No CSRF Token in Form")
            if form.find('input', {'type': 'password'}) and not final_url.startswith('https'):
                results.append("[!] Password Field Without HTTPS")

        # 4. Basic Injection Probe
        results.append("\n[💉 Injection Tests]") # Append header line to results
        test_params = {'q': "' OR 1=1 --", 'id': '<script>alert(1)</script>'}
        for param, payload in test_params.items():
            test_url = f"{final_url}?{param}={payload}"
            try:
                r = session.get(test_url, timeout=timeout)
                if "error" in r.text.lower() or "syntax" in r.text.lower():
                    results.append(f"[!] Possible SQLi in '{param}'")
                if payload in r.text:
                    results.append(f"[!] Possible XSS in '{param}'")
            except requests.exceptions.RequestException:
                pass

    except requests.exceptions.RequestException as e:
        results.append(f"[X] Network or HTTP error during scan: {e}") # Capture error

    except Exception as e:
        results.append(f"[X] An unexpected error occurred: {e}") # Capture error


    raw_scan_output = "\n".join(results)

    prompt = f"""
    **Role:** Cybersecurity Analyst and Educator.

    **Task:** Summarize the provided web penetration test findings. Explain all identified issues and their potential exploitations in simple, concise terms, suitable for someone new to hacking. Focus on practical insights from the report.

    **Input:** Raw findings from an automated web reconnaissance tool, including server information, HTTPS status, security headers, form details (CSRF, password fields), and basic injection test results (SQLi, XSS).

    **Output:** Two short sections: "Key Findings" and "Possible Exploitations."

    --- START RAW DATA ---
    {raw_scan_output}
    --- END RAW DATA ---

    **Desired Output Format:**

    [A]. Key Findings:

    - [Short, simple explanation of a significant observation like a missing header or HTTP-only site, in uppercase, not bold]
    - [Short, simple explanation of another key finding, e.g., a form issue or server info, in uppercase, not bold]
    - ...

    [B]. Possible Exploitations:

    - [Short, simple explanation of exploitation method 1 in uppercase, not bold] - [Brief potential impact, all in lower case, letter]
    - [Short, simple explanation of exploitation method 2 in uppercase, not bold] - [Brief potential impact, all in lower case, except first letter]
    - ...

    [C]. Possible Solutions:
    - [Short, simple explanation of solution to patch exploitation method 1 in uppercase, not bold] - [Brief potential solution, all in lower case, letter]
    - [Short, simple explanation of solution to patch exploitation method 2 in uppercase, not bold] - [Brief potential solution, all in lower case, except first letter]
    - ...

    Note: if one the keyfindings is that the website timed out, then give instead of [B]. Possible Exploitations:

    - [Short, simple explanation of exploitation method 1 in uppercase, not bold] - [Brief potential impact, all in lower case, except the first letter, in the sentence]
    - [Short, simple explanation of exploitation method 2 in uppercase, not bold] - [Brief potential impact, all in lower case, except first letter, in the sentence]
    - ...

    Do:

    [B]. Possible Reasons For Timeout:

    - [Short, simple explanation of reason of timeout, uppercase not bold] - [Brief explanation, all in lower case, except the first letter in the sentence]
    - ...

    [C]. Due to timeout, no solutions be generated

    AND GIVE ME NOTHIGN ELSE, JSUT WHAT I ASKED 4!!!!!!!!!!!!!!!
    """
    frame = Frame(root, width=225, height=0.3)
    frame.place(x=5, y=240)

    # Create Text widget
    text_widget = Text(frame, wrap="word", font=("Courier", 12), bg='lightgrey')
    text_widget.pack(side=LEFT, fill=BOTH)

    # Create Scrollbar
    scrollbar = Scrollbar(frame, command=text_widget.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    scan_results = model.generate_content([prompt], stream=False)
    text_widget.config(state=NORMAL)
    text_widget.insert(END, f"Scan Report:\n===============================================================================\nWebsite: {target_url}\n\n{scan_results.text.strip()}")
    text_widget.config(state=DISABLED)


def d2_run():
        # --- CONFIG ---
    if not site_3.get():
        messagebox.showwarning("No Website Was Given", "Please provide url in order to run web scanner.")
    else:
        target = site_3.get()  # CHANGE THIS
    timeout = 3

    # --- DIG MODE SCAN ---
    results = f"⛏️ DIG MODE SCAN REPORT: {target}\n\n"

    # 1. SSL/TLS Check
    try:
        ctx = ssl.create_default_context()
        hostname = urlparse(f"https://{target}").hostname or target
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                results += f"🔐 SSL PROTOCOL: {ssock.version()}\n"
                results += f"🔏 CERT EXPIRY: {cert['notAfter']}\n"
                if ssock.version() in ('TLSv1', 'TLSv1.1'):
                    results += "⚠️ INSECURE PROTOCOL DETECTED\n\n"
    except Exception as e:
        results += f"🔐 SSL CHECK FAILED: {str(e)}\n\n"

    # 2. Admin Panel Finder
    results += "🔑 ADMIN PANELS:\n"
    for path in ['admin','wp-login.php','backup','dashboard']:
        try:
            url = f"https://{target}/{path}"
            if requests.head(url, timeout=timeout).status_code == 200:
                results += f"⚠️ FOUND: /{path}\n"
        except:
            pass
    if "FOUND:" not in results:
        results += "✅ No common admin panels found\n"
    results += "\n"

    # 3. Vulnerability Checks
    results += "💉 VULNERABILITY TESTS:\n"
    tests = {
        'LFI': '/?file=../../etc/passwd',
        'Open Redirect': '/redirect?url=https://evil.com',
        'XSS': '/search?q=<script>alert(1)</script>'
    }
    vulns_found = False
    for name, test in tests.items():
        try:
            r = requests.get(f"http://{target}{test}", timeout=timeout)
            if ("root:" in r.text) or ("evil.com" in r.text) or ("<script>alert(1)" in r.text):
                results += f"🚨 {name} VULNERABILITY DETECTED\n"
                vulns_found = True
        except:
            pass
    if not vulns_found:
        results += "✅ No obvious vulnerabilities detected\n"

    

    prompt = f"""
    **Role:** Cybersecurity Analyst and Educator.

    **Task:** Summarize the provided web penetration test findings. Explain all identified issues and their potential exploitations in simple, concise terms, suitable for someone new to hacking. Focus on practical insights from the report.

    **Input:** Raw findings from an automated web reconnaissance tool, including server information, HTTPS status, security headers, form details (CSRF, password fields), and basic injection test results (SQLi, XSS).

    **Output:** Two short sections: "Key Findings" and "Possible Exploitations."

    --- START RAW DATA ---
    {results}
    --- END RAW DATA ---

    **Desired Output Format:**

    [A]. CRITICAL OBSERVATIONS:

    - [MAIN RISK 1 IN UPPERCASE]: 1-sentence plain English explanation
    - [MAIN RISK 2 IN UPPERCASE]: 1-sentence plain English explanation
    - ...

    [B]. EXPLOITATION GUIDE:

    - [EXPLOIT METHOD IN UPPERCASE] - [Impact]: Simple consequence description all lowercase except first letter in sentence
    - [EXPLOIT METHOD IN UPPERCASE] - [Impact]: Simple consequence description all lowercase except first letter in sentence
    - ...

    [C]. POSSIBLE SOLUTIONS:
    - [Short, simple explanation of solution to patch exploitation method 1 in uppercase, not bold] - [Brief potential solution, all in lower case, letter]
    - [Short, simple explanation of solution to patch exploitation method 2 in uppercase, not bold] - [Brief potential solution, all in lower case, except first letter]
    - ...

    Note: if one the keyfindings is that the website timed out, then give instead of [B]. Possible Exploitations:
    - [EXPLOIT METHOD IN UPPERCASE] - [Impact]: Simple consequence description starting lowercase except first letter in sentence
    - [EXPLOIT METHOD IN UPPERCASE] - [Impact]: Simple consequence description starting lowercase except first letter in sentence
    - ...
   

    Do:

    [B]. POSSIBLE REASON FOR TIMEOUT:

    - [Short, simple explanation of reason of timeout, uppercase not bold] - [Brief explanation, all in lower case, except the first letter in the sentence]
    - ...

    [C]. Due to timeout, no solutions be generated

    AND GIVE ME NOTHIGN ELSE, JSUT WHAT I ASKED 4!!!!!!!!!!!!!!!
    """
    frame = Frame(root, width=225, height=0.3)
    frame.place(x=5, y=240)

    # Create Text widget
    text_widget = Text(frame, wrap="word", font=("Courier", 12), bg='lightgrey')
    text_widget.pack(side=LEFT, fill=BOTH)

    # Create Scrollbar
    scrollbar = Scrollbar(frame, command=text_widget.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    scan_results = model.generate_content([prompt], stream=False)
    text_widget.config(state=NORMAL)
    text_widget.insert(END, f"Scan Report:\n===============================================================================\nWebsite: {target}\n\n{scan_results.text.strip()}")
    text_widget.config(state=DISABLED)


  

la = font.Font(family='Consolas', size=18, weight='bold')
l1 = font.Font(family='Consolas', size=14, weight='bold')
l2 = font.Font(family='Consolas', size=13, weight='bold')
a = font.Font(family='Courier', size=14)
b = font.Font(family='Courier', size=12)


# Create a label with Consolas font
image = image = Image.open(resource_path("New Project (2).png")) 
img = ImageTk.PhotoImage(image)

image_label = Label(root, image=img, bg='black')
image_label.place(x=40, y=10)

cont = Button(root, text="Yes", font=a, bg='lightgreen', width=17, height=2)
cont.place(x=345, y=320)
cont.config(command=next1)

no = Button(root, text="No", font=a, bg='red', width=17, height=2)
no.place(x=345, y=390)
no.config(command=leave)

root.mainloop()


