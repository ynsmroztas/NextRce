# NextRce - Next.js RSC Exploit Tool (CVE-2025-55182)

<div align="center">
  <img src="https://github.com/ynsmroztas/NextRce/blob/main/nextrce.jpg" alt="NextRce Logo" width="600px">
  <br><br>

  [![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)](https://www.python.org/)
  [![Vulnerability](https://img.shields.io/badge/Vulnerability-RCE-red?style=for-the-badge)](https://nvd.nist.gov/)
  [![WAF Bypass](https://img.shields.io/badge/WAF%20Bypass-UTF--16LE-magenta?style=for-the-badge)](https://github.com/ynsmroztas/NextRce)
  [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
  [![Twitter](https://img.shields.io/badge/Twitter-@ynsmroztas-1DA1F2?style=for-the-badge&logo=twitter)](https://x.com/ynsmroztas)

  <h3>Advanced Vulnerability Scanner & Exploiter for Next.js App Router</h3>
  
  <p>
    <b>Developed by <a href="https://x.com/ynsmroztas">Mitsec</a></b>
  </p>
</div>

---

## 🔥 New Feature: WAF Bypass Mode (UTF-16LE)

Standard payloads containing keywords like `child_process` or `execSync` are often blocked by Web Application Firewalls (WAFs). 

**NextRCSWaff.py** introduces a specialized **UTF-16LE (Little Endian)** encoding engine. By encoding the malicious payload in this specific format, the byte sequence changes completely, rendering it invisible to most signature-based WAFs. However, the Next.js (Node.js) server correctly decodes and executes the command.

<div align="center">
  <img src="https://github.com/ynsmroztas/NextRce/blob/main/waf-next-js.jpg" alt="WAF Bypass Proof of Concept" width="800px">
  <p><i>Proof of Concept: The screenshot above demonstrates a standard payload being blocked, followed by a successful RCE execution using the --bypass flag.</i></p>
</div>

---

## 📖 Description

**NextRce** is a high-performance, multithreaded security tool designed to detect and exploit **CVE-2025-55182**. It specifically targets the **React Server Components (RSC)** implementation within the Next.js **App Router** architecture.

By manipulating the serialization process in Server Actions, NextRce injects a crafted payload to achieve **Remote Code Execution (RCE)** on vulnerable instances. It features a smart detection engine that automatically distinguishes between vulnerable App Router architectures and safe legacy Pages Routers, ensuring efficiency during mass scans.

## 🚀 Key Features

* **🛡️ WAF Bypass (NextRCSWaff.py):** Utilizes UTF-16LE encoding to evade WAF detection while maintaining payload integrity on the server side.
* **Smart Architecture Detection:** Heuristically analyzes the DOM (looking for `window.__next_f`) to identify vulnerable **App Router** targets vs. legacy Pages Router sites.
* **Pipeline & CI/CD Ready:** Fully supports `stdin` piping. Seamlessly integrates with reconnaissance tools like `subfinder`, `httpx`, and `gau`.
* **Mass Scanning Engine:** Built-in `ThreadPoolExecutor` allows for scanning thousands of domains concurrently with minimal resource overhead.
* **Auto-Parsing:** Automatically extracts valid URLs from mixed input formats (e.g., status codes, titles, or raw logs).
* **Live RCE Feedback:** Executes commands and retrieves the output directly from the server's response digest.

## 🔍 Technical Analysis

### The Vulnerability (CVE-2025-55182)
Next.js App Router utilizes a custom serialization format for React Server Components (RSC). The vulnerability exists in the deserialization logic of `Next-Action` headers. When a specifically crafted object (polluting the `__proto__`) is sent to a server action endpoint (e.g., `/adfa`), the internal parser can be coerced into executing arbitrary Node.js code via `child_process`.

### Exploit Workflow
1.  **Reconnaissance:** NextRce sends a benign probe to check for `X-Powered-By: Next.js` headers and specific path structures (`/_next/`).
2.  **Fingerprinting:** It scans the response body for the App Router hydration marker:
    * `window.__next_f` -> **Vulnerable (App Router)**
    * `__NEXT_DATA__` -> **Safe (Pages Router)**
3.  **Payload Injection:** If the architecture is vulnerable, NextRce constructs a multipart/form-data request with a serialized malicious JSON object targeting the prototype.
4.  **Execution & Exfiltration:** The payload forces the server to run `execSync(cmd)`. The `stdout` is base64 encoded and returned in the `digest` field of the server's error response, which NextRce decodes and displays.

## 🛠️ Installation

```bash
# Clone the repository
git clone [https://github.com/ynsmroztas/NextRce.git](https://github.com/ynsmroztas/NextRce.git)

# Navigate to the directory
cd NextRce

# Install dependencies
pip install requests

💻 Usage Examples

1. WAF Bypass Mode (Using NextRCSWaff.py)
Use this script when the target appears vulnerable but standard exploits are blocked.

# Enable UTF-16LE encoding with the --bypass flag
python3 NextRCSWaff.py -u [https://target.com](https://target.com) -c "whoami" --bypass

2. Pipeline / Bug Bounty Mode

Designed for Linux pipelines. Pipe your subdomain lists directly into the tool.

# Standard scan
subfinder -d target.com -silent | httpx -sc -td -title -server -silent | python3 nextrce.py -c "id" -t 50

# WAF Bypass scan
subfinder -d target.com -silent | httpx -sc -td -title -server -silent | python3 NextRCSWaff.py -c "id" -B

3. Single Target Scan

Test a specific endpoint with a custom command using the standard script.

python3 nextrce.py -u [https://vulnerable.target.com](https://vulnerable.target.com) -c "cat /etc/passwd"

4. Mass Scan from File

Scan a list of URLs from a file with high concurrency.

python3 nextrce.py -l targets.txt -c "whoami" -t 100

⚙️ Command Line Options

Flag,Description,Default
"-u, --url",Single target URL to scan,None
"-l, --list",File path containing a list of URLs,None
"-c, --cmd",Command to execute on the server,id
"-t, --threads",Number of concurrent threads,30
"-p, --proxy","HTTP Proxy URL (e.g., http://127.0.0.1:8080)",None
"-v, --verbose",Enable verbose output (show failed attempts),False
"-B, --bypass",(NextRCSWaff.py only) Enable UTF-16LE encoding to bypass WAFs,False

⚠️ Disclaimer
This tool is developed for educational and security research purposes only. The author (Mitsec) is not responsible for any illegal use, damage, or unauthorized access caused by this tool. Always obtain explicit permission from the system owner before performing any security testing.

👤 Author
NextRce is developed and maintained by Mitsec.

Twitter/X: @ynsmroztas

GitHub: ynsmroztas
