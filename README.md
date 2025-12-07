# NextRce - Next.js RSC Exploit Tool (CVE-2025-55182)

<div align="center">
  <img src="https://github.com/ynsmroztas/NextRce/blob/main/nextrce.jpg" alt="NextRce Logo" width="600px">
  <br><br>

  [![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)](https://www.python.org/)
  [![Vulnerability](https://img.shields.io/badge/Vulnerability-RCE-red?style=for-the-badge)](https://nvd.nist.gov/)
  [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
  [![Twitter](https://img.shields.io/badge/Twitter-@ynsmroztas-1DA1F2?style=for-the-badge&logo=twitter)](https://x.com/ynsmroztas)

  <h3>Advanced Vulnerability Scanner & Exploiter for Next.js App Router</h3>
  
  <p>
    <b>Developed by <a href="https://x.com/ynsmroztas">Mitsec</a></b>
  </p>
</div>

---

## 📖 Description

**NextRce** is a high-performance, multithreaded security tool designed to detect and exploit **CVE-2025-55182**. It specifically targets the **React Server Components (RSC)** implementation within the Next.js **App Router** architecture.

By manipulating the serialization process in Server Actions, NextRce injects a crafted payload to achieve **Remote Code Execution (RCE)** on vulnerable instances. It features a smart detection engine that automatically distinguishes between vulnerable App Router architectures and safe legacy Pages Routers, ensuring efficiency during mass scans.

## 🚀 Key Features

* **Smart Architecture Detection:** Heuristically analyzes the DOM (looking for `window.__next_f`) to identify vulnerable **App Router** targets vs. legacy Pages Router sites.
* **Pipeline & CI/CD Ready:** Fully supports `stdin` piping. Seamlessly integrates with reconnaissance tools like `subfinder`, `httpx`, and `gau`.
* **Mass Scanning Engine:** Built-in `ThreadPoolExecutor` allows for scanning thousands of domains concurrently with minimal resource overhead.
* **Auto-Parsing:** Automatically extracts valid URLs from mixed input formats (e.g., status codes, titles, or raw logs).
* **Live RCE Feedback:** Executes commands and retrieves the output directly from the server's response digest.
* **Proxy Support:** Full support for HTTP/HTTPS proxies (e.g., Burp Suite, Caido) for deep analysis.

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
git clone https://github.com/ynsmroztas/NextRce.git

# Navigate to the directory
cd NextRce

# Install dependencies
pip install requests
```

## 💻 Usage Examples

### 1. Pipeline / Bug Bounty Mode (Recommended)
NextRce is designed to work in a Linux pipeline. You can pipe the output of your subdomain discovery tools directly into NextRce.

```bash
# Scan subdomains, filter live hosts, and exploit immediately
subfinder -d target.com -silent | httpx -sc -td -title -server -silent | python3 nextrce.py -c "id" -t 50
```

### 2. Single Target Scan
Test a specific endpoint with a custom command.

```bash
python3 nextrce.py -u https://vulnerable.target.com -c "cat /etc/passwd"
```

### 3. Mass Scan from File
Scan a list of URLs from a file with high concurrency.

```bash
python3 nextrce.py -l targets.txt -c "whoami" -t 100
```

### 4. Proxy Mode (Debug)
Route traffic through Burp Suite or another proxy for analysis.

```bash
python3 nextrce.py -u https://target.com -p http://127.0.0.1:8080
```

## ⚙️ Command Line Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-u`, `--url` | Single target URL to scan | `None` |
| `-l`, `--list` | File path containing a list of URLs | `None` |
| `-c`, `--cmd` | Command to execute on the server | `id` |
| `-t`, `--threads` | Number of concurrent threads | `30` |
| `-p`, `--proxy` | HTTP Proxy URL (e.g., http://127.0.0.1:8080) | `None` |
| `-v`, `--verbose` | Enable verbose output (show failed attempts) | `False` |
| `-i`, `--shell` | Drop into an interactive shell after the first successful exploit (sequential mode) | `False` |

### 5. Interactive Shell (Opt-In)
After finding a vulnerable target, you can jump into a live shell without rerunning the script:

```bash
# Single target: enter shell after first success
python3 nextrce.py -i -u https://vulnerable.target.com

# From a list: shell opens on the first vulnerable host, then stops scanning
python3 nextrce.py -i -l targets.txt
```

## ⚠️ Disclaimer

This tool is developed for **educational and security research purposes only**. 
The author (**Mitsec**) is not responsible for any illegal use, damage, or unauthorized access caused by this tool. 
Always obtain explicit permission from the system owner before performing any security testing.

## 👤 Author

**NextRce** is developed and maintained by **Mitsec**.

* **Twitter/X:** [@ynsmroztas](https://x.com/ynsmroztas)
* **GitHub:** [ynsmroztas](https://github.com/ynsmroztas)

**CLI interactive shell flag contributed by:** [ToritoIO](https://github.com/ToritoIO) (Twitter/X: [@Xyborg](https://x.com/Xyborg))
