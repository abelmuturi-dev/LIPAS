<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f2027,50:203a43,100:2c5364&height=200&section=header&text=LIPAS&fontSize=70&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=Lightweight%20Penetration%20Assessment%20Suite&descAlignY=58&descSize=18" width="100%"/>

<a href="https://github.com/abelmuturi-dev/LIPAS">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&duration=2800&pause=900&color=2C5364&center=true&vCenter=true&multiline=true&repeat=true&width=600&height=50&lines=Subdomain+Recon+%E2%80%A2+Port+%26+TLS+Scanning;SQLi+%2F+XSS+Probing+%E2%80%A2+WAF+Fingerprinting;Built+for+Authorized+Security+Testing" alt="Typing SVG" />
</a>

<br/>

<img src="https://img.shields.io/badge/version-1.1.0-2C5364?style=for-the-badge&logo=semanticrelease&logoColor=white" />
<img src="https://img.shields.io/badge/python-3.8+-0f2027?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/license-MIT-203a43?style=for-the-badge" />
<img src="https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge" />

<br/><br/>

<img src="https://img.shields.io/github/stars/abelmuturi-dev/LIPAS?style=social" />
<img src="https://img.shields.io/github/forks/abelmuturi-dev/LIPAS?style=social" />

</div>

<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:2C5364,100:0f2027&height=3&width=100%" width="100%"/>

## 🔍 Overview

**LIPAS** *(Lightweight Penetration Assessment Suite)* is a comprehensive, modular, and fast web security assessment tool written in Python. One CLI, one target, a full reconnaissance-to-report pipeline.

<table>
<tr>
<td width="50%" valign="top">

### 🧭 Recon
- Subdomain enumeration (DNS + HTTP)
- DNS reconnaissance (A / MX / NS)
- Port scanning &amp; banner grabbing
- TLS certificate inspection
- Technology &amp; WAF/CDN fingerprinting

</td>
<td width="50%" valign="top">

### 🛡️ Vulnerability Checks
- Error-based SQL injection
- Reflected XSS
- CORS misconfiguration
- Risky HTTP methods
- Exposed sensitive files
- Cookie &amp; security-header audit
- HTML comment secret scanning
- security.txt discovery

</td>
</tr>
</table>

> [!WARNING]
> **Responsible use only.** Scan targets you own or have explicit written permission to test. Unauthorized scanning may be illegal.

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:2C5364,100:0f2027&height=3&width=100%" width="100%"/>

## 🆕 What's New in `1.1.0`

<details open>
<summary><b>Click to expand the full changelog</b></summary>
<br/>

| Area | Change |
|---|---|
| 🔎 **Subdomains** | Candidates now resolve over DNS *and* get confirmed with a real HTTP GET (HTTPS → HTTP fallback); DNS-only hits are still reported separately |
| 🔐 **TLS** | Reports issuer, subject, expiry countdown and SAN count — falls back to an unverified handshake (`certificate_trusted: false`) for self-signed certs instead of failing |
| 🧩 **Fingerprinting** | Detects Cloudflare, Sucuri, generic WAFs, AWS ELB/CloudFront, plus WordPress, Joomla, Drupal, Laravel, React and Angular |
| 🗺️ **Discovery** | Pulls extra in-scope endpoints from `robots.txt` and `sitemap.xml` |
| 📄 **security.txt** | Checks `/.well-known/security.txt` and extracts the contact field |
| 🍪 **Cookies** | Flags missing `HttpOnly`, `Secure` and `SameSite` attributes |
| 💬 **Comments** | Scans HTML comments for leaked secrets/API keys |
| 🌐 **CORS** | Detects reflected-origin-with-credentials and wildcard `ACAO` |
| ⚙️ **Methods** | Flags risky HTTP verbs — `PUT`, `DELETE`, `TRACE`, `CONNECT` |
| 💉 **SQLi / XSS** | Error-based SQLi + canary-based reflected XSS, each diffed against a benign control request to cut false positives |
| 🕊️ **Passive mode** | `--passive` disables all active probes for a safe, read-only scan |
| ⏱️ **Rate limiting** | `--rate-limit` sets delay between requests (default `0.5s`) |
| 🧮 **Bounded testing** | `max_active_tests` caps parameter probes to avoid runaway test matrices |
| 📊 **Reporting** | Every finding ships with severity, confidence and remediation guidance |
| 🖥️ **CLI** | Repeatable `-H/--headers`, cookie-string parsing, custom wordlists (`-w`), `--insecure` to skip TLS verification |

</details>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:2C5364,100:0f2027&height=3&width=100%" width="100%"/>

## 🛠 Installation

### From Source

```bash
git clone https://github.com/abelmuturi-dev/LIPAS.git
cd lipas
pip install -r requirements.txt
```

<br/>

<details>
<summary><b>⚡ Quick usage example</b></summary>
<br/>

```bash
python lipas.py -u https://example.com -o report.json
```

| Flag | Description |
|---|---|
| `-u, --url` | Target URL *(required)* |
| `-c, --cookies` | Cookies as `"name=value; name2=value2"` |
| `-H, --headers` | Custom header, repeatable |
| `-t, --threads` | Thread count (default `15`) |
| `-w, --wordlist` | Custom subdomain wordlist |
| `-o, --output` | Write JSON report to file |
| `--passive` | Safe mode — disable active probes |
| `--rate-limit` | Seconds between requests (default `0.5`) |
| `--insecure` | Disable TLS certificate verification |
| `-v, --verbose` | Verbose logging |

</details>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:2C5364,100:0f2027&height=3&width=100%" width="100%"/>

<div align="center">

**Made with 🖤 by [Abel Muturi](https://github.com/abelmuturi-dev)**

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:2c5364,50:203a43,100:0f2027&height=100&section=footer" width="100%"/>

</div>
