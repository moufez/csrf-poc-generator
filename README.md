# CSRF PoC Generator & Analyzer

A single-file Python tool for authorized CSRF testing. It parses a raw HTTP request (Burp Suite style), runs a heuristic risk analysis, generates a working PoC exploit page, and produces a report — all offline, no dependencies.

> **Authorized testing only.** Use it on programs you're enrolled in, engagements you're contracted for, or your own applications.

---

## Overview

During a CSRF assessment you typically repeat the same steps for every state-changing endpoint: capture the request, check for tokens/SameSite/Origin validation, build a PoC, confirm it fires, then write it up. This tool automates that loop from a single pasted request.

**Capabilities**

- Parses raw HTTP/1.1 and HTTP/2 requests (CRLF or LF)
- Heuristic risk scoring based on auth model, token presence, Origin/Referer, custom headers
- PoC generation: auto-form, GET, POST, multipart, JSON via `fetch`/`XHR`, iframe
- HTML/Markdown report generation
- Token entropy analysis, request diffing, parameter mutation utilities
- GUI (Tkinter, 10 themes) and CLI, both fully functional standalone

---

## Workflow

### 1. Capture the request in Burp Suite

Send the target request through Proxy or Repeater and copy it as raw text.

![Burp Suite capture](screenshots/burp.png)

### 2. Paste and parse it

The **Request Analyzer** tab parses the request and extracts method, body type, endpoint category, parameters, cookies, and headers.

![Request Analyzer tab](screenshots/parse_request.png)

### 3. Review the CSRF analysis

The **CSRF Analysis** tab reports risk level, authentication model, token detection, and concrete remediation recommendations.

![CSRF Analysis tab](screenshots/csrf_analyse.png)

### 4. Generate the PoC

Pick a PoC type, optionally edit parameters, and generate an auto-submitting exploit page.

![Generated PoC tab](screenshots/generat_poc.png)

### 5. Export a report

Combine the request, analysis, and PoC into a Markdown or HTML report for the write-up.

![Reports tab](screenshots/generat_report.png)

---

## Installation

Standard library only — `requirements.txt` is intentionally empty of packages (comments only), since no third-party dependency is needed to run the core tool.

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/csrf-poc-generator.git
cd csrf-poc-generator

# 2. (Optional) create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install requirements (no-op — confirms your Python setup, nothing to download)
pip install -r requirements.txt

# 4. Run it
python3 csrf_poc.py --help
```

**GUI dependency (not a pip package):** the GUI uses `tkinter`, which ships with most Python installs but is a separate OS package on some Linux distros:

```bash
# Debian/Ubuntu
sudo apt install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch
sudo pacman -S tk
```

If you only use the CLI (`--analyze`, `--generate`, `--report`, `diff`), `tkinter` isn't required at all.

---

## CLI Usage

```bash
# Analyze
python3 csrf_poc.py request.txt --analyze --tokens

# Generate a PoC
python3 csrf_poc.py request.txt --generate post -o poc.html

# Generate a report
python3 csrf_poc.py request.txt --report html -o report.html

# Diff two requests
python3 csrf_poc.py diff before.txt after.txt
```

PoC types: `auto_form`, `get`, `post`, `multipart`, `json_fetch`, `json_xhr`, `iframe`.

---

## Risk Model

| Risk | Basis |
|---|---|
| High | Cookie-based session, no CSRF token, no custom header requirement |
| Medium | Partial protection present, unverifiable from the request alone |
| Low | Strong protection detected, or header/Bearer-token auth (not exploitable via classic CSRF) |
| Info | No authentication mechanism identified |

The analysis is static and request-only — it cannot see server-side `SameSite` handling or confirm actual Origin/Referer validation. Treat findings as leads to confirm with a live cross-origin test, not final conclusions.

---

## Persistence

Theme, last-used PoC type/auto-submit state, and per-endpoint edited parameters are cached in `~/.csrfgen/settings.json` and restored automatically on the next run. Reset via **File → Reset saved settings**.

---

## Author

Moufez Khadhraoui — khadhraoui.moufez@gmail.com · Discord `moufez` ([server](https://discord.gg/UkUgdj2DPb)) · [Instagram](https://instagram.com/mou_fez)

MIT License · Python 3.12+
