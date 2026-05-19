# ThreatLens v3.0 - Sentinel Protocol

**AI-Driven Malware Triage & Deep Swarm Inspection**

![ThreatLens Demo](assets/demo.gif)

If the image preview does not load on your device, open it directly: [View Demo GIF](assets/demo.gif)

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Available-brightgreen)](https://your-deployment-url.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

ThreatLens is a full-stack, real-time malware triage platform that automates file analysis by combining **deterministic risk scoring**, a **multi-agent AI swarm**, **YARA-Lite signature scanning**, **PE binary analysis**, **Authenticode signature verification**, and **global threat intelligence** — all streamed live to a React dashboard.

---

## What's New in v3.0

| Feature | Description |
|---|---|
| **Sentinel Protocol Scoring** | Deterministic scoring remains binding. AI agents explain the Hard Risk Score and cannot override it. |
| **YARAify Integration** | Optional abuse.ch YARAify lookup/scan via `YARAIFY_AUTH_KEY`, with graceful zero-impact fallback when unavailable. |
| **MalwareBazaar Lookup** | Optional hash reputation lookup against MalwareBazaar via `MALWAREBAZAAR_AUTH_KEY`. Confirmed known malware adds the highest-confidence deterministic signal. |
| **Simulated Sandbox Analysis** | PE import mapping to behaviors such as process injection, persistence, credential access, network activity, and ransomware indicators. |
| **MITRE ATT&CK Reporting** | Sandbox behaviors are mapped into ATT&CK techniques and shown in the frontend report. |
| **Email (.eml) Triage** | Parses EML metadata, URLs, and attachments. Attachments run through the existing forensic pipeline. |
| **SOC Admin Portal** | PIN-protected dashboard with live scan feed, statistics, high-risk threat feed, and simulated quarantine actions. |
| **Webhook Alerts** | Optional Slack/Discord high-risk alerts when webhook URLs are configured. |
| **Headless API Mode** | `/api/v1/scan` supports CI/CD and automation with API-key protection and synchronous JSON results. |

### SOC Admin PIN

The SOC Portal button opens the admin dashboard login. The PIN is controlled by `ADMIN_PIN` in `project/.env`; if it is not set, local development defaults to `1337`. The PIN is only for the browser login gate. Admin API calls use `ADMIN_API_KEY`, which should be set to a long random value in production.

Never commit `project/.env`. It is ignored by Git and should hold real API keys, webhook URLs, and private admin/API secrets.

## What's New in v2.0

| Feature | Description |
|---|---|
|  **Hard Risk Scorer** | Deterministic, pre-AI numeric scoring engine (`riskScorer.js`). Computes a 0–100 score based on extension mismatch, entropy, digital signature trust, VirusTotal detections, YARA hits, and IAT classification — before any AI runs. Bands: `<20 LOW`, `20–60 SUSPICIOUS`, `>60 HIGH`. |
|  **3-Agent Swarm (Deep Swarm Inspection)** | Agent 1 (Static Analyst) → Agent 2 (Threat OSINT) → Agent 3 (Lead Investigator). Each agent is grounded by the Hard Risk Score and cannot override or escalate it. |
|  **PE Binary Parser** | Pure-JS portable executable parser (`peParser.js`) — extracts architecture (x86/x64), sections, entry point, and full Import Address Table (IAT). Zero native dependencies. |
|  **YARA-Lite Engine** | Regex and byte-pattern matching engine (`yaraEngine.js`) with 5 rule families: Crypto Wallet, Ransomware, C2/Network, Suspicious PE Imports, and Obfuscation. Includes `validate` callbacks for false-positive prevention (e.g., PDF checksums vs real BTC addresses). |
|  **Authenticode Verifier** | Manual ASN.1 PKCS#7 walker using `node-forge` — extracts publisher, issuer, validity dates, and trust status. Trusted vendor signatures act as a Trust Anchor that reduces risk. |
|  **Risk Score UI Card** | Frontend displays a prominent risk badge with numeric score, color-coded classification (green/yellow/red), and full signal-by-signal breakdown with +/− deltas. |
|  **429 Retry with Backoff** | Agent API calls automatically retry up to 3 times on HTTP 429 (rate limit) with exponential backoff and `Retry-After` header support. |
|  **Security Hardened** | `helmet` security headers, `express-rate-limit` (30 req/15min), CORS restricted to dev origins, 10 MB upload limit (demo-safe), filename sanitization, auto-cleanup of uploaded files. |
|  **False-Positive Prevention** | BTC regex requires non-hex Base58 chars (rejects MD5/SHA hashes). PE imports rule requires the full injection triad (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread). AI prompts are score-grounded and explicitly told not to flag benign APIs. |

---

## Key Features

- **Byte-Level File Signatures (Magic Bytes):** Extracts the first 4 hex bytes and cross-references against the claimed extension to catch spoofed executables (e.g., `.exe` disguised as `.pdf`).

- **Shannon Entropy Calculation:** Computes binary data unpredictability (0.0–8.0 bits/byte). Contextualised per file type — compressed formats (.zip, .png, .pdf) naturally have high entropy.

- **Threat Intelligence (VirusTotal v3):** Queries 70+ global AV engines against the file's SHA-256 hash with timeout handling and graceful fallback notes.

- **AI Agent Swarm Analysis:** Streams real-time forensic reports via SSE. Each agent is bound by the deterministic Hard Risk Score — AI explains the score, it doesn't invent it.

- **PE Import Address Table (IAT) Analysis:** Parses and clusters Windows API imports into BENIGN / HIGH-RISK / ANTI-ANALYSIS categories. Only the injection triad triggers YARA alerts.

- **YARA-Lite Signature Scanning:** 5 rule families with strict validation callbacks to prevent false positives on hex hashes, PDF internals, and benign system APIs.

- **Digital Signature Trust Anchoring:** Authenticode verification acts as the strongest trust signal — trusted vendor signatures with 0 VT detections = safe, no escalation.

- **ASCII String Extraction:** Surfaces printable strings (6+ chars) to reveal hardcoded IPs, URLs, PE artifacts, or tool marks indicating malware staging.

- **EXIF/Metadata Analysis:** Parses filesystem and EXIF metadata to detect spoofed provenance, tampered images, or privacy-sensitive leaks.

- **Exportable HTML Reports:** Generates polished, downloadable forensic reports from the full 3-agent swarm analysis.

- **Hard Risk Score Display:** Frontend card shows the numeric score, classification badge (LOW/SUSPICIOUS/HIGH), and a full breakdown of every scoring signal with +/− deltas.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    ThreatLens React Dashboard                       │
│                                                                    │
│  File / Email Upload  → Risk + Reputation Cards → MITRE Table       │
│  LiveTerminal         → Agent progress + report download            │
│  SOC Portal           → Admin stats, live feed, quarantine actions   │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                │ POST /upload
                                │ POST /analyze/email
                                │ GET  /api/swarm-stream
                                │ GET  /admin/*
                                │ POST /api/v1/scan
┌───────────────────────────────▼────────────────────────────────────┐
│                 ThreatLens Express Backend (port 5000)              │
│                                                                    │
│  1. File identity: SHA-256, entropy, magic bytes, strings, EXIF      │
│  2. Local static analysis: PE parser, IAT, Authenticode, YARA-Lite   │
│  3. Reputation: VirusTotal, YARAify, MalwareBazaar                   │
│  4. Simulated sandbox: import behaviors + MITRE ATT&CK mapping       │
│  5. ═══ Hard Risk Scorer (deterministic, binding, pre-AI) ═══        │
│  6. Analysis store: admin feed, stats, quarantine/review flags        │
│  7. Optional alerts: Slack / Discord webhooks for HIGH risk           │
│  8. AI swarm explains score: Static → OSINT → Sandbox → Lead          │
│  9. HTML report generation + headless JSON API output                 │
└────────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

- **Frontend:** React 19, Vite 7, Tailwind CSS v4
- **Backend:** Node.js, Express 5, Multer
- **AI:** OpenRouter API (free tier)
- **Threat Intel:** VirusTotal API v3
- **Community Intel:** YARAify and MalwareBazaar via abuse.ch APIs
- **Crypto:** node-forge (ASN.1 / PKCS#7 parsing)
- **Email Parsing:** mailparser for `.eml` triage
- **Security:** helmet, express-rate-limit, CORS
- **Architecture:** Server-Sent Events (SSE) for real-time streaming

---

## Local Setup

### 1. Clone the Repository

```bash
git clone https://github.com/waris206/ThreatLens.git
cd ThreatLens/project
```



### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the `project/` directory:

```env
OPENROUTER_API_KEY=your_openrouter_key
VIRUSTOTAL_API_KEY=your_virustotal_key
YARAIFY_AUTH_KEY=your_yaraify_auth_key
MALWAREBAZAAR_AUTH_KEY=your_malwarebazaar_auth_key
ADMIN_PIN=1337
ADMIN_API_KEY=generate_a_long_random_admin_key
API_KEY=generate_a_long_random_headless_api_key
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=
```

### 4. Start the Servers

**Terminal 1 (Backend API):**

```bash
node server.js
```

Server runs on `http://localhost:5000`

**Terminal 2 (Frontend UI):**

```bash
npm run dev
```

Frontend runs on `http://localhost:5173`

---

## Project Structure

```
project/
├── server.js                    # Express backend: uploads, SSE, admin, API, email routes
├── forensics.js                 # Entropy, magic bytes, strings, EXIF, Authenticode
├── riskScorer.js                # Deterministic Hard Risk Scorer (binding, pre-AI)
├── yaraEngine.js                # YARA-Lite signature scanning engine
├── peParser.js                  # Pure-JS PE parser and import table extraction
├── forensics/
│   ├── yaraifyScanner.js        # Optional abuse.ch YARAify lookup/scan
│   ├── malwareBazaar.js         # MalwareBazaar hash reputation lookup
│   ├── sandboxAnalyzer.js       # Simulated sandbox behavior + MITRE ATT&CK mapping
│   └── emlParser.js             # EML metadata, URL, and attachment parsing
├── utils/
│   └── webhookAlerter.js        # Optional Slack/Discord HIGH-risk alerts
├── vite.config.js               # Vite config
├── src/
│   ├── App.jsx                  # Main app state, file/email upload flow, SOC overlay
│   └── components/
│       ├── Navbar.jsx                 # Top nav + SOC Portal button
│       ├── FileUploadZone.jsx         # File/email drag-drop + mode selector
│       ├── FileDetailsCard.jsx        # Score, reputation, MITRE, PE/IAT, signatures
│       ├── LiveTerminal.jsx           # SSE agent progress + report download
│       ├── InvestigationTimeline.jsx  # Progress stages
│       └── admin/
│           ├── AdminPortal.jsx        # SOC overlay shell
│           ├── AdminLogin.jsx         # PIN login
│           ├── AdminDashboard.jsx     # Live analysis table + quarantine action
│           ├── AdminStatsBar.jsx      # Daily scan statistics
│           └── ThreatFeed.jsx         # Last 10 HIGH-risk detections
└── uploads/                       # Generated HTML reports only
```

---

##  Risk Scoring Logic

| Signal | Delta | Condition |
|---|---|---|
| Extension mismatch | +30 | Magic bytes don't match claimed extension |
| Trusted digital signature | −50 | Valid Authenticode from known vendor |
| Untrusted signature | −10 | Signed but by unknown publisher |
| Unsigned PE | +20 | PE file with no digital signature |
| VT clean (0 malicious) | −20 | All engines report clean |
| VT low detections (1–3) | +20 | Few engines flag it |
| VT medium (4–10) | +40 | Multiple engines flag it |
| VT high (>10) | +60 | Widespread detection |
| High entropy (non-compressed) | +15 | >7.2 bits/byte on non-archive types |
| YARA critical hit | +35 | Critical severity rule triggered |
| YARA high hit | +25 | High severity rule triggered |
| No YARA hits | −10 | Passed all automated signature screening |
| Injection triad in IAT | +40 | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread |
| YARAify rule match | +30 | YARAify returned one or more community YARA matches |
| YARAify multi-match | +20 | YARAify returned more than five matches |
| YARAify known malware | +25 | YARAify/ClamAV context marks sample as known malware |
| YARAify high-impact family | +20 | Family tag includes ransomware, RAT, stealer, or loader |
| MalwareBazaar confirmed malware | +60 | SHA-256 exists in MalwareBazaar malware database |
| Sandbox process injection | +35 | Simulated sandbox maps imports to process injection |
| Sandbox persistence | +25 | Imports map to persistence behavior |
| Sandbox defense evasion | +20 | Imports map to anti-analysis / evasion behavior |
| Sandbox credential access | +30 | Imports map to credential access behavior |
| Sandbox ransomware indicators | +40 | Imports map to encryption / drive traversal behavior |
| Sandbox network communication | +15 | Imports map to network communication behavior |

**Bands:** Score < 20 → **LOW** | 20–60 → **SUSPICIOUS** | > 60 → **HIGH**

---

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Developed by [waris206](https://github.com/waris206)
