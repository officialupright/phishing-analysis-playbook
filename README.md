<h1 align="center">🎣 Phishing Analysis Playbook</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Use%20case-Phishing%20Triage-D14836?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-IOC%20Extractor-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/MITRE-T1566-C8102E?style=for-the-badge" />
</p>

<p align="center"><b>Phishing is still how most breaches start. This is the step-by-step process I use to go from<br/>"a user reported a weird email" to a confident verdict, contained threat, and clean report.</b></p>

---

## 🗺️ The Playbook at a Glance

```
 📥 1. RECEIVE  →  🔍 2. HEADERS  →  🔗 3. IOCs  →  🧪 4. DETONATE  →  ⚖️ 5. VERDICT  →  🧹 6. CONTAIN  →  📝 7. REPORT
```

| Step | Goal | Time budget |
|---|---|---|
| 1. Receive & preserve | Get the original `.eml` with full headers (never a forwarded copy) | 2 min |
| 2. Analyze headers | Who *really* sent it, and did authentication pass? | 5 min |
| 3. Extract IOCs | URLs, domains, IPs, attachment hashes | 3 min (scripted) |
| 4. Check reputation & detonate | What do the IOCs do? | 10 min |
| 5. Verdict | Legit · Spam · Phishing · Malware | 1 min |
| 6. Contain & scope | Purge, block, reset, hunt | 15+ min |
| 7. Report | Document so the next analyst learns from it | 10 min |

---

## 📥 Step 1: Receive & Preserve

- Ask the user to report using the **Report Phishing** button, or to send it **as an attachment**. Forwarding destroys the original headers.
- In Microsoft 365: *Microsoft Defender → Explorer*, find the message, and download the `.eml`.
- ⚠️ Never click links or open attachments on your workstation. Use a sandbox or an isolated VM.

## 🔍 Step 2: Analyze the Headers

Read the `Received:` headers **bottom to top**: the lowest one is closest to the true origin.

| Check | What good looks like | Red flag 🚩 |
|---|---|---|
| **SPF** | `spf=pass` | `fail` / `softfail`: sending IP isn't authorized for the domain |
| **DKIM** | `dkim=pass` and the signing domain matches From | `none` / `fail` |
| **DMARC** | `dmarc=pass` | `fail`: domain owner says "reject this" |
| **From vs Reply-To** | Same domain | Replies secretly go to a different (often free webmail) address |
| **Return-Path** | Matches the sender's domain | Unrelated bulk-mail or compromised domain |
| **Display name** | Matches the address | "Microsoft Support" `<alerts@micros0ft-help.co>` |

🔧 **Tools:** [MXToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) · [Google Admin Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/)

## 🔗 Step 3: Extract IOCs (automated)

The included script pulls every IOC out of an `.eml` file, hashes the attachments, defangs the output, and flags common red flags automatically:

```bash
python3 scripts/extract_iocs.py suspicious.eml
python3 scripts/extract_iocs.py suspicious.eml --json > iocs.json   # for your SOAR / ticket
```

<details>
<summary><b>📄 Example output (click to expand)</b></summary>

```
============================================================
 PHISHING TRIAGE - IOC EXTRACTION REPORT
============================================================
From        : IT Support <support@micros0ft-secure-login.com>
Reply-To    : helpdesk@gmail.com
Subject     : Urgent: Password expires today

Auth results : {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail'}

[URLs] (1)
  - hxxps://micros0ft-secure-login[.]com/verify?id=1
[Public IPs] (1)
  - 185[.]220[.]101[.]45
[Attachments] (1)
  - invoice.html (application/octet-stream, 7 bytes)
      SHA256: 25b2d486f51a7d2d20b56f9b959b1aab4aa2e47ea5befa48d938f7d8e8fc8082

[Red flags] (6)
  ! Reply-To domain (gmail.com) differs from From domain (micros0ft-secure-login.com)
  ! SPF result is 'fail'
  ! DKIM result is 'none'
  ! DMARC result is 'fail'
  ! High-risk attachment type: invoice.html
  ! Suspicious-looking domain: micros0ft-secure-login.com
```
</details>

✅ Standard library only, so there's nothing to install. Works on any analyst box with Python 3.8+.

## 🧪 Step 4: Reputation & Detonation

| IOC type | Where to check |
|---|---|
| URL / domain | [URLScan.io](https://urlscan.io) · [VirusTotal](https://www.virustotal.com) · WHOIS (how old is the domain?) |
| IP | [AbuseIPDB](https://www.abuseipdb.com) · [Talos Intelligence](https://talosintelligence.com) |
| Attachment hash | VirusTotal (**search the hash first**; only upload if your policy allows) |
| Attachment behavior | [Any.Run](https://any.run) · [Hybrid Analysis](https://www.hybrid-analysis.com) · [Joe Sandbox](https://www.joesandbox.com) |

> 💡 A domain registered **in the last 30 days** that imitates a brand is one of the strongest phishing signals there is.

## ⚖️ Step 5: Verdict

| Verdict | Typical evidence |
|---|---|
| 🟢 **Legitimate** | Auth passes, known sender, links go to expected domains |
| 🟡 **Spam / Marketing** | Unwanted but not malicious |
| 🔴 **Credential phishing** | Fake login page, look-alike domain, urgency |
| 🔴 **Malware delivery** | Malicious attachment or download, sandbox shows execution / C2 |

## 🧹 Step 6: Contain & Scope

1. **Who else got it?** Run a message trace by sender, subject and URL across the tenant.
2. **Purge** it from every mailbox (Microsoft 365: `Search-Mailbox` / *Threat Explorer → Soft delete*).
3. **Block** the sender, domain, URLs and hashes at the email gateway, proxy/DNS and EDR.
4. **Who clicked?** Check proxy / DNS logs for the phishing domain.
5. **Who submitted credentials?** Reset passwords, **revoke sessions**, check MFA, review sign-in logs.
6. **Who opened the attachment?** Hunt in EDR for Office or Outlook spawning child processes (see my [Splunk detection](https://github.com/officialupright/splunk-threat-detection)).

## 📝 Step 7: Report

Use [`templates/phishing-report-template.md`](templates/phishing-report-template.md). Good reports make the next investigation faster and feed lessons back into awareness training.

---

## 🧭 MITRE ATT&CK Coverage

| Technique | Name |
|---|---|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts (stolen credentials used after phishing) |

## 📂 Repository Structure

```
phishing-analysis-playbook/
├── README.md                           ← the playbook
├── scripts/
│   └── extract_iocs.py                 ← IOC extractor + red-flag checker
└── templates/
    └── phishing-report-template.md     ← investigation report template
```

## 🏋️ Practice Resources

- [PhishTank](https://phishtank.org/): live phishing URLs (view safely via URLScan)
- [Blue Team Labs Online](https://blueteamlabs.online/) and [LetsDefend](https://letsdefend.io/): free phishing investigation challenges
- [TryHackMe: Phishing module](https://tryhackme.com/)

---

<p align="center">Built by <a href="https://github.com/officialupright">Ifeanyi Solomon Uneze</a> · SOC Analyst · <a href="https://www.linkedin.com/in/ifeanyi-solomon-uneze-6536b8450/">LinkedIn</a><br/>⭐ If this playbook saves you time on your next ticket, star it and share it with your team!</p>
