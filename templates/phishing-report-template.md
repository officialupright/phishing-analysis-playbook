# 🎣 Phishing Investigation Report

| Field | Value |
|---|---|
| **Ticket ID** | PHISH-YYYY-#### |
| **Reported by / Detected by** | User report · Email gateway · SIEM rule |
| **Date received (UTC)** | |
| **Analyst** | |
| **Verdict** | 🟢 Legitimate · 🟡 Spam / Marketing · 🔴 Phishing · 🔴 Malware delivery |
| **Users who received it** | # |
| **Users who clicked / opened** | # |

## 1. Email Details

| Header | Value |
|---|---|
| From | |
| Reply-To | |
| Return-Path | |
| Subject | |
| Sending IP | |
| SPF / DKIM / DMARC | pass · fail · none |

## 2. Indicators of Compromise (defanged)

| Type | Value | VirusTotal | URLScan / AbuseIPDB | Notes |
|---|---|---|---|---|
| URL | `hxxps://example[.]com/login` | x/90 | | Credential-harvesting page |
| Domain | | | | Registered N days ago |
| IP | | | | |
| Attachment SHA-256 | | | | |

## 3. Analysis

- **Lure / pretext:** (e.g. fake Microsoft 365 password expiry, fake invoice, delivery notice)
- **Red flags observed:**
  - [ ] Sender domain look-alike / typosquat
  - [ ] Reply-To differs from From
  - [ ] SPF / DKIM / DMARC failure
  - [ ] Urgency or fear language
  - [ ] Link text does not match the actual URL
  - [ ] Risky attachment type (.html, .iso, .zip, .docm, .lnk)
- **Sandbox result:** (Any.Run / Hybrid Analysis / Joe Sandbox link)

## 4. Impact Assessment

- Did anyone **submit credentials**? (Check proxy logs for POST requests to the phishing domain.)
- Did anyone **open the attachment**? (Check EDR for child processes of Outlook / Office.)
- Any **sign-ins from unusual locations** for affected users afterwards?

## 5. Containment & Response

- [ ] Email purged from all mailboxes (search & destroy)
- [ ] Sender / domain blocked at email gateway
- [ ] URLs and domains blocked at proxy / DNS
- [ ] Hashes blocked in EDR
- [ ] Passwords reset and sessions revoked for users who submitted credentials
- [ ] MFA verified for affected users
- [ ] Affected users notified and thanked for reporting 🙌

## 6. Lessons Learned

- Why did this get past the email gateway?
- Detection or awareness-training improvements:
