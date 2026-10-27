# Phishing Link Checker

A command-line tool written in Python that scans a URL for common warning signs of phishing and gives it a risk score.

It only analyses the text of the link. It never opens or visits the site, so it is safe to run on links you suspect are dangerous.

## Why I built this

Phishing links are one of the most common ways people lose passwords and money, including through fake SMS messages pretending to be from local banks and mobile wallets. I wanted to understand the tricks attackers hide inside a URL, so I built a tool that checks for them automatically.

## What it checks

| Check | Why it matters | Points |
|---|---|---|
| Brand impersonation | The link mentions a brand (e.g. PayPal, HBL) but is not on that brand's real domain | 4 |
| Look-alike characters (punycode) | `xn--` domains can use letters from other alphabets that look identical to English ones | 5 |
| Raw IP address | Real sites use names, not numbers like `192.168.4.20` | 3 |
| `@` symbol | Browsers ignore everything before `@`, so `paypal.com@evil.com` goes to evil.com | 3 |
| Link shortener | Services like bit.ly hide the real destination | 2 |
| Risky domain ending | Cheap endings such as `.xyz`, `.top`, `.click` are common in scams | 2 |
| Too many subdomains | Words stacked up to look official, e.g. `secure.login.microsoft.evil.click` | 2 |
| No HTTPS | The connection is not encrypted | 1 |
| Very long URL | Long links are used to hide the real domain | 1 |
| Many hyphens | Domains like `hbl-secure-login` imitate real brands | 1 |
| Bait words | Words like `verify`, `login`, `suspend` that create urgency | 1 |

**Verdict:** 0 to 1 = Probably safe, 2 to 4 = Suspicious, 5 or more = Likely phishing.

## How to run it

You need Python 3. No extra libraries are required.

```
python phish_checker.py                       # asks you to paste a link
python phish_checker.py "http://example.com"  # checks one link
python phish_checker.py -f sample_links.txt   # checks every link in a file
```

## Example output

```
URL:     http://hbl-secure-login.verify-account.xyz/update
Score:   9
Verdict: LIKELY PHISHING
  - Not using HTTPS (connection is not encrypted)
  - Uses a domain ending (.xyz) common in scams
  - Domain contains many hyphens
  - Contains bait words: login, verify, secure, account, update
  - Mentions 'hbl' but the real domain is verify-account.xyz
```

## Limitations

This is a rule-based tool, so it has blind spots:

- A brand-new phishing domain with a clean-looking name (e.g. `paypa1.com`) may pass every check.
- A safe link can sometimes be flagged as suspicious.
- It does not check the website's content, reputation or blocklists.

It is a learning project and should not replace real security tools.

## Ideas for future versions

- Detect misspelled brand names (e.g. `paypa1`, `g00gle`) using string similarity
- Check links against a public phishing blocklist
- Expand shortened links to see their real destination
- A simple web or browser-extension interface

## Author

Muhammad Faridoon Khan, A-Level student (Mathematics, Physics, Computer Science) interested in cybersecurity.
