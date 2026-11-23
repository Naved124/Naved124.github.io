---
title: "building reconforge: recon that writes the report for you"
date: 2026-10-30
draft: false
tags: [tools, recon, python, nmap]
description: "Why I built a scoped recon-to-report tool, how its scope guard and findings engine work, and what it caught on HTB Fawn."
image: images/reconforge-card.png
---

## The idea in one paragraph

Every box and every engagement starts the same way: scan, read the Nmap output, google each
service version for CVEs, check whether Metasploit has a module, then write it all down.
[reconforge](https://github.com/Naved124/reconforge) automates that first hour. It takes a
target, refuses to touch it unless it's in an authorized scope file, runs Nmap, and turns the
output into a Markdown report: misconfigurations first, candidate CVEs second, Metasploit
modules third, next steps at the end. It doesn't exploit anything. It hands a human a
prioritised list to verify.

## How it actually works (the mechanism)

**1. Scope guard, before anything else.** The scope file is a list of IPs and CIDR ranges. The
check runs *before* Nmap starts, so an out-of-scope target never receives a packet. Hostnames
are rejected on purpose: a hostname can resolve somewhere you're not authorized to test, so
you resolve it yourself and list the IP. If you import an existing scan instead of running
one, every host in that file is checked too.

```text
$ reconforge scan --scope scope.txt --target 10.10.10.10
[x] out of scope, refusing to continue: 10.10.10.10
```

**2. Parse Nmap's XML, not its text output.** `-oX` gives structured data: each port's
product, version, CPEs and every NSE script's output. reconforge only keeps hosts that are up
and ports that are open, and drops script output that starts with `ERROR`.

**3. Misconfigurations beat CVEs.** This was the most important design choice. A CVE lookup
can't see that an FTP server lets anyone log in. Nmap's scripts can. So reconforge reads
script output with rules like these:

| Script | What it means | Severity |
|---|---|---|
| `ftp-anon` | anonymous FTP login allowed | high |
| `mysql-empty-password` | database root with no password | high |
| `http-git` | exposed `.git` directory | high |
| `smb2-security-mode` | SMB signing not required | medium |
| `http-methods` | risky methods like PUT/DELETE | medium |
| plain `ftp` / `telnet` | credentials sent in cleartext | low |

These land under **Priority findings** at the top of each host, above the CVE list.

**4. CVE lookup via the NVD API.** For each service with a detected version, it queries the
NVD CVE API 2.0 with `product + version` and sorts results by CVSS severity. Two details
mattered:

- Services without a version are **not** queried. "OpenSSH" alone returns hundreds of
  irrelevant CVEs, and noise in a report is worse than nothing.
- Without an API key, NVD allows about 5 requests per 30 seconds, so requests are spaced out
  and every response is cached on disk. A rerun costs zero API calls.

Keyword matching is fuzzy, so the report labels these as *leads to verify*, not confirmed
vulnerabilities.

**5. Metasploit mapping, review-only.** Metasploit ships a metadata file listing every module
and the CVEs it references. reconforge indexes it and suggests exploit and auxiliary modules
for each CVE. It writes them into a resource script where **every line is commented out**, so
nothing runs until a human reads it and decides.

## Example

Here's the real report from HTB's Starting Point box Fawn (abridged):

```text
Misconfigurations: High 1, Low 1
Candidate CVEs:    High 1

Priority findings:
- [HIGH] Anonymous FTP login allowed (ftp-anon)
  -rw-r--r--  1 0  0  32 Jun 04 2021 flag.txt
- [LOW] FTP sends credentials in cleartext (service)

21/tcp  vsftpd 3.0.3
- CVE-2021-30047 (HIGH, CVSS 7.5): denial of service via limited connections
```

The interesting part is the ranking. The "high" CVE is a denial of service, which is useless
for getting in. The actual way in is the anonymous login, and that's what sits at the top. An
earlier version of the tool only did CVE lookups and would have pointed me at the wrong thing.

## How to find it / how to fix it

**Run it:**

```bash
git clone https://github.com/Naved124/reconforge && cd reconforge
pip install -e .
echo "10.129.0.0/16   # HTB lab" > scope.txt
reconforge scan --scope scope.txt --target <box-ip>
```

It's standard-library Python only, with 16 tests at the time of writing. Only point it at machines you own or are
authorized to test.

**If you're on the defending side,** the fixes for what it flagged on Fawn are simple:
disable anonymous FTP (`anonymous_enable=NO` in `vsftpd.conf`), or better, replace FTP with
SFTP so credentials never cross the network in cleartext.

Next up: running it against an SMB box, where the signing and share rules come into play.

   > **Update (4 Nov 2026):** v0.3 replaced the keyword CVE search in step 4 with CPE matching and confidence levels. See [reconforge v0.3](/notes/reconforge-v0-3/). The rest of this post still applies.