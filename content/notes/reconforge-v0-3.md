---
title: "reconforge v0.3: why keyword CVE matching lies"
date: 2026-11-04
tags: ["tools", "recon", "python", "nmap", "nvd"]
summary: "Replacing a keyword CVE search with CPE matching, local version checks and a confidence level on every result. Most of the work turned out to be NVD's data, not the API."
---

In the [first post](/notes/building-reconforge/) I said reconforge's CVE results were "leads to verify, not confirmed vulnerabilities". That was true, and it bothered me. v0.3 fixes it. Every CVE in the report now says **how sure the tool is** and **why**.

Source: [github.com/Naved124/reconforge](https://github.com/Naved124/reconforge) (tag `v0.3.0`)

## the problem with keyword search

v0.2 asked NVD for `keywordSearch="vsftpd 3.0.3"`. That returns any CVE whose description mentions those words. Some are about 3.0.3, some are about older versions that happen to be named in the text, and some are about something else entirely. The report had no way to tell them apart, so every result carried the same weight.

For a recon tool, that's the wrong default. A pentester reading the report has limited time, and a list of guesses with no ranking wastes it.

## matching on CPE instead

Nmap already knows more than the product name. With `-sV`, it attaches a **CPE** to most services it identifies:

```
cpe:/a:vsftpd:vsftpd:3.0.3
```

That's a structured identifier: part (`a` = application), vendor, product, version. NVD uses the same scheme to describe which software each CVE affects. So v0.3 does this:

1. **Convert** Nmap's CPE 2.2 URI to CPE 2.3 (`cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*`), handling escaping and missing fields.
2. **Query** NVD with `virtualMatchString=cpe:2.3:a:<vendor>:<product>`, which returns every CVE with a configuration naming that product.
3. **Check versions locally.** Each CVE's configuration lists affected CPEs, either an exact version or a range with `versionStartIncluding` / `versionEndExcluding` and friends. reconforge compares the detected version against those itself instead of trusting the search.

The version comparator splits versions into numeric and alpha parts, so `7.4 < 7.4p1 < 7.5` and `2.0rc1 < 2.0`. Anything it can't compare honestly (like `2.4.41-4ubuntu3`) returns "uncomparable" instead of a guess.

OS and hardware CPEs (`cpe:/o:linux:linux_kernel`) are skipped. Querying the Linux kernel would pull in thousands of CVEs that say nothing about the service.

## confidence levels

Every CVE now gets one of four labels, plus a reason string:

| level | meaning |
|---|---|
| `exact-cpe` | NVD lists this exact version as affected |
| `confirmed-range` | the detected version falls inside an affected range |
| `unconfirmed` | matched the product, but something limits trust (see below) |
| `keyword-guess` | no usable CPE, fell back to the old keyword search |

The report lists confirmed results first and caps the weaker ones, so the top of each service section is what's worth your time.

## the hard part was the data

Wiring up the API took an evening. Most of the work was NVD's data not lining up with Nmap's.

**Vendor names disagree.** Nmap's probe file emits `vsftpd:vsftpd`. NVD calls the vendor `vsftpd_project`. Query with Nmap's vendor and NVD returns **zero** CVEs, which is worse than keyword search. Query with a wildcard vendor (`*:vsftpd`) and you get 8.

The wildcard is a fallback, not a fix, because you're no longer sure you have the right software. So wildcard matches are capped at `unconfirmed` with the reason `vendor alias`. For known cases there's a small alias table, built from evidence: I checked 13 common services in Nmap's probe file against NVD's CPE dictionary and only added an entry where the vendors differ **and** NVD has exactly one vendor for that product. Only vsftpd qualified.

**Vendors get renamed.** Nmap reports nginx as `igor_sysoev:nginx`. In NVD, all 383 `igor_sysoev` CPEs are deprecated. Their `deprecatedBy` field points to `nginx:nginx`, which is also fully deprecated (543 of 543) and points to `f5:nginx`, the live one. MySQL is the same story: 414 of 415 `mysql:mysql` CPEs are deprecated, and the chain ends at `oracle`.

Rather than hardcoding "nginx is f5 now", reconforge follows `deprecatedBy` itself: up to 6 hops with cycle protection, only when at least 90% of the vendor's CPEs are deprecated and every chain ends at one live vendor. Then it queries both the old and new vendor (old CVE records still use the old name) and dedupes. Because this is NVD's own mapping, these matches aren't capped.

**Versions are spelled differently.** Nmap reports OpenSSH as `7.2p2`. NVD stores it as version `7.2` plus update `p2`. The matcher joins the two fields before comparing.

**Some versions can't be trusted at all.**

- **Distro packages.** `OpenSSH 7.2p2 Ubuntu 4ubuntu2.8` is upstream 7.2p2 with security fixes backported by Ubuntu. The upstream version says vulnerable; the package may not be. Anything with a distro marker is downgraded to `unconfirmed` with the reason `distro package, fixes may be backported`.
- **MariaDB.** MariaDB often answers Nmap's MySQL probe with a version like `5.5.5-10.3.23-MariaDB`. Match that against Oracle MySQL 5.5.5 and you get confident nonsense. If MariaDB shows up anywhere in the banner, matches against MySQL are capped at `unconfirmed`.

## fawn, before and after

Same box as last time: vsftpd 3.0.3, anonymous login allowed.

![report summary](/images/reconforge-v03-summary.png)

| | v0.2 | v0.3 |
|---|---|---|
| method | keyword `"vsftpd 3.0.3"` | CPE + local version check |
| CVE-2021-30047 | listed, no context | `exact-cpe`: NVD lists 3.0.3 itself |
| CVE-2021-3618 (ALPACA) | not shown | `confirmed-range`: 3.0.3 within `< 3.0.4` |
| dropped by version check | n/a | CVE-2011-2523 (the 2.3.4 backdoor), CVE-2011-0762, CVE-2015-1419, and older entries |

![CVE lines with confidence tags](/images/reconforge-v03-cves.png)

Two things I like about this result. First, the famous vsftpd backdoor is gone. A keyword-happy tool would happily put it in front of a beginner, and it doesn't apply to 3.0.3. Second, the report still says **anonymous FTP comes first**. Both CVEs are real by NVD's standard, and neither gets you in. Better CVE matching didn't change the lesson from the first post; it just made the CVE section honest.

(I re-ran it on a live Fawn instance on 5 Nov 2026 and got the same two CVEs with the same confidence levels. The repo's example is that real scan.)

## being polite to NVD

- **Rate limit:** a sliding window of 5 requests per 30 seconds, or 50 with an `NVD_API_KEY`.
- **Retries** with backoff on 403/429/503, which is how NVD says "slow down".
- **Cache:** `~/.cache/reconforge/nvd`, 24-hour TTL, configurable with `--cache-dir` and `--cache-ttl`.

## testing without the network

108 tests, none of which touch NVD. The fixtures are real NVD responses, fetched once and trimmed to the fields that matter, plus a hand-written file of range edge cases (inclusive vs exclusive boundaries, negated nodes, `vulnerable: false` platform entries). The client tests use a fake fetch and a fake clock, so rate limiting and cache expiry are tested without waiting 30 seconds.

## what's next

- A real multi-service HTB scan (SSH plus a web server), so nginx and OpenSSH go through the new logic on a live target.
- CI on every push.
- A notes file to mark a CVE as reviewed or not applicable. CVE-2021-30047 is the obvious first entry: NVD says 3.0.3 is affected, and for a pentest it's noise.

## for defenders

Same advice as before, plus one: if your scanner or SIEM reports CVEs from a banner version, check whether the package is a distro build before panicking. Backported fixes mean the banner version and the actual patch level are often different things.
