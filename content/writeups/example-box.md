---
title: "Example Box"
date: 2026-10-21
draft: true
retired: true
platform: "HackTheBox"
os: "Linux"
difficulty: "Easy"
solved: "solo"
time_spent: "5h"
tags: [web, suid, privesc]
description: "Sample post to show the layout. Delete this file."
---

## Summary

This is a sample draft so you can see the layout locally with `hugo server -D`. It is a draft, so it is never published. Delete it once you've written your first real post.

## Recon

```bash
nmap -sC -sV -oA scans/initial 10.10.10.10
```

| Port | Service | Version |
|---|---|---|
| 22 | ssh | OpenSSH 8.9 |
| 80 | http | nginx 1.18 |

## Foothold

Explain *why* the bug existed, not just which command worked.

## Privilege escalation

```bash
find / -perm -4000 -type f 2>/dev/null
```

## Lessons learned

- Enumerate SUID binaries early.
