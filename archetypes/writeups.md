---
title: "{{ replace .File.ContentBaseName "-" " " | title }}"
date: {{ .Date }}
draft: true

# --- required before publishing ---
retired: false          # set to true ONLY once the machine is retired (the build refuses otherwise)

# --- box facts (shown in the box at the top) ---
platform: "HackTheBox"  # HackTheBox / TryHackMe
os: "Linux"
difficulty: "Easy"
solved: "solo"          # solo / partial-help / writeup-assisted  (be honest — it's your credibility)
time_spent: ""          # e.g. "6h"
tags: []                # e.g. [web, idor, suid, privesc]
description: ""         # one line for link previews
---

## Summary

One paragraph: what the box was about and the chain from foothold to root.

## Recon

## Enumeration

## Foothold

## Privilege escalation

## What I got stuck on

## Lessons learned

## What I'd check first next time
