---
title: "{{ replace .File.ContentBaseName "-" " " | title }}"
date: {{ .Date }}
draft: true

# --- required before publishing ---
disclosed: false        # set to true ONLY if the program disclosed it or gave permission (the build refuses otherwise)

# --- report facts ---
program: ""             # program name, or "private program" if you can't name it
vuln_class: ""          # e.g. IDOR, stored XSS
severity: ""            # low / medium / high / critical
status: ""              # reported / triaged / resolved / disclosed / duplicate / N/A
tags: []
description: ""
---

## Summary

## Impact

## How I found it

## Timeline

## What I learned
