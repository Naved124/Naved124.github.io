---
title: "sentinel-detections: KQL detection rules that have to prove themselves"
date: 2026-11-08
draft: false
tags: [detection, kql, sentinel, azure, blue-team]
description: "Fifteen Microsoft Sentinel rules in KQL, each with a triage playbook and tests that run on the real Kusto engine. Two of the rules were wrong until the tests said so."
---

## The idea in one paragraph

A detection rule is a claim: "if this attack happens, I will fire, and if it doesn't, I'll stay
quiet." Most rules never get checked against either half of that claim until a real incident or
a flood of false positives does it for you. [sentinel-detections](https://github.com/Naved124/sentinel-detections)
is fifteen Microsoft Sentinel analytics rules written in KQL, where every rule ships with test
cases for both halves: attack data it must alert on, and the closest normal behaviour it must
ignore. Every rule also has a triage playbook, because an alert nobody knows how to investigate
is just noise with a severity label.

## What's in it

The rules cover the four log sources a Microsoft-stack SOC lives in:

| Source | Rules |
|---|---|
| Entra ID sign-ins | password spraying, sign-in after brute force, MFA fatigue, impossible travel, legacy authentication |
| Entra ID audit | privileged role assigned, credential added to an app, Conditional Access policy disabled |
| Azure activity | NSG opening SSH/RDP/database ports to the internet, Owner/Contributor assigned, VM Run Command, logging removed |
| Linux syslog | SSH brute force, SSH login after failures, sudo to a root shell or sensitive file |

Each rule is one YAML file: the KQL query, schedule, severity, MITRE ATT&CK tactics and
techniques, entity mappings (which output columns are the account, IP, host), the playbook and
the tests. The rule index and playbooks in `docs/` are generated from those files, so they can't
drift apart.

## How it actually works (the mechanism)

**1. Tests without an Azure subscription.** The problem with testing KQL is that you need
somewhere to run it. A Sentinel workspace costs money after the trial, and you can't easily
replay the same attack twice. Microsoft publishes a free **Kusto emulator**, a Docker image of
the same query engine Sentinel and Log Analytics run on. So the tests run there.

The trick is that the emulator has no `SigninLogs` table. KQL's `let` can define a name that
shadows a table, so the test runner turns each test case's rows into a `datatable` with the
real table's name and columns, and puts it in front of the rule's own query:

```kql
let SigninLogs = datatable(TimeGenerated:datetime, UserPrincipalName:string, IPAddress:string,
                           ResultType:string, /* ...every column in the schema... */)[
    datetime(2026-11-08T13:20:00Z), "bob@example.com", "203.0.113.60", "50126", ...
];
// the rule's query runs unchanged from here
let lookback = 1h;
SigninLogs
| where TimeGenerated > ago(lookback)
...
```

The rule doesn't know it's being tested. Timestamps in the test cases are relative (`at: -40m`,
`repeat: 12, every: 30s`), so the data always falls inside the rule's lookback window no matter
when CI runs.

**2. Every rule needs a "must fire" and a "must not fire" case.** The linter refuses a rule that
only has one kind. A rule tested only on attack data can quietly become a noise machine; a rule
tested only on normal data can quietly stop detecting anything. For example, the brute-force
rule has four cases: twelve failures then a success (fires), failures with no success (quiet),
a success from a *different* IP (quiet), and a success that happened *before* the failures
started (quiet).

**3. Static checks with Microsoft's own parser.** Microsoft publishes `Kusto.Language`, the parser
behind Sentinel's query editor. The linter loads the column schemas of the four tables and
analyses every query against them, so a typo like `ClientApp` instead of `ClientAppUsed` fails
before anything runs:

```text
✗ SIGNIN-005.yaml
    KQL line 8:9: The name 'ClientApp' does not refer to any known column, table, variable or function.
```

The same analysis returns the query's output columns, which catches a quieter bug: an entity
mapping that points at a column the query no longer outputs, for example after renaming a
column in the final `project`.

**4. CI runs all of it.** GitHub Actions starts the emulator as a service container, lints every
rule, runs all 49 test cases on the real engine and checks the generated docs are current.

## Two rules that were wrong

This is the part that justified building the tests.

**Conditional Access policy disabled (AUDIT-003).** My first version flagged an update when the
policy's modified properties matched `state ... disabled`. Writing the "must not fire" case for
*re-enabling* a policy showed the problem: the audit record contains both the old value and the
new value, and when you re-enable a policy, the *old* value says disabled. The rule would have
paged someone for fixing the problem. The fix checks only `newValue`, and deletions are handled
as a separate branch.

**SSH brute force (SYSLOG-001).** The first version grouped failures into fixed 10-minute bins
with `bin(TimeGenerated, 10m)` and alerted when a bin had 10 or more. Twelve failures spread over
nine minutes can straddle a bin boundary: 6 land in one bin, 6 in the next, and neither reaches
10. An attacker doesn't even need to know that to slip under it. The fix is a real sliding
window: sort failures per host and source IP, and for each one look 9 events back with
`prev(TimeGenerated, 9)`. If those 10 events fit inside 10 minutes, it's a burst. There's now a
test case built to straddle a boundary.

## Example: the MFA fatigue rule

MFA fatigue (ATT&CK [T1621](https://attack.mitre.org/techniques/T1621/)) is an attacker who
already has the password sending push prompt after push prompt until the user taps Approve to
make it stop. In `SigninLogs`, a denied prompt is `ResultType 500121` with details like
"MFA denied; user declined the authentication".

The rule counts denials per user over an hour, alerts at three, and then answers the question an
analyst would ask first: **did one get approved after the denials started?** It joins the
denials against successful MFA sign-ins for the same user and sets `ApprovedAfterDenials`. The
playbook's first step is built on that column: if it's true, treat the account as compromised.

The tests cover denials followed by an approval (fires, approved), denials alone (fires, not
approved), two denials (quiet) and MFA *timeouts*, which use the same result code but aren't
denials (quiet).

## Limits

- Ingesting Entra ID sign-in logs into Sentinel needs an Entra ID P1 or P2 licence, which a
  student tenant doesn't have. The sign-in rules are tested against realistic sample data, not a
  live tenant.
- Passing tests show a rule does what I intended on the cases I thought of. They don't show the
  thresholds are right for a real environment. That takes real data and tuning.
- The test data uses documentation IP ranges and `example.com` accounts.

## Run it

```bash
git clone https://github.com/Naved124/sentinel-detections && cd sentinel-detections
npm ci
npm run lint                      # no engine needed
docker run -e ACCEPT_EULA=Y -m 4G -d -p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
npm test                          # all 49 cases on the emulator
```

The full rule list with ATT&CK coverage is in
[docs/RULES.md](https://github.com/Naved124/sentinel-detections/blob/main/docs/RULES.md), and
each rule's playbook is linked from there.
