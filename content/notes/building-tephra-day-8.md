---
title: "Building tephra, day 8: held-out tests, and a sensor that can't be blinded quietly"
date: 2026-11-20
series: tephra
draft: false
tags:
  - kubernetes
  - ebpf
  - runtime-security
  - detection-engineering
  - evasion
description: "Eight attacks committed before any fix, programs recognised by what they are instead of what they're called, a sensor that leaves a record however it's stopped, and the first real exam on two kernels, including the alert flood that buried the one alert that mattered."
image: images/tephra-day8-card.png
---

![Held-out evasions detected: 2 of 8 before the fixes, 6 of 8 after](/images/tephra-day8-heldout.png)

[Day 7](/notes/building-tephra-day-7/) ended with three evasions that got past the sensor and a rule
for everything after: **fix the class of weakness, not the test, and judge the fix on attacks written
before it.** Day 8 is that rule in practice. Eight new attacks, committed first. Three fixes, each
aimed at a class. Then one run on real machines that both said "it worked" and found a new weakness.

## TL;DR

- **E09–E16:** eight held-out evasions, written with their predictions and committed before any fix.
  The unchanged sensor caught **2 of 8**.
- **Fix 1:** programs are recognised by their **content**, not their name or path. A renamed shell is
  still a shell.
- **Fix 2:** two rules for remote sessions that **never start a program**: an interpreter that isn't
  the app connecting out, and a terminal handed out by one.
- **Fix 3:** the sensor **can't be blinded quietly**. Stopping it through Kubernetes raises nothing.
  Any other stop leaves a record, and the kernel keeps recording while no agent runs.
- **First real exam,** kernels 7.0 and 5.15: attacks **22 of 22** on both, held-out evasions
  **6 of 8**, and a 30-minute false-positive run with **zero high or critical alerts**.
- **The finding of the day:** an attacker can bury the alert that matters under thousands of others.
  It happened by accident in the test, which is how I found it.

## Phase 0: write the exam before studying

Day 7's three misses were a renamed shell, a session inside Python, and killing the agent. If I had
fixed exactly those three scenarios, a re-run would have passed, and it would have proved nothing.
So, before touching the sensor, I wrote eight more attacks from the same classes. Each one has a
prediction:

| ID | What it tries | Predicted |
|---|---|---|
| E09 | A reverse shell through a renamed copy of busybox | missed |
| E10 | Read `/etc/shadow` with another program copied over an allow-listed one | missed |
| E11 | Download and run a file with Python's own HTTP client, no download tool | missed |
| E12 | An interactive session inside Perl, no shell ever started | missed |
| E13 | A reverse shell through a pseudo-terminal relayed to a socket | missed |
| E14 | Freeze the agent, read `/etc/shadow`, kill the agent before it wakes | missed |
| E15 | Read `/etc/shadow` from inside the agent's own cgroup | missed |
| E16 | Flood the sensor with connections, then read `/etc/shadow` | detected |

They went into git **before** any fix, so the history shows they weren't tuned afterwards. The harness
counts a held-out scenario as caught if **any** rule fires on it, so the test doesn't name the rule a
later fix would add. Baseline on the unchanged sensor: **2 of 8**.

One honest note: E13 was "caught" in the baseline, but by a broad rule that flags any shell whose
ancestor is Python. That catches the relay by accident, and it would fire the same way on a harmless
Python app that starts a shell. I recorded it as a false-positive risk to measure, not a reason to
change the rule.

## Fix 1: who a program is, by what it is

Rules used to recognise a shell or a download tool by its name or path. Copy `/bin/sh` to
`/tmp/backup` and it's no longer a shell, as far as the rules know.

Now the agent looks at each container's filesystem once and remembers a fingerprint (a SHA-256 of
the first MiB) of every file shipped under a shell, interpreter or download-tool name. Every program
started in a container is fingerprinted once and looked up. A copy keeps its identity under any
name. For busybox, the applet it actually runs counts.

Two more facts come with it:

- **Changed after start:** a program file written or replaced inside a running container is marked.
  That's how R005 tells the real `/usr/bin/passwd` from something copied over it (E10).
- **The app is recognised by file, not path:** rules that leave the application alone compare the
  actual file, so copying a tool over the app's binary no longer inherits its exemptions.

The cost is one fingerprint per new program file, a few milliseconds, then cached.

## Fix 2: sessions that never start a program

An interpreter can run a remote session by itself, reading commands from a socket and running them in
its own process. No shell starts, so a rule waiting for a shell on a socket never fires (E02, E12).
What's left are two things an application doesn't normally do, and two new rules:

- **R028:** an interpreter that isn't the container's application connects out. Jupyter kernels and
  workers run the app's own interpreter, so they're left alone. An attacker's interpreter comes from
  `kubectl exec` or through the app, not from the container's first process.
- **R029:** a program starts on a pseudo-terminal handed out by an interpreter that isn't the app
  (E13).

What this can't see: code running inside the app's own interpreter, like a Python app exploited
through `eval`. To the kernel, that **is** the app.

## A bug I found by reading a rule

While learning how a rule is written, I read R001 (reverse shell) line by line. Its backup list of
shell names had no `fish`. Recognition by content usually caught it anyway. But when it didn't, a
fish reverse shell would drop from R001 (high) to a medium rule. I added fish, tcsh, csh, mksh, yash
and hush, with tests. It was the first bug I found myself.

The same session turned up a bigger finding. Rules that leave the application alone (it reads its own
token, talks to the API, connects out) are blind to an attacker running code **inside** the
application. That is exactly the main attacker in the threat model. It isn't a rule bug; it's a
class. It's recorded in the build log, and planned as its own milestone: learn what the app normally
does, and alert on what's new.

## Fix 3: the sensor can't be blinded quietly

E07 killed the agent; E14 froze it and killed it before it woke; E15 hid in its cgroup. In each case
the dashboard went quiet, and quiet looks like nothing happening.

My first plan alerted on every stop. It was wrong, and the reason matters: **alert fatigue is real.**
An admin who upgrades or removes Tephra must not be paged for it. And root on the node, like a domain
admin in Active Directory, can always stop a sensor; no tool prevents that. The real flaw is being
stopped **quietly**. So the principle became: **a stop through Kubernetes is an operator's and raises
nothing; any other stop leaves a record.**

- **Recording outlives the agent.** The eBPF programs and their buffer stay pinned in the kernel. A
  killed or frozen agent leaves them recording, and the next agent reads what happened in between. A
  planned stop removes them, so uninstalling leaves nothing behind.
- **R030:** a signal sent to the agent. The kernel reports who sent it, so the container runtime's own
  stops are recognised and stay silent.
- **R031:** the collector notices a node that goes silent, or an agent that restarted without
  announcing it.
- **The agent is ignored by process, not by cgroup**, so moving into its cgroup no longer hides
  anything (E15).
- **R033:** anyone attaching to the agent's process or touching its memory. The agent is the one thing
  the sensor ignores, so getting into it would act unseen. Nobody routinely debugs a security sensor,
  so this one is critical, from the node too.

## The first real exam

Two cloud machines in parallel, kernel 7.0 and the 5.15 floor, run once and kept as measured.

| | Before the fixes | Run 1 |
|---|---|---|
| Attack scenarios A01–A22 | 22 / 22 | **22 / 22 on both kernels** |
| Original evasions E01–E08 | 5 / 8 | **6 / 8** |
| Held-out evasions E09–E16 | 2 / 8 | **6 / 8** |
| 30-min false-positive run | | **0 high or critical, 0 dropped** |

Missed on 7.0: E02 and E12 (sessions inside an interpreter), E07, and E15.

**E07 is the interesting one.** It passed on 5.15 and failed on 7.0. The previous scenario's process
was still reading `/etc/shadow` in a loop, because the harness deleted each scenario without waiting.
While E07 had the agent dead, the kernel kept recording those reads. The new agent found **47,917**
events waiting and raised about **23,600** alerts at once. The export queue dropped **15,422** alerts,
including E07's R005 and R030.

That's two findings. The harness must wait for each scenario to be gone, which is a test bug. And
**a flood of alerts can bury the one that matters**: the queue protected alerts from floods of
events, not from floods of alerts. An attacker can do that on purpose, so it needs its own held-out
scenario before its fix.

**E15:** the read was seen, but filed under the agent's pod, because pod names follow the cgroup. Seen
but blamed on the wrong pod is still a miss.

## What this proves, and what it doesn't

- **Proves:** the fixes caught attacks they weren't written against: 6 of 8 held-out evasions, against
  2 of 8 before, with predictions committed first. And they did it with no high or critical false
  positives in 30 minutes of ordinary workloads.
- **Doesn't prove:** that the classes are closed. E02, E12, E07 and E15 are still open, and each needs
  new held-out attacks before its fix. One run per kernel isn't a rate. And a lab's ordinary workloads
  aren't a real cluster's.

## Takeaways

- **Write the exam before studying.** Committed predictions are what make a result mean something.
- **Fix classes, then check against attacks the fix never saw.**
- **Don't make legitimate admin work noisy.** Make stealth impossible instead.
- **Your test harness can find real weaknesses by accident.** Keep the result as measured, and chase it.

Code, raw results and the full build log: [github.com/tephrasec/tephra](https://github.com/tephrasec/tephra).
