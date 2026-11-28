---
title: "Building tephra, day 9: fix the attack class, not the test case"
date: 2026-11-21
series: tephra
draft: false
tags:
  - kubernetes
  - ebpf
  - runtime-security
  - detection-engineering
  - evasion
description: "Nine attacks committed before any fix, then three fixes each aimed at a whole class: alerts drowned in a flood, a process borrowing another pod's identity, and remote sessions hidden on loopback. Plus a false positive solved by a lab instead of a guess."
image: images/tephra-day9-card.png
---

![Nine held-out attacks committed before the three fixes, in git order](/images/tephra-day9-card.png)

[Day 8](/notes/building-tephra-day-8/) ended with a run that worked and still let a handful of attacks
through. The easy move was to patch exactly those scenarios, re-run, and see green. That is
overfitting: the test passes, and the attacker takes the next path. Day 9 is about not doing that.

## TL;DR

- **Rule for the day:** every fix starts by listing **every** way an attacker reaches the same goal,
  not just the scenario that failed.
- **Nine held-out attacks (E19–E27)** were written from those lists, each with a prediction, and
  committed **before** any fix code. Git shows the order.
- **Fix 1, drowning the signal:** repeated alerts are grouped, each pod has a budget, and a full queue
  drops the lowest-level alert first, never a critical one.
- **Fix 2, borrowed identity:** a process keeps the container it was born in, so moving into another
  pod no longer moves the blame. Three new rules watch the move itself.
- **Fix 3, hidden session channels:** loopback connections are now seen, and an interpreter that
  **listens** for its operator is caught.
- **Also:** the test harness was fixed first, and a noisy false positive was solved with a 10-cent lab
  run instead of a guess.

## First, fix the measuring tool

Day 8's most interesting failure came partly from the harness itself: it deleted each scenario without
waiting, so one scenario's process was still running while the next one was measured. Before touching
the sensor, the harness now waits for each scenario to be really gone, and reports a scenario as not
run if the previous one is still around after two minutes.

No scenario changed. It's a boring fix, and it has to come first: if the ruler is bent, every
measurement after it is wrong.

## Write the exam first, again

For each weakness from day 8, I listed the ways to the same goal, and wrote held-out scenarios for the
ones nothing tested yet:

| ID | What it tries | Class |
|---|---|---|
| E19 | Flood alerts from a second pod, kill the agent, read `/etc/shadow` while it's down | Drowning the signal |
| E20 | Read the pod's token from inside the agent's cgroup | Borrowed identity |
| E21 | A Perl session relayed through a sidecar on loopback | Hidden session |
| E22 | A token mounted under a custom path, read with `dd` | Credential by path |
| E23 | Like E19, but the flood comes from 200 differently named programs | Drowning the signal |
| E24 | A Python that listens, and the operator connects **in** | Hidden session |
| E25 | Like E21, over a Unix socket in a shared volume | Hidden session |
| E26 | Move into a bystander pod's cgroup and mount namespace, then read `/etc/shadow` | Borrowed identity |
| E27 | Another pod's token, read from the node's side of its volume | Credential by path |

E19–E22 went in at 13:17 and E23–E27 at 13:29, both before the first fix commit. Each has a prediction
for the sensor as it was. The credential class (E22, E27) is day 10's story.

## Fix 1: an attacker can drown the alert that matters

On day 8 a flood of about 23,600 alerts pushed out the two alerts that mattered. That happened by
accident; an attacker can do it on purpose. The ways to flood: one program, many programs, many rules,
a flood recorded while the agent was down. So the fix has three parts:

- **Grouping.** The first alert of a kind goes out at once. Repeats within 10 seconds become one
  summary with a count and a few sample command lines. A "kind" is the rule, the pod, the program and
  the target, so a different file, command or pod is never folded into someone else's flood.
- **A budget per pod.** A pod that varies its programs to escape grouping (E23's 200 renamed copies)
  gets folded by rule after 50 kinds in 10 seconds. Other pods are untouched.
- **Drop by level.** When the export queue is full of alerts, the oldest lowest-level alert goes first.
  A critical alert is never dropped to make room for a low one.

**CI caught a bug in my first version.** Program starts had no "target", so running a download tool
with a new URL was held for 10 seconds as a repeat. Grouping now uses the command line for program
starts. That's the point of tests in CI: the bug never reached a cluster.

The replay test feeds in 50,000 recovered alerts followed by the real kill-and-read. Both important
alerts come out, through a queue of 8,192, with nothing dropped.

## Fix 2: borrowed identity

Rules decided which pod did something by looking at the process's cgroup. Write your process ID into
another pod's `cgroup.procs`, and your actions get blamed on that pod, or inherit its exemptions.
Three layers, so getting past one isn't enough:

- **The move itself (R034, high):** a write to `cgroup.procs` or `cgroup.threads` from a pod is
  reported, naming the pod that made it.
- **Where a process came from:** every process now remembers the container it was born in. A move
  doesn't change that, and when the cgroup disagrees, the record is filed under the real origin and
  marked as a mismatch.
- **Two more rules:** R035 (critical) for any program started inside the agent's own container, and
  R036 (high) for entering another pod's namespaces.

My first version of R036 covered only mount namespaces. I asked myself what the second limit of the
design really was, and it was that one, so pid and network namespaces went in before the commit. The
network one is the serious case: entering another pod's network namespace means your connections leave
with **its** address, past network policies meant for yours.

That meant the kernel's event header grew by 8 bytes. Since day 8, the kernel buffer outlives the
agent, so a new agent could find an old agent's records in the old layout and decode garbage. A layout
version is now pinned next to the buffer, and a mismatch makes the new agent start fresh and say why.

**What it doesn't cover:** root on the node can do all of this from outside any pod. That's the
admin-level limit every sensor has.

## Fix 3: sessions hidden on loopback

Two day-8 misses were interactive sessions inside an interpreter: no shell ever starts, so the shell
rules never fire. The sensor already caught an interpreter connecting **out**. The other ways:
connecting to a relay on loopback, listening and letting the operator connect in, and talking over a
Unix socket.

- **Loopback is seen.** It was thrown away in the kernel to save cost, which is exactly how those
  sessions slipped through. Now connects **and** accepts on `127.0.0.1` and `::1` reach the rules.
  Accepts matter because `kubectl port-forward` arrives on loopback inside the pod.
- **Seen, not exported.** Loopback is most of a node's traffic and never leaves it, so its events are
  judged and only alerts leave the agent. What's held back is counted, never silent.
- **R037:** an interpreter that isn't the container's own application accepting a connection: a bind
  shell.

**An honest miss in my own prediction:** I predicted E25 (the Unix-socket relay) would get through. The
code already reported Unix-socket connects, so it was caught. The prediction stays in the record as
written. Predictions are only worth something if you don't edit them afterwards.

**The cost question:** a new benchmark workload hammers loopback with 200,000 connections. I set the
limit **before** measuring: 2 percentage points of throughput. If it's over, I decide between speed
and visibility, not the code.

## A false positive, solved by a lab instead of a guess

In day 8's false-positive run, two rules fired 120 times each on a harmless notebook workload. I had a
theory. Instead of shipping a fix for the theory, a short lab run (about $0.10) checked it.

The theory was wrong. The sensor decided a container's "main program" was its oldest process. But when
a container starts while the sensor is already watching, the oldest process is **runc**, the runtime
setting it up, not the app. So the notebook wasn't recognised as the app, and R029, which leaves a
terminal handed out by the app alone, fired on its shells. With the agent restarted, it read the
container from `/proc` after runc was gone, and nothing fired. That's how the lab proved it. The main
program is now the first program the container runs that isn't the runtime, with a test that replays a
container start.

No exemption was loosened: R029 now does what it was written to do. R002 still fires on those shells by
design (a shell under a server process), and the grouping from fix 1 turns 120 alerts into one plus a
summary every 10 seconds.

## What this proves, and what it doesn't

- **Proves:** the order. Nine attacks, with predictions, are in git before the fixes, and each fix is
  aimed at a class with its own list of ways in.
- **Doesn't prove:** that the fixes work against the nine. That needs a full run on real kernels, with
  the results kept as measured, even the ones that hurt.

## Takeaways

- **Fix the ruler before you measure.**
- **List every way to the goal, then fix the class.** The scenario that failed is one example, not the
  problem.
- **Write predictions down and don't edit them,** even when you turn out to be too pessimistic.
- **Test your theory before you fix it.** Ten cents of lab time beat an afternoon of the wrong fix.

Code, raw results and the full build log: [github.com/tephrasec/tephra](https://github.com/tephrasec/tephra).
