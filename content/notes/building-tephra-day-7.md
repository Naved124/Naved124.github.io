---
title: "Building tephra, day 7: what the sensor costs, and auditing my own results"
date: 2026-11-19
series: tephra
draft: false
tags:
  - kubernetes
  - ebpf
  - runtime-security
  - benchmarking
  - detection-engineering
description: "120 benchmark cells on EC2, four harness bugs found before the real run, a network cost of 22% traced to its root cause, a comparison I withdrew, and three evasions that changed how every fix after it is tested."
image: images/tephra-day7-card.png
---

![What a new connection cost the agent, and what it costs after the fix](/images/tephra-day7-cost.png)

[Days 5 and 6](/notes/building-tephra-days-5-6/) ended with every rule, blocking included, passing
on the oldest kernel Tephra supports. Day 7 asked two harder questions. **What does the sensor cost
a node?** And, once I had that number: **do my own results hold up?** The second one turned out to
matter more. This write-up is the experiment, the bugs, the root cause, and the parts I got wrong.

## TL;DR

- 6 configurations × 4 workloads × 5 runs = **120 cells**, unattended, on one EC2 c7i.2xlarge, kernel 7.0.
- The trial run found **four bugs in the benchmark harness** and one hang. All were fixed before a single number was kept.
- Tephra against no sensor: **−14% exec throughput, −3.4 to −4.3% on a compile, −22 to −26% on new-connection HTTP**.
- The network cost wasn't where I assumed. "Alerts only" saved the export but not the cost, because the cost was **per record wakeups**, not output. The fix landed later in v0.2.0, and the network cost in that later run went from **−16.7% to −2.3%**.
- I withdrew the competitor rows of this benchmark. They compared **cost at unequal coverage**, which proves nothing.
- Three evasions had gotten past the sensor. Fixing those three scenarios would have been overfitting. That became the rule for everything after: **fix the class, and judge the fix on held-out attacks written before it**.

## Threat model, briefly

Tephra watches a Kubernetes node from the kernel with eBPF: process starts, file opens, connections,
privilege changes. It raises alerts on rules. The attacker I design for starts **inside a pod**,
usually through an application bug, and may reach the **node**. Two properties follow:

1. **Cost is a security property.** A sensor too expensive to run everywhere isn't deployed, and an
   agent that falls behind drops events. A flood that makes the agent drop is an evasion technique.
2. **Results need the same scrutiny as code.** A benchmark or a detection rate is a claim. If the
   method is wrong, the claim is a vulnerability in the project's credibility.

## Experiment design

| | |
|---|---|
| Machine | EC2 c7i.2xlarge (8 vCPU, 16 GiB), ap-south-1, Ubuntu 24.04, kernel 7.0.0-1017-aws |
| Cluster | kind, the workload pinned to 2 CPUs of one worker |
| Configurations | no sensor; Tephra exporting every event; alerts only; alerts only with enforcement on (plus two that are withdrawn below) |
| Workloads | exec-heavy (20,000 fork+exec of /bin/true); file-heavy (unpack and compile BusyBox 1.37.0); network-heavy (200,000 HTTP requests, 32 concurrent, a new connection each); idle |
| Repeats | 5 per cell; median reported, with min and max |
| Measured | throughput and p99 relative to no sensor; agent CPU and RSS on the workload's node; events/s and drops from the sensor's own kernel counters |

The whole matrix runs **unattended** under `bench/supervise.sh`. It runs the matrix, then runs it
again retrying only missing cells, writes the report, and powers the instance off. Every step has a
time limit: 15 minutes to bring a configuration up, 20 minutes per cell. A hang costs one cell, not
the run. I added this because the first attempt hung on a pod that never became ready, and nothing
noticed until someone looked.

## Bug review: the trial run

I ran a short trial before the real matrix. It found four faults, each of which would have
produced a plausible but wrong number:

1. **No nanosecond clock in BusyBox.** `date +%N` isn't supported there, so the timings were
   garbage. The harness now reads `/proc/uptime`: 10 ms resolution, which is enough for runs that
   take seconds.
2. **The server never started.** The Alpine nginx and httpd images don't ship `taskset`. The pin
   failed, the server didn't run, and the "benchmark" measured connection refusals. Debian images
   are used now.
3. **A ready pod with no listener.** Debian's `nginx.conf` already sets `worker_processes`. nginx
   refuses a directive given twice and exits, but the pod still reported ready. The setting is now
   changed inside the file, and a readiness probe on port 80 waits for the actual listener.
4. **Empty results were stored as results.** A workload that printed nothing became a cell with
   no value and was averaged in. A `RESULT` with an empty value is now a failed cell.

The pattern: **every one of these failed silently**. A measurement tool needs the same "fail
closed" design as the sensor it measures.

## Results (Tephra against no sensor)

Median of 5; full brackets in [docs/benchmarks.md](https://github.com/Naved124/tephra/blob/main/docs/benchmarks.md).

| Workload | Alerts only | Every event exported | Enforcement on | Agent CPU (alerts only) |
|---|---|---|---|---|
| Exec, execs/s | −14.0% | −19.8% | −14.8% | 20% of a CPU |
| Compile, builds/h | −3.9% | −4.3% | −3.4% | 4% |
| HTTP, new connection each, req/s | −22.1% | −25.5% | −22.1% | **69%** |
| Idle | | | | 0.1% (0.7% with enforcement on) |

No ring-buffer drops in any cell. p99 latency moved from 2 ms to 3 ms only when every event was exported.

## Insight: the network cost wasn't the export

Each new connection produces a connect and an accept record, about **27,000 records a second** in
this workload, and the agent spent about 70% of a CPU on them. The obvious assumption was that
writing the records out was the cost. But **"alerts only" exports almost nothing, and cost the same
22%**. So the cost was upstream of the export: decoding, enrichment, rule evaluation, or the trip
from kernel to agent.

I recorded the finding and didn't fix it that day; the numbers describe the sensor as it was. The root cause was found
in v0.2.0 by profiling before touching anything:

- A replay of connect and accept records through the enricher and the rules cost about
  **2.5 µs per record**. That's nowhere near enough to explain 70% of a CPU.
- The real cost was **the kernel waking the agent for every record** once the agent had caught up,
  and the agent handling **600,000 records for 200,000 requests**.
- The fix, two options that are off by default and recommended in the chart:
  - **batched wakeups:** the kernel wakes the agent once a batch is waiting;
  - **quiet connections:** the kernel counts connections per process and destination and sends a
    summary, instead of one record per connection, for processes no rule cares about.

  Nothing a rule needs is skipped: a process becomes "quiet" only when the agent has judged it so, and
  "can't tell" means "report".

| Network workload, measured in the v0.2.0 run | Before | Both options on |
|---|---|---|
| Throughput vs no sensor (alerts only) | −16.7% | **−2.3%** |
| Agent CPU | 73% | **2%** |
| Records handled | 600,729 | **633** |

The lesson: **profile before you optimise**. The optimisation I'd have guessed at, cheaper export,
would have changed nothing.

## Audit: the comparison I withdrew

The original M10 matrix had two more configurations: **Falco and Tetragon with their default
configs**. Three days later I withdrew those rows from the repo and the README, and no longer cite them.

**Why they were invalid.** A runtime sensor's cost is driven by **what it watches**. The default
configs watch very different amounts. Tetragon's default, for example, barely watches file opens or
connections, while Tephra's defaults watch both. A cost-only comparison at unequal coverage measures
the configs, not the sensors. Detection was never run on the other two at all.

**What a valid comparison needs:** equal-coverage configs, the same attack scenarios run against each
for detection and blocking, a false-positive run, and cost, all measured together. Until that exists
the benchmark reports Tephra against **no sensor**, which is a fair cost and regression check, and
nothing more.

A second methodology bug came out of the same audit, later. The benchmark scripts are
resumable: they skip cells whose results already exist. Old results had been committed, so a later
run **silently reused last week's numbers** for some cells. The fix and the rule: every measured run
starts from an empty results folder.

## Failed tests: three evasions got through

Alongside the attacks, the harness runs **evasions**: attacks designed to get past a specific rule.
Of the eight, three succeeded:

| ID | Evasion | Why it worked | Class of weakness |
|---|---|---|---|
| E01 | Reverse shell through a copy of the shell under another name | R001 matched the binary's **name** | Identity by name or path |
| E02 | Interactive session inside Python, no shell ever executed | Detection keyed on **exec**; nothing was executed | Sessions without an exec |
| E07 | Kill the agent from the node, read `/etc/shadow`, let it restart | Nothing recorded **the kill or the gap** | Sensor tampering |

The tempting fix is three targeted patches: add the renamed path, look for that Python pattern, add a
heartbeat. Each would turn its test green, and none would fix the weakness. A renamed BusyBox, a Perl
session or a frozen agent would still get through. **That's overfitting, in security.**

![Three evasions, three classes of weakness, and the held-out tests for each](/images/tephra-day7-classes.png)

## The rule that came out of it

The fixes go after each **class**, and they're judged on **held-out evasions**:

1. For each class, write new evasions that reach the same goal by other means (a renamed BusyBox
   applet, a shell copied over an allow-listed binary, a session inside Perl, a pseudo-terminal
   relayed by Python, an agent frozen with SIGSTOP, a process hiding in the agent's own cgroup).
2. Write down the **prediction** for each, against the sensor as it is.
3. **Commit them before any fix exists**, so git's history proves they weren't tuned afterwards.
4. Run them once against the fixed sensor. A miss stays a miss, with a write-up.

These were E09–E16, committed the next day. The baseline on the unchanged sensor was
**2 of 8 detected**, and that's where day 8 starts.

## What this proves, and what it doesn't

- **Proves:** on that machine and kernel, Tephra's cost against no sensor per workload, with five
  runs and brackets; and that the network cost was wakeups and record count, not export.
- **Doesn't prove:** anything about another machine, a real cluster's mix of workloads, or how
  Tephra compares with another sensor. That comparison is withdrawn until it can be done at equal
  coverage, with detection measured alongside.

## Takeaways

- **Treat measurement code like production code.** Most of the bugs I found fail silently.
- **Profile before optimising.** The obvious suspect, export, was innocent.
- **Audit your own comparisons.** Unequal coverage makes a cost number meaningless.
- **Fix classes, not tests.** Commit the held-out tests before the fix, and let git be the witness.

Code, raw results and the full build log: [github.com/Naved124/tephra](https://github.com/Naved124/tephra).
