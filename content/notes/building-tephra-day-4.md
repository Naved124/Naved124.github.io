---
title: "Building tephra, day 4: attacking my own sensor"
date: 2026-11-13
series: tephra
draft: false
tags:
  - kubernetes
  - ebpf
  - detection
  - runtime-security
  - blue-team
description: "Eight evasions written against my own rules (three got through), blocking in the kernel with BPF LSM and every safety catch I could think of, and rules that need two events to fire."
image: images/tephra-day4-card.png
---

![Eight evasions against my own rules: five caught, three got through](/images/tephra-day4-evasions.png)

[Day 3](/notes/building-tephra-day-3/) ended with 22 attacks out of 22 detected. That number
was easy to get: I wrote the attacks and the rules. Day 4 was the harder test. I wrote attacks
whose only goal was to get past my own rules, and wrote down which ones did, and why.

The same day the sensor learned to **block** a few things instead of only reporting them, and
got rules that need **two events** to fire. And the lab moved for good: from here on, every
test runs on an AWS EC2 machine, never on my laptop. That day it was kernel 7.0.

## Eight evasions, three got through

Each evasion has a prediction, written in the design before it ran: detected, missed or partial.
Each gets a write-up: what was measured, why it worked or didn't, and the fix. A result that
differs from the prediction corrects the prediction. It's not hidden as a failed test.

| | Evasion | Result |
|---|---|---|
| E01 | Copy the shell to `/tmp/kworker`, run it as a reverse shell | **missed** |
| E02 | A remote session written in Python, no program ever started | **missed** |
| E03 | Read `/etc/shadow` through a hard link | detected |
| E04 | Open `/etc/shadow` through io_uring instead of `open()` | detected |
| E05 | Flood the sensor with 32,000 process starts, then read `/etc/shadow` | detected |
| E06 | Change the file name from a second thread while `open()` runs | detected |
| E07 | Kill the agent, read `/etc/shadow`, let it restart | **missed** |
| E08 | Hide the payload past the 1,024 bytes of command line kept | detected |

### The ones that got through

**E01: a shell is a shell under any name.** R001, the reverse-shell rule, asked "is the program
called `sh`, `bash`, `dash`...?" One `cp` later it's called `kworker`, and the rule is blind. A
name is the one thing about a file its owner controls completely. The fix took a few more days:
the agent now hashes the shells, interpreters and download tools shipped in each container's
image, and recognises a copy by its content. E01 is detected today.

**E02: no program, no event.** Python, Node and Perl can list directories, read files and open
sockets without ever starting another program. To a sensor built on process starts, the whole
session is one long-running `python3` with a network connection. That's a limit of the approach,
not a bug, and the write-up says so. What stays visible is what the session *touches*:
credentials, persistence paths, the Kubernetes API. Those are watched.

**E07: kill the watcher.** From a pod with enough privilege to see the node's processes, kill the
agent and read `/etc/shadow` in the seconds before Kubernetes restarts it. Nothing records the
read: the kernel programs went away with the agent. Getting that privilege is already a container
escape, but "what's still visible after an escape" is exactly the question a sensor should
answer. The fixes came later: the kernel side now keeps recording into a buffer that outlives the
agent, and a rule fires on any signal sent to the agent. E07 is detected today.

### The ones that didn't, and why

![Hook where the kernel has resolved the file, not where the program asked for it](/images/tephra-day4-lsm.png)

E04 and E06 were caught for the same reason, and it's the most useful design rule in the project:
**hook where the kernel has done the work, not where the program asked.**

- **io_uring** lets a program queue an open without making the `open()` system call. A sensor
  that hooks system calls never sees it. Tephra hooks `security_file_open`, the permission check
  every open passes through, however it was asked for.
- **The race in E06** is a classic time-of-check to time-of-use attack. One thread opens a name
  from a shared buffer, another flips the buffer between `/etc/shadow` and a harmless name. A
  sensor that reads the name from the program's memory can be shown one name while the kernel
  opens another. Tephra reads the file the kernel actually opened, after the kernel copied and
  resolved the name.

E03 (the hard link) was caught by the inode watch from day 3. Its first run was also invalid: the
link was made inside the judged window, and the alert counted was `ln` opening `/etc/shadow`
itself. Fun side lesson: preparing the evasion was already visible. E05's flood didn't fill the
buffer, and if it had, every dropped event is counted, so the gap would show. E08 cut the payload
out of the command line, but no rule matches on command lines, so the alert still fired. What it
cost was the evidence in the alert.

## Blocking, carefully

Detecting a module load is good. Refusing it is better, but a blocking bug on a node can stop
real workloads or the node itself. So blocking went in with every safety catch I could think of.

**Where:** BPF LSM programs, at the same security hooks, for the same reason as E06: a decision
made at system-call entry can be raced. The kernel asks the program, and the program's answer is
the decision.

**What:** six actions, chosen because they're rarely legitimate inside a container:

- running a binary with no file on disk (memfd);
- writing `/etc/ld.so.preload`;
- writing `release_agent` or `core_pattern` (classic container escapes);
- attaching to another process with ptrace;
- loading a kernel module;
- mounting a filesystem.

![Blocking ships off, then dry-run, only for labelled pods, with a kill switch](/images/tephra-day4-enforce.png)

**The safety catches:**

- **Off by default, then dry-run.** In dry-run nothing is refused; the sensor reports what it
  *would* have refused. You turn it on only after the dry-run looks right.
- **Opt-in per pod.** Only pods labelled `tephra.dev/enforce=true` can be refused anything.
  Host processes, `kube-system` and the agent itself never are.
- **The container runtime is let through by file identity,** not by name, since setting up a
  container legitimately mounts things.
- **A rule can only block if the kernel can judge it alone.** The compiler checks that the
  kernel's decision matches the rule on every recorded event, and refuses `action: block`
  otherwise.
- **A kill switch:** one command turns all blocking off, even with the agent dead.
- **Blocking survives the agent.** The programs and their settings are pinned in the kernel, so
  killing the agent (E07) doesn't switch blocking off.

The lab run did both modes on the six attacks that use these actions. In dry-run, 7 out of 7
would-be refusals were reported and nothing was stopped. With blocking on, all 7 were refused.

## Rules with two steps

Some attacks are two harmless-looking steps. Reading your pod's service account token is
normal. Talking to the Kubernetes API is normal. A shell that wasn't the pod's own program doing
**both within a minute** is how stolen credentials get used.

![R026: token read, then the Kubernetes API, same pod, within 60 seconds](/images/tephra-day4-sequence.png)

So rules can now be **sequences**: steps, a window, and what has to match between them (here,
the pod). R026 is that one; R025 is "a file downloaded into a container, then executed". Both
fire as one alert on the node, not as two events someone has to join later in a SIEM.

## Honest limits

- **3 of 8 evasions got through,** and I wrote the evasions too. Someone else would find others.
- **Blocking was tested on one kernel (7.0)** and covers six actions. Anything else is detect-only.
- **A sequence rule can't block.** By the time the second step happens, the first can't be undone.
- **E02 is still missed today.** Watching every open and connection of every interpreter would
  cost more than the sensor is allowed to; what's caught is what the session touches.

## Next

Day 5 was mostly a fight with AWS quotas. After that: benchmarks, more evasions, and the fixes
for the three that got through.

The code is at [github.com/tephrasec/tephra](https://github.com/tephrasec/tephra). This post covers
commit `51976c1`. The full evasion write-ups are in `docs/evasions/`.
