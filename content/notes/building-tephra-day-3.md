---
title: "Building tephra, day 3: from seeing events to catching attacks"
date: 2026-11-12
series: tephra
draft: false
tags:
  - kubernetes
  - ebpf
  - detection
  - runtime-security
  - blue-team
description: "Network and file events filtered in the kernel, rules that have to prove themselves, an agent that gave up root, and the first real attacks run against it. Plus the first false positive, two CI failures and a signed v0.1.0."
image: images/tephra-day3-card.png
---

![Most file opens never leave the kernel: three lookups decide, and only a match becomes an event](/images/tephra-day3-file-filter.png)

[Day 2](/notes/building-tephra-day-2/) ended with an agent that could say *which pod* a program
started in. Nothing judged it yet. Day 3 was the day it started catching things: network and
file events, a rule engine, somewhere to send alerts, and the first real attacks run against it.
It was the longest day of the build, six milestones, and it ended with a signed release.

## The cheapest event is the one you never send

Process starts are rare enough to report every one. File opens are not: a busy node opens
thousands of files a second, and copying each one out of the kernel would cost more than
anything the sensor could catch. So file events are filtered **in the kernel**, before anything
is copied. An open is reported only if the file is one a rule asked about, checked three ways:

- **by path prefix**: everything under `/etc/cron.d/`;
- **by file name**: `authorized_keys`, in whatever directory it is;
- **by the file itself**, its device and inode number: `/etc/shadow` reached through a hard
  link called `/tmp/innocent` is still `/etc/shadow`.

The third one matters most. A path is just a name, and an attacker can make new names. The
inode is the file.

One more piece came from the same idea: the rule compiler **refuses** a file rule it cannot
turn into one of those kernel lookups. A rule like "any file open by a shell" would quietly need
every open on the node sent to the agent, so it isn't allowed to load at all. Better a loud error
at start-up than a node that slows down on its own.

Network events came the same day: connects and accepts over IPv4, IPv6 and Unix sockets. One
detail I liked: accepts are hooked where the kernel attaches a new connection to its socket,
which also catches servers that were already waiting in `accept()` before the agent started.

## Rules that have to prove themselves

Rules are YAML, close to Sigma: a few named blocks of conditions and one line that combines
them. This is the one for `/etc/shadow`, as it was that day:

```yaml
id: R005
title: /etc/shadow opened by a process outside the allowlist
event: file_open
detection:
  selection:
    file.path: /etc/shadow
  allowed:
    process.Image: [/usr/bin/passwd, /usr/sbin/sshd, /usr/bin/sudo, ...]
  condition: selection and not allowed
```

The rule I set for myself: **a rule ships with the events it must fire on and the events it must
not**, recorded, and the tests run every rule against both. A rule with no proof doesn't count.
Fifteen rules went in that day, R001 to R014 and R021, each with its recorded events, and two
commands to work with them: `tephrad rules validate` and `tephrad rules test`.

![A rule is compiled to kernel watches or refused, and has to pass its recorded events](/images/tephra-day3-rules.png)

## Alerts before raw events

The agent sends everything to a small collector, which writes to Loki, with Grafana on top. Two
choices there are really security choices:

- The agent's send queue is bounded, and when it's full it **drops raw events before alerts**.
  If something has to be lost under load, it's the context, never the alert.
- The collector tells the agent a batch was received **only once Loki has stored it**. Until
  then the agent keeps it and sends it again. "Sent" and "saved" are not the same thing.

## The sensor gave up root

Until day 3 the agent ran as a privileged container: full root on every node. That makes the
sensor the most valuable thing to hijack in the cluster. Now it holds four capabilities, the
ones loading eBPF programs actually needs (`BPF`, `PERFMON`, `SYS_PTRACE`, `SYS_RESOURCE`),
drops every other one, and runs on a read-only root filesystem. A test reads the capability sets
of the running agent on every node, so this can't quietly regress.

![The agent kept four capabilities and dropped the rest; the release was signed](/images/tephra-day3-least-privilege.png)

## Then the real attacks

Unit tests prove the code does what I think. They don't prove it catches attacks. So the day's
biggest piece was an **attack harness**: each scenario is a real technique (a reverse shell,
reading `/etc/shadow`, a cron entry for persistence, loading a kernel module, mounting the host's
disk), run in its own throwaway namespace. The harness then looks for the alerts in Loki,
through Grafana, exactly where a person would look, and writes a coverage report: which rule
caught what, and how long it took.

It refuses to run on any cluster whose nodes aren't labelled as a lab. It runs real attack
techniques, and I didn't want it pointed at the wrong cluster by a typo.

![Each scenario runs a real technique in a throwaway namespace and is judged by the alerts in Loki](/images/tephra-day3-harness.png)

After v0.1.0 was out, the next step was obvious: write real attacks and see how well it holds
up. That set up the next days. Day 3's 22 scenarios were written by the same person who wrote
the rules, which is the easy test. Day 4 was about the hard one, attacks written to get past them.

### The first false positive

The harness also has a **false-positive run**: 30 minutes of ordinary workloads (a web server under
load with rolling updates, a database under a benchmark, an image build every few minutes), and
any high or critical alert during it is a failure. The first
run found one. **kaniko**, a tool that builds container images inside a container, writes
`/etc/shadow` while it unpacks a base image. To R005 that looks exactly like credential theft.
It went on the allowlist, with a comment saying why.

By the end of the day: all 22 scenarios detected on kernels 5.15 and 6.8, and on 6.8 no high or
critical alert in the 30-minute run.

## Trusting the right things

Some rules need to know whether a process is the **container runtime** (runc and friends): the
runtime legitimately does things that look like an escape. The first version recognised it by
path and command line. But a process inside a container can name itself anything and put any
command line it likes. So the agent now resolves the node's runtime binaries to their device and
inode at start-up, and "is the runtime" means "is running *that file*". The same lesson as the
file watches: names are cheap, files are not.

## Two CI failures

- **The M3 to M5 commit failed in CI.** Not the sensor: one acceptance check counted host
  program starts from a different log read than the one that found them. Fixed by counting from
  the same read.
- **A kernel renamed a function.** The refused-open hook attaches to `do_filp_open`, which newer
  kernels call `do_file_open`. On GitHub's runner the hook silently didn't attach. Now there are
  two copies of the program and the loader attaches whichever the kernel has. This is why every
  hook reports whether it attached, instead of assuming.

## v0.1.0, signed

The day ended with the first release: the agent and collector images built by GitHub Actions and
**signed with cosign**, keyless, tied to the repository's workflow. I ran `cosign verify` on both
images myself before calling it released. If you run my images, you can check they're the ones my
workflow built, and not something swapped in on the way.

## Honest limits

- **I wrote both the attacks and the rules.** 22 out of 22 is what that gets you. It says the
  rules work for the cases I thought of, not that they're hard to get past. Day 4 started on that.
- **R005's allowlist trusted paths.** A tool copied over `/usr/bin/passwd` would have been
  allowed to read `/etc/shadow`. Later, a file written after its container started stopped getting
  the exemption.
- **The lab is kind: three "nodes" sharing one kernel** on one machine. That evening it moved to
  an EC2 machine, but it's still kind, not a real multi-node cluster.
- **The false-positive run is three workloads for 30 minutes.** Quiet there is a floor, not proof
  of quiet in production.
- **The release workflow hadn't run when the code was committed.** It ran for v0.1.0 that
  afternoon, and the signatures checked out.

## Next

Day 4: evasions written to beat my own rules, the first blocking with BPF LSM, and correlation
rules that need two events to fire.

The code is at [github.com/Naved124/tephra](https://github.com/Naved124/tephra). This post covers
commits `3e540da`, `ecab6f9`, `0121ca9` and `a1cec7a`.
