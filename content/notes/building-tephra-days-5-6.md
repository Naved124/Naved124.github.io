---
title: "Building tephra, days 5 and 6: a quota wall and the oldest kernel"
date: 2026-11-18
series: tephra
draft: false
tags:
  - kubernetes
  - ebpf
  - aws
  - runtime-security
  - blue-team
description: "A new AWS account's CPU limit paused testing for four days. Then the blocking and two-step rules ran on the oldest kernel Tephra supports, 5.15, in a lab with no open ports that boots the kernel under test."
image: images/tephra-day5-6-card.png
---

![The lab: a throwaway EC2 machine with no open ports, booted into the kernel under test](/images/tephra-day5-6-lab.png)

[Day 4](/notes/building-tephra-day-4/) added blocking and two-step rules, tested on kernel 7.0.
The obvious next question: do they work on the **oldest** kernel I claim to support? Answering
it took two days, and only one of them was about the kernel.

## Day 5: the quota wall

Every test runs on an AWS machine, never my laptop. The machine I wanted had 32 vCPUs. My account
was allowed **8**.

That's normal. New AWS accounts start with a small CPU limit (a "service quota") to protect
against stolen cards and runaway scripts, and raising it means a support request and waiting
for a person to approve it. I filed the request and waited. Day 5 produced no code.

It was a useful reminder that infrastructure is part of the project. A plan that assumes
compute is always there isn't a plan. The limit came back at **16 vCPUs**, half of what I asked
for and enough to work with. Every lab since has been sized for it.

## Day 6: the kernel floor

Tephra promises to run on **Linux 5.15 or newer**. That number is its *kernel floor*: 5.15 is
the long-term kernel of Ubuntu 22.04, which a lot of clusters still run. A promise like that is
only worth something if it's tested on the floor itself, not just on whatever new kernel my
machine happens to have.

### Compile once, run on every kernel

![Compiled once against a new kernel, the same programs load on 5.15 through 7.0](/images/tephra-day5-6-co-re.png)

eBPF programs read kernel structures, and those structures change shape between versions: a
field moves, gets renamed, or disappears. The old way was to compile on every node against its
own kernel headers. Tephra uses **CO-RE** ("compile once, run everywhere"): the programs are
compiled once, and at load time the kernel's own type information (BTF) tells the loader where
each field actually is on *this* kernel.

Day 6 showed why that matters. Ubuntu 22.04's own build tools are too old to even compile
Tephra's programs. That didn't matter: the programs compiled on my laptop against a 2026 kernel
loaded unchanged on 5.15. Shipping one binary is the whole point.

### What 5.15 needs

Blocking runs as **BPF LSM** programs, and the kernel only runs those if `bpf` is in its list of
active security modules. That list is set at boot, and most distributions leave `bpf` out. So
the lab machine:

1. boots Ubuntu 22.04 (whose default kernel is actually 6.8),
2. installs the 5.15 long-term kernel and makes it the default,
3. adds `bpf` to the security-module list on the boot line,
4. reboots, then checks that `/sys/kernel/security/lsm` really contains `bpf` before running anything.

The last step matters. Attaching an LSM program *succeeds* even when `bpf` isn't active; it
just never runs. If you don't check the list, a "passing" blocking test proves nothing.

### The result

All **25 kernel tests** passed on 5.15.0-1120-aws, including the four blocking tests:

- the programs attach;
- every blockable action is reported in dry-run and refused when on;
- blocking keeps working while the agent is gone, and the kill switch turns it off;
- a process started by the container runtime keeps the runtime's pass when it forks.

## The lab, since it carries every result

- **A throwaway EC2 machine**, built by Terraform and destroyed at the end of each session. A
  typical day costs between $0.50 and $2.
- **No inbound ports at all.** The security group allows nothing in; I reach the machine through
  AWS's session service, which needs my AWS login rather than an open SSH port.
- **The kernel under test is chosen at creation:** current, or the 5.15 floor.
- **One script** (`lab.sh up | sync | ssh | destroy`) does all of it, so a run is reproducible
  from the repository.

## Honest limits

- **Day 6 ran the kernel tests on 5.15, not the full attack runs.** The kind cluster and the
  attack harness weren't repeated on 5.15 for blocking and two-step rules that day. They were
  later.
- **One distribution's 5.15.** Ubuntu patches its kernels. A vanilla 5.15, or another
  distribution's, could differ.
- **Kernels below 5.15 aren't supported at all.** There's no fallback for them.

## Next

Day 7: the first benchmarks, and a hard look at what the numbers can and can't show.

The code is at [github.com/Naved124/tephra](https://github.com/Naved124/tephra). This post covers
commit `6abe3ed`.
