---
title: "Building tephra, day 2: which pod did that come from?"
date: 2026-11-11
draft: false
tags:
  - kubernetes
  - ebpf
  - detection
  - runtime-security
  - blue-team
description: "Turning a counter into real process events, keeping a process tree that survives pid reuse, and the hard part: getting from what the kernel knows (cgroups) to what you care about (pods). Plus the decision that became the project's rule."
image: images/tephra-day2-card.png
---

![From what the kernel says to a pod: cgroup path, container ID, pod; unresolved means unknown, never host](/images/tephra-day2-cgroup-to-pod.png)

[Day 1](/notes/building-tephra-day-1/) ended with one eBPF program that counted every program
start on the node, and an agent on every node that loaded it. A counter tells you *how many*.
Day 2 was about *what*: which program, with what arguments, run by which user, started by
what, and the part I'd underestimated: **which pod it came from**.

## Three events are enough to follow every process

Every process on Linux comes from three things happening:

- **fork**: a process copies itself. The copy is the child.
- **exec**: a process replaces the program it's running with a new one. This is the moment
  `sh` or `curl` or `python3` actually starts.
- **exit**: it ends.

If you see all three for every process, you can rebuild the whole family tree of the node.
So day 2 added a kernel program for each one. Every event gets the same header: process id,
the time the process started, user and group, its cgroup, and the program name. Exec events also
carry the path of the program and its arguments.

All of them go onto the same ring buffer (the conveyor belt from day 1), and the agent takes
them off and prints one JSON line per event.

## Counting honestly

The test for this milestone wasn't "events show up". It was this: run a loop of 10,000
program starts, then check that

```
emitted + dropped + filtered == seen
```

Every event the kernel saw has to be accounted for: sent to the agent, dropped because the
belt was full, or filtered on purpose. If those numbers don't add up, events are disappearing
somewhere you can't see, and every coverage number you publish later is fiction. It added up.

## My first bug was seeing everything three times

My lab is a Kubernetes cluster in **kind**, where each "node" is really a container on one
machine. That means all three nodes share **one kernel**. So each node's agent saw every
process on every node, and each event showed up three times. On top of that, the process ids
the kernel reported didn't match the ones each node sees in its own `/proc`, because each kind
node has its own pid namespace (its own numbering of processes).

The fix: when the agent starts, it runs one tiny program in its own context to learn which pid
namespace it lives in. From then on, the kernel programs number processes the way that
namespace does, and drop anything outside it. On a real node the agent is in the root
namespace and nothing gets dropped, so the fix costs nothing there. It only matters in the lab,
but a lab that triple-counts makes every measurement wrong.

![Counting every event, and the bug where a kind lab saw every event three times](/images/tephra-day2-count-honestly.png)


## The decision that became the rule

When a script runs, say `/app/run.sh` starting with `#!/bin/sh`, what should the exec event
say the program was?

- **The script**, `/app/run.sh`: what the user typed.
- **The interpreter**, `/bin/sh`: what the kernel actually runs.

It sounds like a detail. It isn't. The rules I'd planned look for things like "a shell started
by a web server". If the event names the script, an attacker can wrap a shell in a two-line
script and the event says `run.sh`, not a shell. If it names the interpreter, wrapping doesn't
help: a shell is a shell. The script's path isn't lost; it's still in the arguments.

I was asked which one I wanted. My answer was *"use interp, and also always make the best
security decision."* The first half settled the question. The second half became the rule for
every decision after it, and it came back a lot.

![Naming the script lets a shell hide in it; naming the interpreter means a shell is always a shell](/images/tephra-day2-script-or-interpreter.png)


## The process tree

One event isn't enough for detection. "A shell started" is noise. "A shell started *by nginx*"
is an alert. So the agent keeps a tree of every process and its parent, built from the fork,
exec and exit events. A few things I didn't expect:

![The process tree, and its three traps: reused pids, processes older than the agent, parents that leave](/images/tephra-day2-process-tree.png)


- **A pid alone means nothing.** Linux reuses process ids. If pid 4021 exits and a new
  process gets 4021 a second later, a tree keyed by pid would attach the new process to the
  old one's history. So every process is keyed by **pid plus its start time**, which is unique
  for as long as the node is up.
- **Processes that started before the agent.** When the agent starts, nginx has been running
  for hours. Its fork and exec happened before anyone was watching. So at start-up the agent
  reads `/proc` once and adds everything already running. One catch: `/proc` gives start times
  in clock ticks (10 ms), while the kernel events give nanoseconds. A process read from `/proc`
  is matched to its events by pid and tick.
- **Parents that leave.** When a container starts, the runtime (runc) creates the container's
  first process and then exits, and the kernel hands the orphan to another parent. The tree
  has to notice that the recorded parent is gone and ask `/proc` who the parent is now.
  Otherwise every container's process tree ends in a dead process.
- **The order is guaranteed.** Every hook writes to the same ring buffer, which hands events
  over in the order they happened. So a child's exec can never arrive before its fork. If the
  agent sees an event for a process it doesn't know, that process started before the agent,
  and it can be read from `/proc` right away instead of waiting in case the fork shows up late.

## The hard part: from cgroup to pod

The kernel has never heard of a pod. What it knows is the process's **cgroup**, the group
Linux uses to limit and account for resources, and Kubernetes gives every container its own.
The event carries a number, the cgroup ID. Getting from that number to a pod name takes three
steps:

```
cgroup ID  12345
  → cgroup path   (walk /sys/fs/cgroup for the directory whose inode number is 12345)
    .../kubepods-pod0a1b2c3d....slice/cri-containerd-3f9c....scope
  → container ID  (the 64 hex characters in the last part of the path)
    3f9c...
  → pod           (asking Kubernetes which pod has a container with that ID)
    namespace shop, pod web-7c9d8-xk2lp, container web, image nginx:1.27
```

The last step uses a Kubernetes *informer*: the agent watches the pods on its own node and
keeps an index from container ID to pod, so there's no API call per event.


Two edge cases mattered:

- **A container's first processes run before Kubernetes knows its container ID.** The
  container starts before its status reaches the API server. For that window, the agent falls
  back to the pod's UID, which is also in the cgroup path, so the event still names the
  namespace and pod, just not the container yet.
- **`host` versus `unknown`.** A process with no container is labelled `host`. But a process
  whose cgroup can't be resolved, or whose container Kubernetes doesn't know, is labelled
  `unknown`, never `host`. Calling something a host process when you don't actually know is
  exactly the kind of quiet wrong answer an attacker would love.

And one small thing that made the output readable: the **user name** comes from the
container's own `/etc/passwd`, read through `/proc/<pid>/root`, not the node's. uid 33 is
`www-data` in a Debian image and might be nothing at all on the node.

## What an event looked like by the end of day 2

```json
{
  "type": "exec",
  "node": "kind-worker",
  "process": { "pid": 48211, "Image": "/bin/sh", "CommandLine": "sh -i", "User": "www-data", "uid": 33 },
  "parent": { "pid": 48190, "Image": "/usr/sbin/nginx", "CommandLine": "nginx: worker process" },
  "ancestors": ["/usr/sbin/nginx", "/usr/bin/containerd-shim-runc-v2"],
  "container": { "name": "web", "image": "nginx:1.27" },
  "k8s": { "namespace": "shop", "pod": "web-7c9d8-xk2lp", "labels": { "app": "web" } }
}
```

That's a shell, started by nginx, inside the `web` pod in the `shop` namespace. Nothing
judges it yet; there are no rules until day 3. But for the first time, an event says
everything a person would need to decide whether to worry.

The test for this milestone: an exec in a pod carries namespace, pod, container, image and the
chain of ancestors; a host process is labelled host; and after the agent restarts, events
from processes that were already running still resolve. All three passed.

## Then the oldest kernel

The goal from day 1 was to run on any kernel from 5.15 up without compiling anything on the
node. So the same compiled programs (built on my laptop against a 7.2 kernel) went onto an
Ubuntu 22.04 VM running 5.15. They loaded unchanged, and the day 1 and day 2 tests passed there
with zero drops.

That works because of **CO-RE** (compile once, run everywhere): the program records which kernel
structure fields it reads, and the kernel's own type information (BTF) tells the loader where
those fields are on *this* kernel. A field that moved between versions is found where it is
now, without recompiling.

Honest limit: that was Ubuntu's 5.15, not a plain upstream one, and it was a manual test, not
something CI runs on every change.

## Next

Day 3: network and file events, the first detection rules, and the attack harness that would
start telling me what Tephra misses.

The code is at [github.com/Naved124/tephra](https://github.com/Naved124/tephra). This post
covers commits `7096e66` and `7abdfc6`.
