# Security model

Everything inside the guest is treated as hostile, its kernel included. A guest
that gets root, or exploits its own kernel, is expected. The guest still must not
reach the host. To escape, it would need all three of these:

1. a hardware-virtualization or hypervisor (KVM / Hyper-V) escape, **or** a bug in
   this VMM's device emulation, **and then**
2. a way out of the VMM's process sandbox, **and**
3. something worth reaching from an unprivileged user account.

The VMM never runs as root or admin. There is no setuid helper and no
privileged daemon. On Linux the VMM only needs access to `/dev/kvm`. The
host-isolation wrapper `microvm-jail` works unprivileged, through a user
namespace. A service can also start it as root, so that every VM gets a
host uid of its own; it drops everything before the VMM runs.

## Reporting a vulnerability

Report it privately. Do not open a public issue or pull request for it. On the
repository's GitHub page, open the **Security** tab and choose **Report a
vulnerability**. That is GitHub's private vulnerability reporting, and only
the maintainers see the report.

Include:

- the host (Linux/KVM or Windows/WHP) and the commit or release you tested;
- the command line, or the API requests, that show the problem;
- what the attacker controls (the guest, an image, an API client) and what
  they gain, meaning which boundary is crossed;
- steps to reproduce, and the output of `--trace` where it helps.

These are in scope:

- a guest-to-host escape: from the guest into the host, through the VMM's
  device emulation or hypervisor interface;
- a sandbox escape: getting out of the VMM's process sandbox, or out of
  `microvm-jail`;
- an authentication bypass in `microvm-sbxd`'s API: getting past `X-API-KEY`
  or a sandbox's `X-Access-Token`.

A guest that gets root inside its own VM, or exploits its own kernel, is
expected. It is not a vulnerability by itself, as the model above describes.
Report it only if it also gets past one of the boundaries above.

Security fixes go to the latest release and to the main branch. Only those are
supported.

## The VMM sandbox (`src/sandbox*.c`)

The VMM enters the sandbox once setup is done, before the first guest
instruction runs. Every file the run needs is opened before that point. Entering
it costs about 0.1 ms. `--no-sandbox` turns it off, for debugging only.

| Linux | Windows |
|---|---|
| seccomp-BPF allowlist of about 30 syscalls; anything else kills the process | job object: no child processes, memory cap, killed on unhandled exceptions, no desktop/clipboard access |
| `ioctl` allowed only on the vCPU fd (`KVM_RUN`, `KVM_GET_REGS`), plus `KVM_SIGNAL_MSI` on the VM fd (interrupts into its own guest) | all token privileges removed |
| `mmap`/`mprotect` can never create executable memory | token lowered to Low integrity (can't write the user's files, registry, or other processes) |
| Landlock: every filesystem and TCP right denied, abstract-socket and signal scoping on (ABI 6) | no dynamic code; only Microsoft-signed DLLs; no win32k; strict handle checks; no extension points |
| `no_new_privs`, non-dumpable, `RLIMIT_NOFILE`/`CORE`/`MEMLOCK` = 0, `RLIMIT_AS` capped (not `RLIMIT_NPROC`: KVM starts a per-VM worker task under the VMM's uid on the first `KVM_RUN`; seccomp refuses new processes instead) | |

With a virtio-vsock device (`--vsock`), its I/O thread starts after
Landlock and the rlimits and before seccomp, so both cover it; Landlock only
binds threads created after it is applied. The filter then also allows
`poll`, `ppoll`, `readv`, `writev`, `shutdown`, and `accept4` on the
device's listening socket only. `RLIMIT_NOFILE` is 64 + 16 instead of 0.
There is still no `socket`, `connect`, `bind` or `open`: the device can only
use the connections it accepts.

With a network device (`--net`), its I/O thread gets the same calls, plus
`recvmsg` on the network helper's channel only. The helper's replies carry
the host sockets it opened (`SCM_RIGHTS`). The VMM still has no `socket`,
`connect`, `bind`, `sendto` or `open`, so the only sockets it holds are the
ones the egress policy let through (see
[Guest networking](#guest-networking---net)). `RLIMIT_NOFILE` grows by 96
(64 TCP and 32 UDP flows).

Device threads are fully started before seccomp goes on: `os_thread_start()`
returns only once the new thread runs its own code. Before that fix, glibc's
start-up in the new thread (its `rseq()` registration) could land after the
filter under load, and seccomp killed the VMM. 20 VMs starting at once hit it.

**Several vCPUs** (`--cpus N`, KVM only, at most 8):

- vCPU 0 runs on the main thread. Each of the others gets a thread of its
  own, started like the device threads: after Landlock and the rlimits,
  before seccomp. It waits on a futex until the guest is started.
- The ioctl allowlist is the same list of requests on each vCPU's own fd.
  The filter groups the pairs by request: a request, then the fds it may
  be used on. The lists of 8 vCPUs, 16 requests each, then fit the BPF
  jump range. A request listed for the vCPU fds is still killed on any
  other fd (`mvm_sandbox_tests` checks this with 8 vCPUs' lists).
- A vCPU is kicked out of the guest with `tgkill(SIGUSR1)`, the only
  signal the filter lets through. The kick first sets KVM's
  `immediate_exit`, so it can't be lost while the thread is outside
  `KVM_RUN`.
- Each exit is handled on the thread that took it:
  - port I/O (UART, CMOS, the control ports) under one lock;
  - virtio and the I/O APIC, which already locked their state for the
    device I/O threads.
- A snapshot first parks every other vCPU. Each one saves its own state,
  on its own thread, and then waits. Nothing is read while a vCPU still
  runs.
- The guest sees one package of 8 single-thread cores, whatever N: no SMT
  siblings. vCPU 0's CPUID, and so a snapshot's CPUID hash, is the same
  for every N.
- A snapshot records N. A restore runs exactly that many vCPUs and refuses
  more than 8.

With `--snapshot FILE`, the filter also allows the vCPU-state reads that
saving needs (`KVM_GET_SREGS`, `_XSAVE`/`_XSAVE2`, `_XCRS`, `_DEBUGREGS`,
`_LAPIC`, `_MSRS`, `_VCPU_EVENTS`, `_MP_STATE`), on the vCPU fd only. FILE
is opened beforehand, mode 0600. The base allowlist includes `pwrite64`,
which works only on fds that are already open, like `write`.

If a layer exists on the host but fails to apply, the VMM refuses to run. Layers
the host doesn't provide at all, such as a kernel without Landlock, are skipped
and reported (`--trace` prints a `sandbox:` line).

Not done yet: AppContainer on Windows. The layers above already deny
filesystem and network access. On Linux, namespaces come from `microvm-jail`
(below).

## Host isolation (`microvm-jail`, Linux)

`microvm-jail` wraps one VMM. The service starts every VM through it:

```bash
microvm-jail --uid 30017 --gid 30017 --base /run/microvm/base/mnt \
    --cgroup /sys/fs/cgroup/microvm/vm-17 --mem-max 134217728 --pids-max 16 \
    --bind /srv/vmlinux:/vmlinux --bind /srv/images/app.erofs:/app.erofs \
    -- /usr/libexec/microvm --kernel /vmlinux --rootfs /app.erofs -- /bin/app
```

This layer sits under the VMM's own sandbox. It decides what a compromised
VMM could still reach, even if seccomp or Landlock had a hole:

| | what the VMM gets |
|---|---|
| identity | Started as root: `--uid`/`--gid` are required and not 0. They are the VM's own host uid and gid, with the group of `/dev/kvm` as the only supplementary group. Started as anyone else: the caller's ids, through a user namespace. |
| privileges | No capabilities in any set, an empty bounding set, `no_new_privs`, only fds 0–2 (with `--net`, also the network helper's channel as fd 3), an empty environment, umask 077. `PR_SET_PDEATHSIG`: it dies with the jail. |
| filesystem | A new root: an empty read-only tmpfs holding only `/microvm` (the VMM, read-only), `/dev/kvm`, `/proc` and the `--bind` files. Binds are read-only unless `:rw`, and always `nosuid,nodev,noexec`. The old root is detached, not just hidden. `/proc` is this PID namespace's only, with `subset=pid,hidepid=invisible`. |
| namespaces | mount, PID (the VMM is pid 1 and sees no other process), network (only a loopback that is down, even with `--net`), IPC, UTS (hostname `microvm`), cgroup (rooted at the VM's own cgroup). |
| resources | `--cgroup DIR` (cgroup v2): `memory.max` (with `memory.swap.max` 0), `pids.max`, `cpu.max`, `cpu.weight`. The VM's first process is created inside it (`clone3` with `CLONE_INTO_CGROUP`). It is never moved in, and it can't change its own limits, since cgroupfs is not mounted and the cgroup belongs to the jail's caller. |

One process stays outside the VM's namespaces and cgroup, under the VM's
credentials: the waiter. It turns SIGTERM, SIGINT and SIGHUP into SIGKILL for
the VM, and exits with the VMM's status, or 128 + N for a signal. Setup
failures exit with 125, and nothing is created on the host. Its cost is
64 KB of private memory per VM.

Arguments are checked before anything is created. Refused:

- relative, `.`, `..` or overlapping `--bind` destinations, and any under
  `/microvm`, `/dev` or `/proc`;
- limits that aren't numbers or `max`;
- a cgroup that is in use;
- uid 0;
- `--uid` without root;
- `--base` that isn't a pinned mount namespace;
- `--net-allow` or `--net-dns` without `--net`, and the VMM's own `--net`,
  `--net-fd`, `--net-allow` or `--net-dns` (they go to the jail; see
  below). Words after the VMM's `--`, the guest's command, aren't checked.

Bind sources are resolved once, by the jail, with `open_tree()`. That
happens before the new root exists, so paths inside the VM can't redirect
them.

**Two options for a service starting many VMs at once.** With N=256 VMs
starting together, they take launch-to-VMM-`main()` from 20 ms to 5 ms.
The VM's view is the same either way.

- `--base FILE` (root only). FILE pins a mount namespace made once with
  `--make-base`. Its whole tree is one empty read-only tmpfs. Without it,
  every VM's mount namespace starts as a copy of the host's full mount
  table, which is then detached again. Both operations hold the kernel's
  global `namespace_sem`. FILE must sit on a mount with private
  propagation: `mount --bind D D; mount --make-private D`. `umount FILE`
  drops it.
- `--cgroup DIR` reuses DIR if it exists and is empty. Every limit is
  written again, and the defaults go to the ones not given. Creating a
  cgroup holds the global `cgroup_mutex`, so the service can create a pool
  ahead of time.

### Networking and invocations under the jail

Production runs every VM under `microvm-jail`, so `--net` and function
invocations (`--vsock`) have to work there with every layer above intact.

**`--net`: the helper is started by the jail.** The VMM's own `--net`
forks the network helper from the VMM. Under the jail that helper would
sit in the VM's empty network namespace, where every route lookup and
every connect fails. We compared:

| | what it costs |
|---|---|
| (a) keep the host's network namespace for VMs with `--net` | The VMM itself would share the host's network: its interfaces, its abstract UNIX sockets, everything listening on loopback. seccomp still denies it `socket()`, but the jail exists for the case where seccomp has a hole, and for these VMs that layer would be gone. |
| (b) bind-mount a socket directory into the jail, with the helper (or a daemon) listening there | A host-side listener per VM or a shared daemon, a new protocol on a filesystem socket, and a socket the VM could connect to as often as it likes. |
| (c) the jail forks the helper before the VM's process exists, outside its network namespace only, and passes the channel in by fd | The VMM is unchanged: it already takes a helper channel with `--net-fd`. |

We use (c). `microvm-jail --net [--net-allow CIDR]... [--net-dns ADDR]...`
makes the channel (a `SOCK_SEQPACKET` socketpair), creates the helper,
then the VM's process, and adds `--net-fd 3` to the VMM's arguments. The
helper is a fork of the jail (the code is `src/net_helper.c`, linked into
both), and runs `net_helper_main()`, the same loop as the VMM's helper.
Before reading a request it is placed like this:

| | the VMM's own helper (no jail) | the jail's helper |
|---|---|---|
| identity | the VMM's | the VM's uid and gid, without `/dev/kvm`'s group |
| privileges | inherited from the VMM's caller | no capabilities, an empty bounding set, `no_new_privs` |
| namespaces | all the host's | its own mount (an empty read-only tmpfs as root, the old root detached), PID (it is pid 1), IPC, UTS and cgroup; the host's network |
| cgroup | the VMM's caller's | the VM's: `pids.max` counts it, and the guest's socket buffers count against `memory.max` (a socket is charged to the cgroup of the process that creates it) |
| lifetime | `PR_SET_PDEATHSIG` with the VMM | `PR_SET_PDEATHSIG` with the jail; it exits when the VMM's end of the channel closes, and the jail kills and reaps it after the VMM |
| its own sandbox | seccomp, Landlock, rlimits, no files (below) | the same |

Why this is no weaker than the unjailed helper, and the VM no weaker than
one without `--net`:

- **The VMM** is in the same empty network namespace, with the same
  seccomp filter, Landlock and rlimits as without the jail. Its one extra
  fd is the channel the unjailed VMM holds too, and seccomp allows
  `recvmsg` on that fd only. It still can't create, bind or connect a
  socket.
- **The helper** holds exactly what it holds without the jail (the channel
  and a netlink socket), under the same seccomp filter, and is more
  confined on every other axis (table above). The host's network
  namespace is the one thing it shares with the host, as it does without
  the jail. The route check needs it, to see the host's own addresses.
  In that namespace, abstract UNIX sockets are out of its reach twice:
  seccomp kills any `AF_UNIX` socket, and Landlock scopes abstract
  sockets.
- **The egress policy** is the same code, in the same namespace, so it
  refuses the same destinations (no host loopback, link-local or
  metadata, private ranges or host addresses by default). Its options
  come from the jail's caller, never from the VM's process. The jail
  refuses the VMM's own `--net` options, and the VMM refuses
  `--net-allow` and `--net-dns` with `--net-fd`, so a policy can't be
  silently dropped. The jail reads `/etc/resolv.conf` for the resolver
  before the helper's root becomes empty.
- **A compromised VMM** can only ask the helper for sockets, as a guest
  can. It can't signal or trace the helper (another PID namespace,
  non-dumpable) or reach its files (it has none).

The cost per VM is one more process. On the box it has 12 KB of private
dirty memory, plus its kernel stack and page tables. The rest of its
520 KB resident are pages of the jail's static binary, which VMs share
(Pss 298 KB with one VM running).
`mvm_jail_tests` checks the placement from both sides, and
`mvm_net_tests --jail` runs the whole network suite through the jail.

**Invocations (`--vsock`): a per-VM `:rw` bind.** The vsock device's
socket is a UNIX socket the VMM creates at its path before its sandbox
starts. The host must reach it from outside the jail's root. The jail
already gives it a place: the service makes one directory per VM (owned
by the VM's uid in root mode, mode 0700), binds it `:rw`, and gives the
VMM a path in it:

```bash
microvm-jail --uid 30017 --gid 30017 --bind /run/microvm/vm-17:/run:rw \
    --bind /srv/vmlinux:/vmlinux --bind /srv/images/app.erofs:/app.erofs \
    -- /usr/libexec/microvm --kernel /vmlinux --rootfs /app.erofs \
       --vsock /run/vsock.sock --append agent -- /bin/app
microvm-invoke /run/microvm/vm-17/vsock.sock ...
```

- The VM's process can write only in its own directory, and only before
  its sandbox starts: there it creates the socket, and with `--snapshot`
  the snapshot file. After that, Landlock and seccomp deny every file
  operation. No other VM's root holds the directory.
- The jail starts the VMM with umask 077, so the socket is `srwx------`,
  owned by the VM's uid. Connecting needs write permission on it, so
  only that uid and root can talk to the guest. Before this the socket
  took the caller's umask.
- The host side connects to a path the service chose. It never opens a
  path the VM named.
- Restores work the same way: the snapshot is read from a bind (read-only
  is enough), and the restored VM's socket goes in its own directory.

We kept the bind over passing a listening socket in by fd (as for
`--net`). A passed socket would save the `:rw` bind, but snapshots need
one anyway, the directory is the VM's alone, and the VMM's code path stays
the one that is fuzzed and tested without the jail. `mvm_agent_tests
--jail` runs the whole invocation suite this way: cold boots, a snapshot
written through the bind, 5 restores, and the VM-ending cases.

## Guest networking (`--net`)

`--net` gives the guest a virtio-net device and IPv4 to the outside. Nothing
on the host changes: no tap device, bridge, iptables rule or capability.

The VMM is the guest's only peer on the link, in the style of passt:

- It answers ARP for every address.
- It ends the guest's TCP connections itself and relays each one's bytes
  over a host socket of its own.
- UDP goes out over one connected socket per flow.

The guest's addresses are static, from the kernel's `ip=` (no DHCP):

| | |
|---|---|
| guest | 10.0.2.15/24 |
| gateway | 10.0.2.2 |
| resolver | 10.0.2.3 |

**Who opens the sockets.** We compared three designs:

| | what a compromised VMM could reach |
|---|---|
| (a) `socket`/`connect` in the device thread, under seccomp argument filters and Landlock | Anything. seccomp can't read `connect()`'s address, which sits behind a pointer, and Landlock's network rules know only TCP ports, not addresses or UDP. The egress policy would live in the VMM's memory, which is exactly what the guest attacks. |
| (b) a sandboxed helper process that opens the sockets and passes them over a socketpair | Only what the helper's policy allows. The VMM itself keeps no `socket` or `connect`. |
| (c) no NIC at all, a proxy over vsock | The same as (b). But every guest program would need proxy settings (`HTTP_PROXY`, SOCKS), there would be no plain TCP or UDP, and DNS would work only through the proxy. |

We use (b) (`src/net_helper.c`). The helper is forked at the start of
`main()`. At that point the VMM has read nothing from the guest, the kernel
or a snapshot, and it still has a single thread. The helper keeps two
fds: the channel to the VMM and a netlink socket for route lookups.

- Requests are fixed-size records, `{id, proto, v6, port, addr[16]}`, over
  `SOCK_SEQPACKET`. There is nothing to parse beyond that.
- seccomp kills every call except:
  - `recvfrom` and `sendmsg` on the channel;
  - `sendto` and `recvfrom` on the netlink socket;
  - `socket(AF_INET or AF_INET6, SOCK_STREAM or SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)`;
  - `connect`, and `setsockopt(IPPROTO_TCP, TCP_NODELAY)`;
  - `write` (logs), `close`, and exit.
- Landlock denies every file, and TCP `bind()`.
- `RLIMIT_NOFILE` covers its two fds plus the socket being passed on. No
  core dumps, `no_new_privs`, non-dumpable.
- It dies with the VMM (`PR_SET_PDEATHSIG`). If the helper dies, the
  VMM's requests fail, and the guest gets an RST.

`mvm_sandbox_tests` probes each of these limits.

**The egress policy** (`net_policy_route()`, in the helper) runs these
steps in order:

0. **`--net-deny-all`** refuses every flow, DNS included, before any other
   step. The guest still has its interface, and nothing gets out.
   `microvm-sbxd` uses it for a sandbox created with
   `allow_internet_access: false` on a template with a network: such
   sandboxes are restores of a snapshot that had the device, so the
   device stays and the policy closes it.

**A refused datagram is answered at once** (`udp_refused()` in
`src/dev/net.c`), as a refused TCP connection gets a RST:

- A DNS query to the resolver address gets NXDOMAIN: with no way out,
  no name resolves.
  - Resolvers that don't connect their socket (musl's) never see ICMP
    errors.
  - musl ignores every rcode but NOERROR and NXDOMAIN.
  - REFUSED or silence would leave them waiting out their 10 s timeout.
- Any other datagram gets ICMP "administratively prohibited" from the
  gateway.

The query is parsed only enough to copy its question back:

- one question;
- labels up to 63 bytes, a name up to 255, no compression;
- anything else is dropped.

Only refusals by the policy (`-EACCES`) are answered. A datagram lost for
want of a socket stays lost, so the guest retries, and no resolver
caches a false "no such name".

1. **The resolver.** 10.0.2.3:53, UDP or TCP, goes to the host's resolver:
   `--net-dns ADDR`, or else the first `nameserver` in `/etc/resolv.conf`.
   Any other port on 10.0.2.3 is refused. The host chooses this address,
   so it is the one way past the rules below, and only for DNS. A
   resolver that answers for private names (a tailnet's MagicDNS, split
   DNS) tells the guest those names; their addresses stay refused. A
   service should point `--net-dns` at a resolver meant for tenants.
2. **The gateway.** 10.0.2.2 is the host's loopback, 127.0.0.1, and is
   refused like any loopback address. Tests let it through with
   `--net-allow 127.0.0.1/32`.
3. **Port 0** is refused, and so is every **`--net-deny-port PORT`** (up to
   16), TCP and UDP, at any address but the resolver's. `microvm-sbxd`
   denies mail (25, 465, 587) to every sandbox. The helper answers EPERM,
   not EACCES, so the device counts these apart (`denied`, below).
4. **`--net-allow CIDR`** (up to 16 ranges) lets a range past steps 5 and 6.
5. **Refused ranges:**
   - IPv4: loopback, link-local (so 169.254.169.254, cloud metadata),
     "this network", multicast, reserved and broadcast, the IETF,
     documentation and benchmarking ranges, RFC 1918 (10/8, 172.16/12,
     192.168/16), and carrier-grade NAT (100.64/10).
   - IPv6: the same kinds, plus IPv4-mapped and NAT64 (either could reach
     the IPv4 ranges), 6to4, ULA (fc00::/7) and site-local.
6. **The route check.** The kernel's route for the address
   (`RTM_GETROUTE`) must be `RTN_UNICAST`. This refuses the host's own
   addresses, whatever they are: they are `RTN_LOCAL`, and so is anything
   listening on 0.0.0.0. It also refuses broadcast, blackhole and
   unreachable routes.

**RFC 1918 and CGNAT are refused by default.** On a hosting box, these
ranges are where the provider's own things live:

- docker networks (172.17/16 and the rest);
- a VPC, with its databases and control plane;
- a tailnet (100.64/10).

A tenant has no business there. Guessing per host which private ranges
are "safe" is how SSRF happens. A deployment that wants a private service
reachable names it with `--net-allow`.

On the test box, the policy refuses:

- docker0 and another bridge (172.17.0.1, 172.18.0.1, and the bridge's
  ULA);
- the tailnet (its 100.64.0.0/10 address) and its resolver (100.100.100.100), except
  through step 1;
- the host's own public address, by step 6.

**Limits: a guest used against others.** A tenant that scans, floods or
sends spam does it from the host's addresses. The provider gets the
complaints, and the host's addresses the blocklists. The policy above
decides where a guest may go; these decide how much:

- **`--net-flow-rate N`**: new flows a second, in the helper. A GCRA
  allows bursts of up to 5 s worth. Every request counts, refused ones
  too, so a scan of closed ports is slowed as much as one of open ports.
- **`--net-max-dests N`** (at most 4096): different addresses a minute, in
  the helper. An address already reached this minute stays reachable; a
  new one past N is refused until the minute is up. A scan touches many
  addresses; ordinary work, even a crawl, touches far fewer.
- **`--net-tx-rate BYTES`**: bytes a second out.
  - The device caps all the guest's flows together: a GCRA again, up to a
    second's worth at once. A TCP flow over the cap keeps its data in its
    `TCP_IN` buffer, and the window the guest sees closes. Its own TCP
    slows down; nothing is dropped or reset. UDP over the cap is dropped.
  - The helper also sets `SO_MAX_PACING_RATE` to the same rate on every
    TCP socket. The kernel paces each one there, and the VMM can't change
    it (the helper's seccomp filter allows that option; the VMM has no
    `setsockopt` at all). So a VMM that has fallen to the guest still
    can't send faster than the rate times its 64 flows.

Both helper limits refuse with EAGAIN, which the device counts as
`limited`. The guest sees an RST, or an ICMP error for UDP.

**Counters for the host (`--stats FILE`).** The device writes one line
every 2 s, and within 0.2 s of a denied or limited flow:

```
cpu_ns N tx N rx N flows N refused N denied N limited N
```

`cpu_ns` is the whole VMM's CPU time, the guest's included. The others
count since the VMM started: payload bytes each way, flows opened, and
flows refused by the policy, by a denied port, or by a limit. The VMM
opens the file before it sandboxes itself and only ever `pwrite`s it. It
is the host's evidence, not a control: a VMM the guest has taken can write
anything there, while the limits stay in the helper and the kernel.
`microvm-sbxd` serves them as `GET /stats`, where the control plane looks
for abuse.

The policy uses the network namespace the helper runs in. Under
`microvm-jail`, the VMM sits in an empty network namespace, so the jail
starts the helper outside it and passes the channel in with `--net-fd`
(see [Networking and invocations under the jail](#networking-and-invocations-under-the-jail)).

**The device** (`src/dev/net.c`) faces the guest. It takes guest input as
follows:

- **Headers:** each frame's headers are copied once (at most 146 bytes)
  and parsed from that copy. Payloads go straight from the chain to the
  socket (`writev`). These must fit:
  - the IP total length, inside the frame;
  - the IHL and the TCP data offset, inside the headers copied;
  - the UDP length, inside the IP payload.
- **Dropped frames:** fragments (there is no reassembly), sources other
  than 10.0.2.15, broadcast, multicast and loopback destinations, and
  IPv6 (the guest kernel has no IPv6).
- **Limits:** at most 64 TCP flows and 32 UDP flows. UDP flows expire
  after 60 s idle, or 5 s for DNS. At most 64 RSTs and 4 ARP or ping
  replies wait for a receive buffer; more are dropped.
- **Per-flow buffers:** 128 KiB guest → host and 256 KiB host → guest.
  They are demand-paged and given back when the flow ends.
- **Window:** the window we advertise is what the guest → host buffer
  has free, so a guest can't make the VMM buffer more than that. Data
  outside the window is not taken.
- **Connection setup:** the SYN-ACK goes out only once the host connect
  succeeds. A refused destination gets an RST, and the guest sees
  `ECONNREFUSED`.
- **Host side:** sockets are non-blocking, with `TCP_NODELAY`, and
  SIGPIPE is ignored. A host peer that stops reading stalls only its own
  flow.
- **Receive buffers:** they are taken in the order the guest offered
  them. A frame that spans several buffers is published to the used ring
  in one step (virtio 1.2, 5.1.6.4).
- **Reset and snapshots:** a driver reset frees every flow. A snapshot
  keeps no flows, because their host sockets belong to the old process:
  a restored guest gets an RST for each connection it had. A snapshot's
  RST list may hold only RST or RST|ACK, at most 64.

## Guest-controlled input

- All guest memory access goes through `guest_slice()` (`src/mem.h`), which
  bounds-checks with `ckd_add`. The one other place that turns a guest address
  into a host pointer is `ram_ptr()` in the WHP backend, checked the same way.
  It serves the instruction emulator and `OUTS`. `OUTS` is handled in the
  VMM: the guest's own page-table walk (`WHvTranslateGva`, at the guest's CPL)
  gives the source. A read the guest couldn't do itself gets a #PF instead.
  One exit moves at most one page.
- The ELF loader treats the kernel image as untrusted. It checks every offset and
  size, and rejects segments that overlap, wrap around, or reach outside guest
  RAM or below the boot structures (`tests/test_main.c` has the hostile cases).
- The device model is minimal: a 16550 UART, a CMOS clock, i8042 reset, and
  three write-only control ports (boot marker, exit status, console bytes).
  None of them reads guest memory. Unknown ports and MMIO read as all-ones.
  With a virtio device there is also an I/O APIC
  (`src/dev/ioapic.c`). It accepts only 32-bit accesses, and the
  read-only bits stay read-only. Each pin's entry becomes an MSI to the
  local APIC. Entries a device must not raise are dropped: vectors below
  16, SMI, INIT and ExtINT. Without devices the guest doesn't see one at
  all, and the MP table is the same as before.
- **virtio** (`src/dev/virtio_mmio.c`, `virtio.h`) is the first device code
  that reads guest memory. The guest can rewrite its rings at any moment,
  so:
  - Ring addresses become host pointers once, through `guest_slice()`,
    when the driver marks a queue ready. The size must be a power of 2 no
    larger than the device's maximum, and the alignment is checked.
  - Each descriptor is copied out once and validated as a copy:
    - the index is in range;
    - a chain has at most 20 segments and is no longer than the ring
      (so no loops); Linux's virtio-net sends up to 19 for one frame;
    - readable segments come before writable ones;
    - no indirect tables (not offered);
    - lengths are added with `ckd_add`;
    - every buffer goes through `guest_slice()`.
  - A malformed chain stops the device (DEVICE_NEEDS_RESET plus a config
    interrupt) until the driver resets it. The VMM keeps running.
    Failures are logged only a few times per device, because the guest
    can break and reset in a loop.
  - On KVM, the guest's writes to each device's interrupt-acknowledge
    register don't exit: KVM queues them in its coalesced-MMIO ring
    (registered before the sandbox starts, for those 4-byte registers
    only), and the vCPU thread applies them before it handles the next
    exit. KVM writes the ring; we take at most 8 bytes per entry and only
    the entries it says are MMIO. A late acknowledgement can't clear an
    interrupt raised after the status read it answers.
  - On KVM, vsock's queue-notify register is a `KVM_IOEVENTFD` (also
    registered before the sandbox) on its I/O thread's eventfd. A kick
    then only wakes that thread, which checks the queues itself, the
    same as for a spurious wake. The value written is ignored.
- **virtio-vsock** (`src/dev/vsock.c`):
  - Each packet header is copied out once.
  - CIDs must say guest → host.
  - The length must fit the chain and 64 KiB.
  - Data past the credit we advertised (256 KiB per connection) resets
    that connection.
  - At most 128 connections. At most 16 resets are queued; more are
    dropped.
  - The guest can open connections to the host only to ports the host
    is waiting on. The host opens connections ahead of time with
    `LISTEN <port>` (below 2^30), and each guest connect takes the oldest
    one waiting. The VMM never connects anywhere itself: the sandbox has
    no `socket` or `connect`, so a compromised VMM can't reach other
    sockets on the host either. With nothing waiting, the guest gets RST.
  - A driver reset (which the guest does at probe) ends the connections
    the guest knew about. Host connections it never saw, those still in
    their handshake, waiting in `LISTEN`, or with the request not sent
    yet, carry over.
  - Host side: the handshake must be exactly `CONNECT <32-bit port>\n`
    in under 40 bytes, or the connection is closed. A host peer that hangs
    up or stops reading only affects its own connection: sockets are
    non-blocking and SIGPIPE is ignored. A socket the device has nothing
    to wait for stays out of `poll()`, so a hung-up peer can't make the
    I/O thread spin while the guest withholds credit.
  - Anyone who can connect to the socket path can talk to the guest. The
    socket gets the VMM's umask, and connecting needs write permission.
    Under `microvm-jail` it lives in a per-VM `:rw` bind owned by the VM's
    uid, and the jail's umask 077 leaves it to that uid and root (see
    [Networking and invocations under the jail](#networking-and-invocations-under-the-jail)).
  MSRs the hypervisor doesn't implement read as 0 and ignore writes, except
  the AMD performance counters, which fault with #GP: there is no PMU to
  give the guest.
- **virtio-balloon** (`src/dev/balloon.c`, `--balloon`) offers only free
  page reporting; the balloon never inflates, and its config space reads
  as 0 and ignores writes. Buffers on the inflate and deflate queues are
  handed back untouched. A buffer on the reporting queue is a range of
  guest RAM that the VMM discards (`MADV_DONTNEED`): `virtq_pop` has
  already checked it lies inside guest RAM, and only the whole pages
  inside it are discarded. A partial page at either end is left alone, so
  nothing outside guest RAM or outside the range is touched. The worst a
  guest can do is discard its own memory, which then reads as zero, or as
  the snapshot's contents in a restored VM, the same as any other write
  to its own RAM. `fuzz_balloon` checks this against canary pages on both
  sides of guest RAM. Discarding happens on the vCPU thread, during the
  guest's own queue kick.
- **virtio-net** (`src/dev/net.c`): see
  [Guest networking](#guest-networking---net) for what it accepts from
  the guest.
- The guest's CPU view on KVM is a fixed template, not everything KVM
  supports. There is no virtual PMU: CPUID hides it, and
  `KVM_CAP_PMU_CAPABILITY` turns it off in KVM itself, since counters
  shared with the host's cores are a cross-tenant side channel. Of KVM's
  paravirt features only PV EOI is offered. In particular there are no
  async page faults, which would tell the guest when the host is paging
  its memory, no kvm-clock or steal time (the guest runs on the TSC), and
  nothing for SMP. The host's speculation controls do reach the guest
  (SSBD, IBPB, AutoIBRS...), so the guest kernel's own mitigations are
  real; under WHP they aren't exposed and the guest reports itself
  vulnerable.
- The root filesystem (`--rootfs`) adds no device emulation and no new
  guest-to-VMM input. The image file is mapped read-only into the process
  and into the guest (KVM `KVM_MEM_READONLY`, WHP read-only GPA mapping),
  and listed in e820 as legacy persistent memory. A guest write to it
  faults in the hypervisor and never reaches the file. The VMM never
  parses the image. `ram_ptr()` skips read-only regions for writes, so the
  emulator can't write it either. The image must be a whole number of
  pages and at most 64 GiB, and it lies above guest RAM (checked when e820
  is built). The command words go on the kernel command line quoted; a
  word containing `"` or a control character is refused.
- `--env` and `--env-file` strings (often secrets) stay off the kernel
  command line, so `/proc/cmdline`, the boot log and the console never show
  them. `/init` reads them over port 0x707 (`rep insb`, one exit a page)
  while it still has the port; the command's process drops the ports
  before it runs and gets the strings only as its environment, readable
  through `/proc/PID/environ` by its own user and root, as in Docker. The
  VMM only serves bytes on that port: nothing the guest writes there is
  parsed beyond selecting the record. The VMM bounds them (4096 strings,
  1 MiB) and reads the files before the sandbox starts.
- Build hardening: stack protector, CET (`-fcf-protection`), zero-initialised
  automatic variables, FORTIFY_SOURCE=3, static-pie, full RELRO. Windows builds
  use ASLR, DEP and high-entropy VA.

## Container images (`microvm-mkrootfs`, `src/image/`)

Image layers (tar files, eventually from registries) are untrusted. They are
never extracted on the host. The reader parses each layer into an in-memory
tree, and the writer emits one EROFS image from that tree. The only host
files involved are the layers the caller opened and the output image, so the
classic tar-extraction escapes have nothing to act on:
- a `..` component anywhere in a path, a pax path or a hard-link target is
  rejected; absolute paths are taken relative to the image root;
- paths are resolved in the tree and never through a symlink or a file: a
  layer that names `link/x` or `file/x` is rejected; symlink targets are
  stored as data and never followed;
- hard links must name a non-directory already in the tree;
- every header is checksummed, every number bounds-checked (octal or
  base-256, no negatives), and every offset and size checked with `ckd_*`
  against the layer's size; pax records are length-checked, and NUL bytes
  in pax paths are rejected;
- names are at most 255 bytes, paths 4096, and an image holds at most
  2^24 inodes;
- OCI whiteouts only hide entries from lower layers.

Images in layers (`--lower`; [IMAGES.md](IMAGES.md#images-in-layers)) also
read EROFS images, our own, back into the tree. They come back from
storage checked by hash, but the reader doesn't rely on that, and it runs
in the same sandbox:
- only the format the writer makes is accepted (4 KiB blocks, extended
  flat inodes without xattrs, no feature flags); anything else is refused;
- every inode, directory block, name, file and symlink target is checked
  against the image's size and block count before it is read;
- names must be 1-255 bytes without `/`, and a directory may not hold one
  twice; `.` and `..` entries are skipped, never followed;
- a directory reached twice (a loop or a hard link to one) is refused, and
  nesting stops at 2048 levels, so the walk always ends;
- a 0/0 character device is a whiteout: it only removes what a lower layer
  put there, as overlayfs does in the guest.

Whole container images (`--oci`, `--docker-archive`; see
[IMAGES.md](IMAGES.md)) add a layer of JSON and compression in front of
that. All of it is treated as hostile:
- **Verify before use.** Each manifest, config and layer is checked
  against its descriptor before it is read: the size first, then the
  sha256. Each layer's uncompressed bytes must also match the config's
  `diff_id`, and that is checked before the tar parser sees the layer.
  For a compressed layer, a pass through its decoder only to hash it comes
  first. A docker-archive's config must be named by its own digest.
  Digests are `sha256:` plus 64 lowercase hex digits, nothing else.
- **Our own gzip and DEFLATE decoder** (`src/image/inflate.c`), as strict
  as zlib:
  - no over-subscribed codes, and incomplete codes only where zlib allows
    them;
  - stored-block `NLEN` checked, and distances never past the output
    start;
  - CRC-32, `ISIZE` and `FHCRC` checked, and the header's extra, name and
    comment fields capped;
  - no bytes after the stream.
- **Our own Zstandard decoder** (`src/image/zstd.c`), as strict as
  libzstd:
  - reserved header bits and block types refused, and so are dictionaries
    and windows over 128 MiB;
  - Huffman weights, FSE normalized counts, symbols and accuracy logs
    checked, and every Huffman stream and sequence bitstream consumed
    exactly;
  - literal and match lengths kept inside their block, and offsets
    (repeat offsets too) inside both the window and the output so far;
  - the content size and the XXH64 checksum checked, and nothing but
    frames and skippable frames allowed after the last frame.
- **Bomb limits,** enforced while decompressing, not after, for both
  decoders:
  - a cap on all layers' decompressed bytes (`--max-size`, 16 GiB);
  - a ratio cap (`--max-ratio`: output ≤ 200 × input + 64 MiB). For zstd
    it also catches RLE blocks, which make 128 KiB from 4 bytes;
  - a cap on work that produces almost nothing: runs of tiny dynamic
    blocks (gzip), and table builds beyond 4096 plus one per KiB of
    output (zstd);
  - for zstd, a window buffer that grows only with the output, so a header
    claiming a 128 MiB window costs nothing until the frame produces that
    much.
- **Our own JSON parser** (`src/image/json.c`):
  - size-capped (4 MiB for an index or manifest, 16 MiB for a config,
    1M values), with nesting at most 64 deep;
  - UTF-8 and escapes validated, and a duplicate key is an error, not
    "last one wins";
  - config strings with a NUL are refused.
- **Media types must match the bytes:** gzip, zstd or plain tar, each
  checked against its magic number.
- **Bounded structure:** at most 512 layers and 4 nested indexes, and at
  most 64 restarts of one layer's decompression (the writer reads it once
  more, front to back).
- **User names** are resolved against the image's own `/etc/passwd` and
  `/etc/group`, each capped at 1 MiB and read from the tree, never from the
  host. The resulting uid and gid only matter inside the guest (IMAGES.md).

**The parsing runs in a sandboxed helper.** On Linux, `microvm-mkrootfs`
first opens every input itself:
- each layout blob is opened from a directory listing, with
  `O_NOFOLLOW`, and must be a regular file;
- the outputs are created as `OUT.part` (and `CONFIG.part`).

Then it forks. The child enters the VMM's own sandbox (`sandbox_enter`:
the seccomp allowlist, Landlock with no file access, rlimits with 4 GiB of
address-space headroom, `no_new_privs`), and only then reads any image
byte. It can read the fds it was given and write its outputs, and nothing
else: no open, no socket, no exec. The parent renames `.part` to the real
name only if the child exits 0; otherwise it deletes it, so a failed or
killed conversion leaves no half-written image. The parent parses
nothing. `--no-sandbox` (debugging) and Windows, which is dev-only, parse
in-process.

## Snapshots (`--snapshot`, `--restore`)

A snapshot holds the whole guest: its memory, vCPU and device state.
- **Reading it** gives everything in the guest's memory. The VMM creates
  it mode 0600.
- **Writing it** gives control of every guest restored from it, which is
  what a hostile guest has anyway.

The restoring VMM treats the file like guest input:
- **The header** is checked before anything is mapped. RAM must lie inside
  the file, offsets are aligned, sizes are bounded, and the additions are
  done with `ckd_add`.
- **The vCPU state** is a list of records. Each type must appear exactly
  once, with exactly the size of this kernel's struct. KVM then checks
  the values as it checks any state it is given.
- **The device state** is loaded the way the driver's register writes
  would set it:
  - queue layouts go through the QUEUE_READY checks (size, alignment,
    `guest_slice()`);
  - driver features must be a subset of the ones offered;
  - I/O APIC entries keep only writable bits;
  - a device that fails any check is left reset, and the restore stops.
- **The machine** must match: the same CPU model (a hash of the CPUID the
  vCPU gets), TSC rate, devices, root image size and RAM size. Otherwise
  the VMM refuses.

**Diffs** (`--snapshot-diff`, restored with `--base`) hold only the pages
that differ from a full snapshot, their base:
- **The base** must be a full snapshot whose random id (every snapshot
  gets one from `getrandom()`) is the one the diff names, with the same
  RAM size. Otherwise the VMM refuses, so a diff can't be laid over the
  wrong memory.
- **The runs** (which pages the diff has) are checked before anything is
  mapped: at most 16384, in order, apart, nonempty, inside RAM and inside
  the file. Each is mapped copy-on-write over the base's view, so a diff
  can only change the memory of the VM restored from it, which writing a
  full snapshot can too.
- **Saving one** reads `/proc/self/pagemap` (the VMM's own; opened before
  the sandbox is entered, PFNs read as 0 without privileges) to find
  the pages that are no longer the file's. Without it, the VMM saves a
  full snapshot.
- **A diff is version 2**, so a VMM that predates diffs refuses it rather
  than reading it as a full snapshot.
- **The header is written last.** A file with a header is whole; one from
  a save that failed has none and is refused.

`fuzz_snapshot` fuzzes the header (full and diff), a diff's runs and the
device state, then drains the restored queues while the guest rewrites
its rings.

What restored guests share, and what they don't:
- **Memory pages.** RAM is the file itself, mapped copy-on-write. Pages a
  guest only reads stay shared through the host page cache with every
  other VM restored from the same file. That is the same exposure as the
  shared kernel image and root filesystem: page-sharing timing side
  channels between those VMs. Share a snapshot only among VMs of one
  trust domain (one customer's function, say), as with an image.
- **Randomness.** Every restore reseeds the guest kernel's RNG.
  - After the snapshot point, `/init` reads 32 bytes the VMM took from
    `getrandom()` (port 0x707), credits them (`RNDADDENTROPY`) and calls
    `RNDVMFORK` (patch 0039): a reseed, and every `MADV_WIPEONFORK`
    mapping emptied, so userspace generators that detect forks that way
    reseed too. If that fails, the VM ends instead of running.
  - Processes started after that get fresh randomness: `mvm_vsock_tests`
    checks that two restores' `AT_RANDOM` differ.
  - Anything the guest made from randomness *before* the snapshot point
    is the same in every restore: keys, ASLR of processes already
    running, a userspace RNG's state. So take snapshots before any of
    those exist. `/init`'s snapshot point is before COMMAND starts.
- **The clock.** It is set from the host's on restore, through the same
  port. The guest's TSC continues from the saved value, so its timers and
  monotonic clock see no jump.
- **Connections.** vsock connections the guest had open get an RST after
  a restore. Their host sockets belonged to the old VMM.
- A function runtime that takes the snapshot after its warm-up shares
  more: see "Function invocations" below.

## Function invocations (`src/agent/`, `guest/init/agent.c`)

`/init agent run COMMAND` runs COMMAND as a function runtime and relays
invocations to it from the host over vsock. The wire format is in
`src/agent/proto.h`: length-prefixed frames with a magic number, a version
and a type, one invocation at a time.

**The host's parser reads hostile guest output** (`src/agent/parse.c`):
- Every header field is checked: magic, version 1, flags 0, a known type
  in the guest → host direction.
- Sizes are checked before anything is allocated. A data frame (stdout,
  stderr, result) is 1 byte to 64 KiB. HELLO and DONE are exactly 16 bytes.
- Each invocation is held to the caps the host put in its INVOKE: at most
  6 MiB of result and 1 MiB each of stdout and stderr, or less. A buffer
  never grows past its cap.
- Frame order is enforced: HELLO comes first and only once. Data and DONE
  carry the current invocation's id, and nothing may come between DONE
  and the next INVOKE.
- DONE's kind and flags must be known values. A kind that means the
  runtime is gone (exited, killed, timed out, faulted) must also carry
  `VM_ENDS`.
- The first violation is final. The client marks the VM dead, and the host
  should kill it. The client waits at most the deadline plus a grace
  period, reading and writing at the same time, so a guest that stops
  reading or never answers can't block it.

**In the guest**, the agent is not a security boundary: the guest is
hostile anyway. It keeps the protocol honest for well-behaved runtimes:
- It truncates output to the caps and flags the truncation.
- It kills the runtime at the deadline.
- When the runtime dies, breaks the runtime protocol, or the host hangs
  up mid-invocation, it reports that (DONE with `VM_ENDS`) and stops the
  VM. A runtime in an unknown state is never reused.
- The runtime runs without the control ports (ioperm dropped before exec),
  so only `/init` can ask for a snapshot.

**The snapshot point.** The runtime asks for the snapshot with READY, after
its warm-up. Before saving, the agent stops every other process (`SIGSTOP`
to all; pid 1 is never signalled). A stopped process acts on that before
it next returns to user mode. In this VM and in every restore, the agent
reads the resume record (clock, 32 random bytes), credits and reseeds the
kernel RNG, and only then sends `SIGCONT`. So no user code runs between
the snapshot point and the reseed, threads and child processes included.
One side effect: Linux makes a few blocking calls (`epoll_wait`,
`nanosleep`, ...) return `EINTR` after a stop and continue, even with no
handler. Runtimes must retry them, as they already must for any signal.

What restored VMs still share, on top of the "Snapshots" list above:
- **Everything the runtime made during warm-up**: its heap, any keys,
  tokens or session state it created, and a userspace RNG's state (seed
  them after READY returns, or draw from `getrandom()` each time). The
  same holds for the ASLR layout of the runtime and the agent.
  `mvm_agent_tests` checks that `getrandom()` after the restore differs
  between restores and between invocations.
- **Kernel state of open files and sockets.** Listening vsock sockets
  carry over: the agent's own listener is in the snapshot. Connections get
  an RST.

Warm reuse means one VM serves many invocations of one function. State left
behind by one invocation (files, memory, child processes) is visible to the
next one in the same VM, as on Lambda. A host that needs isolation between
invocations restores a fresh VM for each one: that costs 2 ms (BENCH.md).

### Language runtimes and snapshots (`runtimes/`)

The adapters in `runtimes/` run a Python, Bun or Node function under the
agent, on the language's public image (`microvm-mkrootfs --oci DIR
--add-layer` puts the adapter and the function on top). A snapshot after
their warm-up copies the language runtime's process into every restored
VM, and with it every random number generator that lives in user space.
`tools/fn-images.sh` measures what that means. It uses each source once
during warm-up, restores two VMs from one snapshot, and compares what they
draw, on the official images pinned by digest (python 3.15.2, bun 1.4.4,
node 26.13.0):

| source | left alone, restored VMs draw | what makes them fresh |
|---|---|---|
| Python `os.urandom`, `secrets`, `uuid.uuid4` (the kernel's `getrandom()`) | different values | /init reseeds the kernel from the host |
| Python `random` | the same | the adapter reseeds it |
| Python `ssl.RAND_bytes` (OpenSSL's DRBG, in the process) | the same | the adapter: `RAND_add` with 48 bytes of `os.urandom`, whenever libcrypto is loaded |
| Python `hash()` of str and bytes | the same | nothing: the seed is fixed when the interpreter starts |
| Bun `crypto.randomBytes`, `randomUUID`, `getRandomValues`, `randomInt`, generated keys (BoringSSL) | the same | the kernel empties BoringSSL's `MADV_WIPEONFORK` page (patch 0039) |
| Node `crypto.randomBytes`, `randomUUID`, `getRandomValues`, `randomInt`, generated keys (OpenSSL) | the same | the adapter: OpenSSL's `RAND_add` through `reseed.node`, then Node's UUID and `randomInt` caches used up |
| `Math.random` (Bun and Node) | the same | the adapter's own generator, reseeded |

The repeated values are not a weak seed but the same generator state:
restore A's first UUID is restore B's first UUID. Anything a function makes
from them, such as session tokens, nonces, TLS client randoms, key pairs or
ECDSA signature nonces (which leak the key when repeated), would repeat
across VMs. An OpenSSL or BoringSSL DRBG doesn't notice it was copied:
there was no fork, and the pid is the same. The last column is what each
runtime gets now; `fn-images.sh` checks every row for all three runtimes,
and fails if any value but the hash repeats. Switching each fix off
separately (the wipe for Bun, the `RAND_add` for Node) brings back every
repeat in its row, x25519 keys included: each fix is what covers its row.

The pieces, in the order a restored VM runs them:
1. **Before anything runs.** `/init` stops every process (`SIGSTOP`)
   before the snapshot point, so nothing runs between restore and reseed.
   After the restore it gives the kernel 32 bytes of host randomness
   (`RNDADDENTROPY`, from the VMM's resume record) and calls `RNDVMFORK`
   (kernel patch 0039). That reseeds the CRNG, then zaps every
   `VM_WIPEONFORK` mapping of every process, so the next access to one gets
   a zero page, as a child does after `fork()`. Generators that detect forks
   that way reseed on their next use: BoringSSL and AWS-LC, Zig's
   `std.crypto.random`, and the vDSO `getrandom()` state. The processes are
   still stopped, so none is mid-way through one of those pages. If either
   call fails, `/init` ends the VM (status 125) instead of running with the
   snapshot's random state. Only then are the processes let go.
2. **Before the first invocation, the adapter** (`count == 0`, before the
   handler) reads fresh bytes from the reseeded kernel and:
   - Python: reseeds `random` and OpenSSL, as above;
   - Node: hands 48 of them to OpenSSL's `RAND_add`. That reseeds the
     primary DRBG from the kernel, and the per-thread DRBGs (`randomBytes`,
     key generation, TLS) reseed from it before their next output. Node
     has no JavaScript call that reaches `RAND_add`, so the adapter loads
     `reseed.node` (`runtimes/js/reseed.c`): 60 lines of C, a Node-API
     module that calls OpenSSL's `RAND_add` from Node's own executable,
     with no libc and no headers. Then it calls `randomUUID` 128 times and
     `randomInt` 1024 times, which uses up Node's caches of random bytes
     (128 UUIDs, 6 KiB): they refill from the reseeded DRBG. Without
     `reseed.node` Node takes no snapshot;
   - Bun and Node: reseed `Math.random`. Neither engine can reseed its
     own, so during warm-up the adapter replaces it with xoshiro128**, which
     it can reseed. Like the engines' own, it is not for secrets;
   - then the function's `after_restore()` / `afterRestore()`, for
     generators of its own (`numpy.random`, a `random.Random` instance, a
     library with its own copy of OpenSSL such as `cryptography`'s wheels).
     If it raises or throws, the runtime exits.

So:
- **Python snapshots by default.** Before a VM's first invocation, the
  adapter reseeds `random` and OpenSSL's DRBG, then calls the function's
  `after_restore()`, where it reseeds generators of its own. That covers
  `numpy.random`, `random.Random` instances, and a library with its own
  copy of OpenSSL, such as `cryptography`'s wheels. If the hook raises, the
  runtime exits. The hash seed stays shared: that only weakens
  hash-flooding resistance, and only among one function's VMs.
- **Bun and Node snapshot by default too**, with `--no-snapshot` to turn
  it off, as for Python. A restored VM's first response takes 10 and 19
  ms, against 56 and 95 ms from a cold boot (BENCH.md); the reseeding is
  about 0.5 ms of that.
- What stays shared: Python's hash seed; V8's and JavaScriptCore's own
  hash seeds; Node's internal uses of the original `Math.random`, which
  its modules captured at startup; and the generators of native code that
  neither detects forks with `MADV_WIPEONFORK` nor gets reseeded by the
  function's hook. A function that keeps secrets of its own, such as a key
  made in `init()`, shares them with every VM restored from its snapshot
  by design: make them in `afterRestore()` instead.
- `RNDVMFORK` needs `CAP_SYS_ADMIN` in the guest, as `RNDRESEEDCRNG` does,
  and only changes the guest's own memory. The ioctl number (`'R', 0x40`)
  sits well above the upstream ones.

`--add-layer` layers are untrusted input like the image's own: the same tar
reader and path rules, in the same sandbox. They go in before the config
file is written, so the real `/.microvm/image-config` replaces any copy a
layer brings (`mvm_oci_tests` checks with a forged one). The config records
each added layer's sha256 (`added-layer`).

## Agent sandboxes (`microvm-sbxd`, `src/sbxd/`)

The daemon behind the E2B-compatible API (see SANDBOX.md). It holds the
API key and every sandbox's access token, and it starts VMMs, so it is
built to stay small and to run without root.

**Who sends what:**

- **API clients** send HTTP. The control plane needs `X-API-KEY`, which
  is compared in constant time. envd calls also need the sandbox's
  `X-Access-Token`: 128 random bits from `getrandom`, given out only at
  create and connect, and compared in constant time.
  - Port tunnels (`PORT-ID.DOMAIN`) carry no token, as in E2B.
  - A sandbox's ID is 20 random characters of `[a-z0-9]` (about 103
    bits), so a tunnel is reached only by someone who was told the ID.
  - Without `--api-key-file` any key is accepted, and the daemon says so
    in its log; a deployment always gives one.
- **The guest** is hostile. The daemon reads only what the guest sends
  back, through the strict frame reader of `src/sbx/wire.c` (fuzzed as
  `fuzz_sbx`). Port-tunnel bytes go to the client untouched and are never
  parsed.

**The HTTP code** (`src/sbxd/http.c`, fuzzed as `fuzz_http`) is strict:

- HTTP/1.1 and origin-form targets only.
- Refused: NUL and bare CR or LF anywhere in the head, obsolete line
  folding, duplicate `Content-Length`, `Content-Length` together with
  chunked, and any transfer coding but `chunked`. These are the
  request-smuggling cases when a proxy sits in front.

**Limits:**

| What | Limit |
|---|---|
| Request head | 32 KiB and 64 headers; it must arrive within 15 s |
| JSON body | 1 MiB |
| A gzip upload, compressed | 64 MiB, inflated as it streams |
| A watcher's buffered events | 65536 events or 4 MiB |
| Idle keep-alive connection | closed after 300 s |
| Connections | 1024 |
| Sandboxes | `--max-sandboxes` (64); past it, 429 |
| A sandbox's lifetime | 24 h at most |

**Backpressure.** Output toward a client is held up to 1 MiB (`G_HIGH`).
Past that, the guest connection feeding it is no longer read until the
client drains to 256 KiB, so a slow client stalls only its own stream.

**The VMMs:**

- Each sandbox is its own VMM process: its own seccomp, Landlock and
  rlimits, as everywhere.
- It starts from `posix_spawn` with an empty environment. Its stdin is
  `/dev/null` and its output goes to its console log. Every fd of the
  daemon is close-on-exec, so nothing else is inherited.
- With `--jail`, each VMM is in its own jail with only its image, kernel,
  snapshot and directory (`DIR/sbx/<id>/`, mode 0700 under umask 077).
  It runs as 65534 when the daemon is root, and in a user namespace when
  it isn't.
- A sandbox's files (sockets, snapshots, console log) are removed with
  it, and the whole directory is cleaned at start-up and shutdown.
- The daemon kills every VMM when it stops.

**Pause.** A paused sandbox's snapshot holds its memory, so it holds
whatever secrets the guest had. It is written to the sandbox's own
directory, readable only by the daemon's user, and deleted on kill.
Every restore reseeds the guest's RNG before anything else runs (see
Snapshots).

- The snapshot is a diff of the template's (Snapshots, diffs). A resume
  binds the template's snapshot into the jail read-only, as a create
  does.
- The daemon counts a pause done when the VMM has closed a snapshot with
  a header (inotify), before the process has exited. After a save the
  VMM only exits, and its directory's socket is unlinked first, so a
  resumed VMM never shares it. The old process is reaped when it goes,
  and a failed exit is logged.

## Guest kernel

Guest mitigations (`CONFIG_CPU_MITIGATIONS`) stay **on** by default. They protect
the guest kernel from its own processes and have no effect on the host.

Our kernel patches don't change what is mitigated. Each one does one of these:
- keep the TSC clocksource on WHP (0001);
- make boot-time patching cheaper without changing its result (0002, 0008,
  0010, 0013, 0014, 0021, 0026);
- stop the kernel touching memory, CPUID leaves or chipset registers it
  doesn't need (0003–0007, 0015, 0016, 0024), or hardware the VMM says isn't
  there (`reduced_hw`, 0025: no PIT or PIC, as on hardware-reduced ACPI);
- skip building uevents that no one can receive (0009) and, with
  `--quiet`, logging the messages the console hides (0028; errors and
  warnings are still logged);
- parse the command line, set up the direct map and struct pages, and
  change page attributes, with the same results but less work (0020, 0022,
  0027, 0029–0031);
- take boot-time input and output through the VMM's control ports and
  command line instead of emulated devices: the console (0011) and the boot
  wall clock (0012). The guest already trusts the VMM for both;
- make an e820 persistent-memory root filesystem work without PCI (0033,
  0035) and before `/init` runs (0034), and leave out iomap write-path
  reserves the guest never draws on (0036: smaller mempools, a zero page
  allocated on first use);
- send vsock credit updates only when the peer needs them (0037). Credit
  only limits how much the host may send; the VMM enforces the credit it
  advertised itself;
- after a snapshot restore, empty every process's `MADV_WIPEONFORK`
  mappings along with the CRNG reseed (0039, `RNDVMFORK`), so userspace
  generators reseed as after a fork ("Language runtimes and snapshots").
  Root in the guest only; it changes nothing but the guest's own memory.

The guest kernel refuses writes to mounted block devices
(`BLK_DEV_WRITE_MOUNTED` off). The root image is read-only in hardware
anyway.

Notes on specific changes:
- 0003 drops the 0xcc poison on freed init and alignment-gap pages unless
  `init_on_free` is set. Those pages are already non-executable when freed.
- 0017 (`keep_image_gaps`) leaves the kernel image's alignment padding
  reserved instead of freeing it. The padding stays read-only and
  non-executable; nothing becomes writable or executable that wasn't.
- 0018 skips ENDBR sealing only on CPUs without IBT, where the sealed and
  unsealed instructions are both NOPs. With IBT, sealing runs as before.
- 0019 lets the return-thunk rewrite happen at build time
  (`guest/kernel/prepatch.py`) instead of at boot. The kernel skips its own
  rewrite only if the image was pre-patched for exactly the thunk it chose;
  otherwise it patches every site as usual. So the mitigation in effect is
  the kernel's choice either way. The tool refuses to mark an image if any
  return site isn't the compiled `jmp __x86_return_thunk`.
- 0023 frees init memory with one page-attribute pass that sets RW and NX
  together, instead of NX first and then RW. No page is ever writable and
  executable at once, and the final mappings are identical (compared by
  walking the guest page tables in a `--dump-mem` image).
- 0026 moves the rest of the boot-time text patching to build time. The
  kernel skips its own patching only if this boot's inputs (the CPUID
  leaves the CPU features come from, every CPU feature and bug bit, the
  chosen return thunk, `pv_ops`) match byte for byte the ones recorded in
  the image. Otherwise it restores the compiled bytes from the image's undo
  table, but only where a run still holds the pre-patched bytes, and then
  patches as usual, so mitigations are always the kernel's own choice for
  this boot. Images that can't be pre-patched this way are never marked:
  those with call-depth tracking, FineIBT, or ITS thunks (which live in
  allocated memory). `prepatch.py` refuses if a byte changed outside a known
  patch site, if a site was rewritten before the patch point too, or if
  `pv_ops` changed during boot.

  The pre-patched text runs from the boot's first instruction, not from the
  patch point, so the CPU can't be checked at the patch point. The first
  thing `x86_64_start_kernel()` does is read those CPUID leaves (14 CPUID
  instructions: the ones `get_cpu_cap()` reads, plus the hypervisor
  signature). If they differ from the recorded ones, it restores the
  compiled text there and then, with plain stores and no pre-patched
  helper, before any pre-patched site has run. From then on, the boot is a
  fresh image's. Before this check, an image pre-patched on another CPU
  restored its text only at the patch point, and the code before it ran
  with the other CPU's choices. A KVM-pre-patched image under WHP, which
  hides PKU, set CR4.PKE in `identify_cpu()` and died with a #GP (only
  the guest). The check is tested by `tests/prepatch.cmake`, which hides
  CPUID bits with `microvm --cpuid-hide`. Compared at the patch point with
  a fresh kernel booted the same way, the image's text differs in 0 bytes.

  One difference remains on the CPU the image was patched for (the same
  CPUID), whether or not the other inputs match (another command line,
  other microcode): code that runs before the patch point already sees the
  recorded choices, where an unpatched kernel tests the feature bits as
  they stand at that moment. For features detected from CPUID the answer
  is the same. For mitigation features it is "on" a little earlier, and on
  until the patch point if this boot turns them off. The same CPUID means
  the same instructions, so nothing that runs early can fault for want of
  one. In bytes, the difference is 10 static-call tail calls (PMU
  callbacks with no PMU behind them). `static_call_init()`, which runs
  before the patch point, writes them as `jmp __x86_return_thunk` once it
  sees the return-thunk feature, and as `ret` without it.
  `__x86_return_thunk` is itself a `ret`, so the code does the same. The
  NMI, #DB and #MC entry code uses FSGSBASE instructions even before CR4
  enables them, so one of those exceptions that early would crash the
  guest (only the guest); a microVM gets none that early.
- 0021: the same tool sorts the static-call site table, which the kernel
  otherwise sorts at boot. It only reorders entries. The kernel checks the
  order and sorts the table itself if it isn't sorted.
- `MITIGATION_CALL_DEPTH_TRACKING` is off. Skylake-era Intel CPUs, the only
  ones that use it, fall back to IBRS for Retbleed.
- The VMM hides RDSEED from the guest, so the guest seeds its random number
  generator from RDRAND, which is still a hardware generator.

### The container inside the guest (`guest/init/image.c`)

Container images expect the usual Linux userspace interface: futex, epoll,
timerfd, signalfd and eventfd, setuid, `/proc`, tmpfs, overlayfs, Unix
sockets, `#!` scripts, file locks and SysV IPC, so the kernel has them
(`config.fragment`). Everything they add runs inside the guest kernel,
which the threat model already treats as hostile. None of it reaches the
VMM: the device set and the VMM's seccomp filter are unchanged. Some of
the attack surface stays out of the kernel on purpose:
- **io_uring is off.** It is a large and often-exploited kernel interface,
  and containers rarely need it.
- **AIO, POSIX message queues, cgroups and namespaces are off.** There is
  one container per VM, so there is nothing for cgroups or namespaces to
  separate.
- **sysfs is off.** BENCH.md has why.

`/init` stays pid 1, as root. The command gets a root that looks like
Docker's:
- **The root is the image under a tmpfs overlay.** Writes go to guest RAM.
  The image itself stays read-only in hardware.
- **`/dev` is a tmpfs of its own** with null, zero, full, random, urandom,
  tty, a private devpts instance (`newinstance`) and `/dev/shm`. The VM's
  own devices (pmem, vsock, the console) aren't there, so a command that
  drops root can't reach them through device nodes.
- **`/proc` is mounted without masking.** Docker masks parts of `/proc`
  (`kcore`, `sysrq-trigger`, ...) to protect the host kernel. Here `/proc`
  is the guest kernel's, and the guest kernel is the container's own.
- **The image's User is applied:** `setgroups`, then `setresgid`, then
  `setresuid`, after everything that needs root and before `chdir`. A
  non-root User can't remount, write the image's root-owned files, or
  reopen `/init`'s ports. The ports are dropped with `ioperm` before
  `exec` in any case. This is defence in depth inside the guest; the host
  boundary is the VMM sandbox and the jail either way.
- **Capabilities are not dropped for a root User,** unlike Docker's
  default set. Inside a VM, a root container is root of the guest kernel,
  which it could reach anyway through a guest kernel bug.

## Testing

`ctest` runs `mvm_sandbox_tests`. Each probe starts a fresh child process, enters
the sandbox, and tries one forbidden action. Each probe also has a control run
without the sandbox, which must succeed: that shows the probe can detect an
escape at all.

- **Linux probes:**
  - open a file
  - create a socket
  - map or `mprotect` memory executable
  - fork, clone3, execve, ptrace
  - an ioctl that isn't on the allowlist
  - with 8 vCPUs' ioctl lists: a vCPU request on another fd, and a
    request on no list (each fd and request of the lists must still work)
  - Landlock on its own
  - Positive controls: an allowlisted ioctl and buffered stdio on a pre-opened
    file must still work.
- **Windows probes:**
  - spawn a process
  - write a file in `%TEMP%`
  - allocate executable memory
  - open the parent process for writing
  - write to the HKCU registry
  - exceed the memory cap

- **Device I/O probes:** with the vsock thread's allowances,
  - `poll`, `readv`, `writev`, `shutdown` and `accept4` on its listening
    socket still work;
  - `accept4` on any other socket is killed;
  - new sockets and `open` stay killed.

- **Network probes:**
  - With `--net`, `recvmsg` works on the helper channel but is killed on
    any other socket. Without `--net`, it is killed everywhere.
  - In the helper's sandbox, its own work runs: `socket`, `connect`,
    `TCP_NODELAY`, and the channel and netlink calls. These are killed:
    - opening a file;
    - AF_UNIX, raw and blocking sockets;
    - any other socket option;
    - `bind`;
    - `sendto` on its own sockets;
    - `sendmsg` off the channel;
    - `fork`.

`mvm_net_tests --policy` checks the egress policy without a VM:

- a public address is allowed;
- every refused range above is refused, IPv4 and IPv6;
- the route check refuses the host's own address;
- `--net-allow` ranges are honored, and bad ones refused;
- resolver addresses and ports parse correctly.

On KVM it then boots the test image with `--net` against its own servers
on 127.0.0.1, reached through `--net-allow 127.0.0.1/32`. With `--jail
MICROVM-JAIL` (ctest `net_jail`) every VM starts through the jail, with
`--net` and the policy given to the jail; all of the checks below must
still pass:

- a TCP exchange, a UDP echo, and DNS through 10.0.2.3 to `--net-dns`;
- refusals: 169.254.169.254, a closed port, 192.168.1.1, and the host's
  own address with a listener on 0.0.0.0, which must see no connection;
- the host's loopback, refused without `--net-allow`;
- 1-byte round trips, 8 MiB echoed both ways at once, and half-close;
- snapshots taken with `--net`: the restored guests reach the host, and
  a restore without `--net` is refused.

`mvm_vsock_tests` boots the test image with `--vsock` and talks to
`/bin/vsock-echo` through the host socket:

- a round trip;
- refusals: a port nobody listens on, a bad handshake line, a port past
  32 bits;
- 1-byte round trips;
- half-close in both directions;
- 8 MiB echoed both ways at once, which only completes if credit flow
  control works;
- a host that hangs up mid-stream without reading;
- the guest's exit status and byte count;
- the other direction: with two `LISTEN` connections on a port, the guest's
  connection takes the first and the second keeps waiting; a connect to a
  port nobody listens on is refused; data both ways and EOF.

On KVM it also runs as `nobody` under `setpriv` and through `microvm-jail`.

`mvm_agent_proto_tests` feeds the host's agent parser hostile streams. Each
must be refused:
- a bad magic number, version or header flags;
- data before HELLO, a second HELLO, or a HELLO of the wrong size or
  version;
- data for another invocation id, an empty data frame, or one past 64 KiB;
- stdout, stderr or result past its cap;
- a DONE of the wrong size, kind or flags, or a dead runtime's DONE
  without `VM_ENDS`;
- an INVOKE or an unknown type from the guest;
- data while no invocation runs.

It also checks INVOKE encoding and its limits.

`mvm_agent_tests` (KVM, run as `nobody`) boots `/bin/fn-demo` under the agent.
With `--jail MICROVM-JAIL` (ctest `agent_jail`) every VM starts through
the jail: the kernel and image read-only, the vsock socket and the
snapshot in a `:rw` bind, reached by the host through its host path.
Both modes check:
- **Cold boot:** arguments, environment, payload, result, stdout, stderr
  and status all come through, including a 1 MiB payload and a 3 MB
  result. Output past the caps is truncated and flagged. A runtime exit
  ends the VM with its status.
- **Snapshot after warm-up, 5 restores:** each restore serves several
  invocations, also after a reconnect. All share the warm-up state, none
  share random numbers, and all have the host's clock.
- **Invocations that end a restored VM:** a deadline overrun (124), a
  crash (139), a malformed runtime frame (125), and a host that hangs up
  mid-invocation (125).

`mvm_jail_tests` runs itself through `microvm-jail`. It runs as root on
a KVM host and unprivileged elsewhere, and skips if neither works. Inside
the jail it checks:

- the uid, no capabilities in any set, an empty bounding set,
  `no_new_privs`;
- no fds past 2, an empty environment;
- pid 1, a `/proc` that shows only pid 1;
- no host files;
- the binds: read-only, `:rw`, and `noexec`/`nosuid`/`nodev`;
- a read-only root;
- the hostname, no network (connect gives ENETUNREACH);
- `/dev/kvm`, and the cgroup namespace;
- with `--net`: fd 3 is the helper's channel and no other fd is open;
  sockets the helper passes reach a listener on the host's loopback
  (allowed by the jail's `--net-allow`), also as 10.0.2.2; metadata,
  RFC 1918 and CGNAT are refused; the jailed process itself still has no
  network.

Outside it checks:

- a `:rw` write lands owned by the VM's uid;
- `pids.max` is set;
- the cgroup can be removed afterwards, a reused cgroup works, and one in
  use is refused;
- the exit status comes back, and SIGTERM kills the VM;
- `--make-base` / `--base`;
- with `--net`, the helper: the VM's uid, pid 1 of its own PID namespace,
  seccomp and `no_new_privs`, no capabilities, an empty bounding set. As
  root also: the host's network namespace and its own mount, PID, IPC and
  UTS namespaces, an empty root, the VM's cgroup. It is gone once the VM
  is, and the cgroup can be removed;
- 24 hostile argument sets, each refused with 125 and nothing created on
  the host (6 of them for `--net`); `--net` in the guest's command is
  left alone.

On the KVM box, as `nobody` (unprivileged, through a user namespace) and
as root (VM uid 65534): `mvm_jail_tests`, `mvm_net_tests --jail` and
`mvm_agent_tests --jail` all pass, with no seccomp kills in the kernel
log.

`mvm_image_tests` builds tar layers in memory and reads the images back
with an EROFS reader written from the on-disk format, independently of the
writer. Hostile layers covered: `..` (in paths, pax paths and link targets),
paths through symlinks and files, bad checksums, sizes past the layer, a
wrapping base-256 size, negative and malformed numbers, malformed pax
records, over-long names, hard links to missing entries, to directories and
through symlinks, and the root replaced by a file. The ctest cases
`rootfs_*` boot a real image from `guest/kernel/out/test-layer.tar`, check
the command's output, and check its exact exit status (42, 127 not found,
126 not executable).

`mvm_oci_tests` (about 400 checks) covers the container-image path:
- **SHA-256:** the FIPS 180 vectors and a million `a`s in uneven pieces,
  through both the SHA-NI and the portable code, which are also
  cross-checked.
- **Inflate:**
  - zlib-made dynamic-block vectors, plus stored and fixed blocks from a
    test encoder;
  - 1-byte reads, with every truncated prefix refused;
  - single-bit flips, multi-member gzip;
  - hand-built invalid dynamic headers;
  - bombs past the size and ratio caps.
- **JSON:** malformed documents, deep nesting, duplicate keys, bad UTF-8
  and surrogates, and the size caps.
- **Images:** OCI layouts, the same layout in a tar, docker-archives
  (including Docker's symlinked duplicate layers), multi-arch and nested
  indexes with attestations, refs, and Docker's User rules. A layer made by
  the zstd CLI on top of gzip and plain layers, in a layout and in a
  docker-archive.
- **30 hostile images,** each refused with the right message:
  - wrong layer digest or size, a missing blob;
  - a tampered manifest, a missing `oci-layout`;
  - a wrong diff_id: gzip, zstd and plain;
  - a gzip bomb, a zstd bomb (RLE blocks), a zstd layer with a bad
    checksum;
  - `..` in a path and in a whiteout, a whiteout or file through a
    symlink;
  - hard links out of the tree or to nothing, the root replaced;
  - gzip bytes labelled zstd, zstd bytes labelled tar, gzip bytes labelled
    tar, an unknown layer type;
  - an index nested too deep, duplicate keys (index and config), a sha512
    or uppercase digest;
  - a NUL in Env, a Cmd of numbers, a wrong diff_id count.
- **CLI:** `--oci` and `--docker-archive` through `microvm-mkrootfs`, its
  sandbox included, checked by reading the image back. On the KVM box both
  boot as `nobody` and run `/bin/probe` from the image with the config's
  Entrypoint and Cmd. They show the top layer's file, and a whited-out file
  is gone.

`mvm_zstd_tests` covers the zstd decoder:
- **XXH64:** known values, short and long.
- **Vectors made by the zstd CLI** (`tests/gen_zstd_vectors.py`):
  - levels from `--fast=4` to `--ultra -22`;
  - raw, RLE and compressed blocks, with 1- and 4-stream Huffman
    literals and trees reused across blocks;
  - 1 KiB and 128 KiB windows that slide;
  - frames with and without a content size and a checksum;
  - concatenated and skippable frames.

  Each is checked by length and SHA-256. Line coverage of `zstd.c` is
  about 95%; the rest are error returns for I/O and allocation failures.
- **Streaming:** 1-byte pulls and 1-byte consumes, and a restart that
  must give the same bytes.
- **Damage:**
  - every truncated prefix of five vectors is refused;
  - every single-bit flip of a checksummed vector either fails or gives
    the original output.
- **Hand-made frames:**
  - RLE-table sequences with known output, including an overlapping
    match and 0x7F00 sequences;
  - an offset past the window but inside the output, which is refused;
  - each frame-header, block, literals and sequences error;
  - the size, ratio and table-build caps.

## Fuzzing

`tests/fuzz/` has harnesses for:

- the ELF loader (`fuzz_elf`);
- the device model (`fuzz_devices`: arbitrary port I/O, MMIO and MSR
  sequences);
- the virtio transport and virtqueue parser (`fuzz_virtq`: any register
  sequence, any ring contents, rings rewritten between reads);
- restoring a snapshot (`fuzz_snapshot`: any header, whose vCPU count must
  decode to 1–8, any device state for
  the I/O APIC, UART, CMOS and a virtio device; the loaded device must
  keep every queue inside guest RAM, and one that is refused must be left
  reset);
- the balloon device (`fuzz_balloon`: any register sequence and ring
  contents, any reported ranges; canary pages on both sides of guest RAM
  must survive, and only whole pages are discarded);
- the vsock device (`fuzz_vsock`, Linux).
  - A hostile driver sends any op, ports, CIDs, credit and lying lengths,
    split across descriptors. It offers receive buffers or not, resets the
    device, and pokes its rings.
  - Meanwhile real host clients connect, write, half-close, stop reading
    and hang up.
  - `vsock_poll()` stands in for the I/O thread, so runs are
    deterministic.
  - It checks the device's own invariants: buffered bytes match the
    credit given, the connection table stays consistent, every packet
    toward the guest is well-formed, and a reset frees every connection.
- the network device and its NAT (`fuzz_net`, Linux).
  - A hostile driver sends TCP with any flags, sequence numbers, options
    and lengths. It also sends UDP, DNS (real queries, cut anywhere), ARP,
    ICMP, IPv6, fragments, lying IP and TCP lengths, and chains split
    anywhere.
  - Flows are refused at random, by the policy or by a failure. The
    NXDOMAIN answers and ICMP errors that refusals bring are checked:
    exactly one question back, and a well-formed quoted header.
  - It offers receive buffers of any size, resets the device, pokes its
    rings, and loads damaged snapshots.
  - Meanwhile the host ends of its flows (socketpairs standing in for the
    helper's sockets) write, read, half-close and hang up.
  - It checks:
    - the receive ring: buffers in offer order, never longer than
      offered, a frame's buffers all published at once;
    - every frame to the guest: MACs, lengths, checksums;
    - TCP inside the window the guest advertised, carrying the host's
      bytes at the right sequence numbers;
    - the byte stream reaching each host socket;
    - the flow table;
    - that a reset frees every flow and leaks no fd.
  - It found two bugs, both fixed. A too-small receive buffer was handed
    back out of order, so the guest got the same buffer twice. Drained
    flows kept their buffer pages.
- the image builder (`fuzz_tar`: one or two tar layers into an EROFS
  image);
- the EROFS reader (`fuzz_erofs`: one or two images stacked, as lower
  layers. What it accepts must write out, read back and write out the
  same bytes again, and a diff of the upper image over the lower one must
  write out too);
- the host's parser for the guest agent's stream (`fuzz_agent`: any
  bytes, any caps, split into reads at random). It checks that no buffer
  passes its cap, that DONE fields are in range, that an error is sticky,
  and that every split of the stream gives the same outcome;
- the inflater (`fuzz_inflate`: raw DEFLATE and gzip, handed over in
  pulls of fuzzer-chosen sizes. The output stays under the caps, the
  verdict and output don't depend on how the bytes were split, and an
  accepted stream's output, compressed again, inflates back to itself);
- the zstd decoder (`fuzz_zstd`: seeded with the CLI-made vectors and a
  hand-made sequences frame, handed over in pulls of fuzzer-chosen sizes
  and consumed in pieces. The same invariants as `fuzz_inflate`. An
  accepted stream's output, written again as a frame with a content size
  and a checksum, decodes back to itself);
- the JSON parser (`fuzz_json`: an accepted document, printed back out
  canonically, parses again to the same text; keys are unique; depth stays
  capped);
- microvm-sbxd's HTTP code (`fuzz_http`):
  - request heads: what is accepted is well-formed and ends where it
    says;
  - chunked bodies and multipart uploads: the same bytes and verdict
    however the input is split into reads;
  - base64 round trips;
  - JSON string writing: always one valid string for the strict parser,
    with valid UTF-8 unchanged.
  - It found two bugs, both fixed. NUL in a part's headers crashed the
    multipart reader. A malformed chunked body left the decoder's
    out-parameters unset.
- the host's reader for a sandbox agent's frames (`fuzz_sbx`): any byte
  stream, split into reads anywhere. Every decoder runs on every frame.
  The frames, their decoded fields and the verdict must not depend on the
  split, and a refusal is sticky. Every string handed out must lie inside
  its frame, hold no NUL and respect its cap, and a PROC's string list
  must walk exactly to its end;
- whole images (`fuzz_oci`: OCI layouts and tars of them, built from
  mutated templates whose digests are filled in after mutation, so the
  mutations get past the digest checks and reach the index, manifest,
  config, gzip, zstd and tar code). They
check invariants, not just "doesn't crash". For example, every segment the
ELF parser accepts must lie inside guest RAM, every port read must be masked
to its access size, and every accepted layer set must give a well-formed
image, the same bytes every time. A standalone mutation driver runs them, since GCC has no libFuzzer.
The same harnesses also build with libFuzzer or AFL++.

- **Smoke pass:** `ctest` runs 30k iterations of each.
- **Longer campaign** (2M iterations of each found nothing; `fuzz_tar`:
  3M under ASan + UBSan, nothing; `fuzz_vsock` 3.6M, plus 0.9M under
  ASan + UBSan, and `fuzz_virtq` 1M under ASan + UBSan, nothing; under
  ASan + UBSan, after the inflater's last change: `fuzz_inflate` 2M,
  `fuzz_json` 3M and `fuzz_oci` 500K, nothing, on top of 1M, 1M and 300K
  before it; `fuzz_agent` 4M under ASan + UBSan, nothing;
  `fuzz_net` 4.2M under ASan + UBSan and 19M without, nothing after the two bugs above,
  then 2.2M under ASan + UBSan after refused datagrams were answered, nothing;
  `fuzz_http` and `fuzz_sbx` 1.2M each under ASan + UBSan, then 20M
  (`fuzz_http`) and 80M (`fuzz_sbx`) without, nothing after `fuzz_http`'s
  two bugs;
  `fuzz_balloon` 3M under ASan + UBSan, nothing;
  `fuzz_zstd` 16M under ASan + UBSan (16 seeds × 1M, inputs up to 8 KiB),
  and `fuzz_oci` 400K more with its zstd template, nothing). The first
  zstd campaign crawled: the harness grew its output buffer with a
  `realloc` on every pull, a fresh copy each time under ASan, so a 1 MB
  output in 1-byte pulls copied about a terabyte. `fuzz_inflate` had the
  same loop. Both now grow it only when it fills, and 1M runs take 7
  minutes):

```bash
cmake -B build-asan -DMICROVM_SANITIZE=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-asan
build-asan/fuzz_elf -runs=10000000 -seed=$RANDOM
```

Runs are deterministic for a given `-seed`. To capture the input of a crashing
run, rerun with `MVM_FUZZ_SAVE=1`: it writes the current input to
`fuzz-crash.bin`.

The whole ctest suite also passes in an ASan + UBSan build. Three things
differ there, each compiled in only under `__SANITIZE_ADDRESS__`; the
release build has none of them:

- LeakSanitizer's exit-time check can't run in the sandbox (it needs
  `prctl`, a `ptrace`ing clone and `/proc/self/task`), nor in the jail's
  waiter once it is the VM's uid. Both run the check early instead, at
  `sandbox_enter()` and before the jail drops its credentials, which
  also turns the exit check off. Leaks made after that point go
  unreported; `--no-sandbox` shows them.
- The network helper's filter allows `sigaltstack(NULL, &old)`, a query
  only: the compiler puts `__asan_handle_no_return()`, which makes that
  call, before each `_exit()`. Setting a signal stack is still killed
  (probe "net helper: set a signal stack").
- An ASan VMM can't be a static PIE, so the jail adds the host's library
  directories (`/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, read-only)
  to the VM's root for its loader.
