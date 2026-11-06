# Threat model

Zaun runs untrusted, often LLM-generated, code as the invoking user. That code is assumed fully
hostile, possibly steered by prompt injection. The Linux kernel is trusted.

## Trust boundary

These are trusted: the zaun supervisor, and policy files once a person has reviewed them.
Everything after the target's `execve` is untrusted, including anything it spawns. A policy from
`zaun learn` is only a proposal until someone reviews it. `zaun check` flags the riskiest grants.

## Assets and defenses

| Asset | Example attacks | Defense | Tests |
|---|---|---|---|
| Secrets on disk | Read `~/.ssh`, `~/.aws`, `/etc/shadow` | Tmpfs root with only granted paths bound; Landlock rules on top | FS-1, FS-2, FS-4 |
| Persistence | Write `~/.bashrc`, link files out of the workdir | Read-only, nosuid, nodev binds; Landlock write and REFER rules | FS-3, FS-5 |
| Secrets in memory | API keys in the environment, inherited fds | Environment allowlist; `close_range` in init and in the target | LEAK-1, LEAK-2 |
| Network | TCP/DNS exfiltration; D-Bus and X11 over abstract sockets; host Unix sockets | Empty network namespace; fresh `/tmp` | NET-1–4 |
| Other processes | `ptrace`, `kill(-1)`, `/proc/<pid>/environ`, `/proc/1/root` | PID namespace; seccomp denies `ptrace` and `process_vm_*` | PROC-1–3, FS-6 |
| Host terminal | Inject keystrokes with `TIOCSTI` or `TIOCLINUX` | `setsid`; seccomp denies those ioctl requests | TTY-1 |
| Host resources | Fork bomb, memory balloon, endless loop, filling `/tmp` | cgroup `pids.max` and `memory.max`; timeout plus `cgroup.kill`; sized tmpfs | RES-1–3, FS-8 |
| Privilege boundary | Setuid binaries, nested namespaces, `io_uring`, `bpf`, `keyctl`, 32-bit syscalls | `NO_NEW_PRIVS`; every capability dropped; always-deny seccomp list; kill on a foreign architecture | FS-7, PRIV-1–7 |

Setup order is fixed: `setsid`, close fds, scrub env, drop caps, `NO_NEW_PRIVS`, Landlock, seccomp
(last), `execve`. Every restriction is in place before untrusted code runs.

## Learn mode

Learning gets a wider view so programs behave normally, but the hard walls stay up. The host root
is bound read-only. `/run`, `/sys`, `/dev`, `/proc` and `/tmp` are not the host's. Credential paths
under `$HOME` (`.ssh`, `.aws`, `.gnupg`, browser profiles, and others) are covered with empty mounts.
The always-deny list, the network namespace and the limits still apply. Landlock is off.

The tracer reads syscall arguments from the target's memory, and those can change after it reads
them (TOCTOU). So traces are observations only. Zaun never uses them to allow anything at runtime.
Mounts and Landlock enforce paths, and they check the path the kernel actually resolves. In
allowlist mode the supervisor only ever *denies* (EPERM), so a race gains the target nothing.

## Known gaps

- **Path Unix sockets in the learn view.** Connecting to a socket doesn't need write access, so a
  host socket outside `/run` and `/tmp` (say, an agent socket under `$HOME`) is reachable while
  learning. Run mode doesn't expose it unless a policy grants that path.
- **Learning can be poisoned.** Hostile code can touch extra paths so the learned policy grants
  them. Review is the defense, along with `zaun check` warnings and per-rule "seen in k/N runs" notes.
- **No cgroup delegation means weaker limits.** Without it, only memory is capped, through
  `RLIMIT_AS` per process, and pids and CPU are not. Zaun warns. Run it under
  `systemd-run --user --scope`.
- **The baseline policy exposes all of `/usr`** and a few files under `/etc`. Learned policies are
  narrower.
- **Landlock ABI below 5** doesn't restrict device ioctls. Zaun warns at startup.

## Out of scope

- Kernel exploits. Use gVisor or Firecracker when they are in scope.
- Side channels (timing, Spectre) and covert channels through resources the policy allows.
- Malicious policy files, and attacks on the LLM itself.
- Data the policy deliberately grants. Zaun protects nothing inside a granted directory.
