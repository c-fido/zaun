# Results

Measured 2026-11-05 on the dev VM: Ubuntu 24.04, kernel 6.8.0 aarch64, 4 vCPUs and 4 GiB
under Lima (vz) on Apple Silicon. Zaun ran inside `systemd-run --user --scope`, so cgroup limits were live.

## Escape suite

`python3 tests/escape/run.py --results FILE`. Each attack must succeed bare and fail under zaun for
the reason in its sidecar. PRIV-6 is x86-only and runs in CI. RES-1 and RES-2 need a delegated cgroup,
so CI skips them.

**27/27 blocked, 1 skipped.**

| ID | Attack | Expected defense | Result | Detail |
|---|---|---|---|---|
| FS-1 | Read ~/.ssh/id_ed25519 | Not mounted | PASS | ENOENT |
| FS-2 | Read /etc/shadow | Not mounted | PASS | ENOENT |
| FS-3 | Append to ~/.bashrc | Not mounted | PASS | ENOENT |
| FS-4 | Symlink in workdir pointing into $HOME | Target absent; Landlock | PASS | ENOENT |
| FS-5 | Rename or hardlink a file out of the workdir | Landlock REFER; mount boundary | PASS | EXDEV |
| FS-6 | Escape via /proc/1/root | PID namespace | PASS | ENOENT |
| FS-7 | Remount / read-write | Caps dropped; seccomp | PASS | signal SIGSYS |
| FS-8 | Fill /tmp | tmpfs size limit | PASS | ENOSPC |
| LEAK-1 | Read ANTHROPIC_API_KEY from env | Environment scrubbed | PASS | unset |
| LEAK-2 | Read an inherited fd 3 | close_range | PASS | EBADF |
| NET-1 | TCP connect to 1.1.1.1:443 | Empty network namespace | PASS | ENETUNREACH |
| NET-2 | DNS lookup | No route, no resolver | PASS | EAI_AGAIN |
| NET-3 | Connect to an abstract Unix socket (D-Bus) | Network namespace scoping | PASS | ECONNREFUSED |
| NET-4 | Connect to a socket file in host /tmp | Fresh tmpfs /tmp | PASS | ENOENT |
| PRIV-1 | Run a setuid binary | NO_NEW_PRIVS; nosuid | PASS | euid unchanged |
| PRIV-2 | unshare(CLONE_NEWUSER) | Seccomp always-deny | PASS | signal SIGSYS |
| PRIV-3 | clone3 with namespace flags | clone3 returns ENOSYS | PASS | ENOSYS |
| PRIV-4 | openat through io_uring | io_uring_setup denied | PASS | signal SIGSYS |
| PRIV-5 | bpf, perf_event_open, userfaultfd | Seccomp always-deny | PASS | SIGSYS |
| PRIV-6 | 32-bit syscall via int 0x80 | Bad-arch action kills | SKIP | needs x86_64, this is aarch64 |
| PRIV-7 | Read the session keyring with keyctl | Seccomp always-deny | PASS | signal SIGSYS |
| PROC-1 | ptrace the supervisor | PID namespace; seccomp | PASS | signal SIGSYS |
| PROC-2 | kill(-1, SIGKILL) | PID namespace | PASS | ESRCH |
| PROC-3 | Read another process's /proc/<pid>/environ | PID namespace | PASS | ENOENT |
| RES-1 | Fork bomb (500 processes) | pids.max | PASS | EAGAIN |
| RES-2 | Allocate 1 GB | memory.max OOM kill | PASS | signal SIGKILL |
| RES-3 | Infinite loop (4 s) | Timeout + cgroup.kill | PASS | signal SIGKILL |
| TTY-1 | Inject keystrokes with TIOCSTI | setsid; ioctl filter | PASS | EPERM |

RES-2 allocates 1 GiB, not the design doc's 8 GiB, so the bare run fits on a 4 GiB VM.

## Overhead

`systemd-run --user --scope bench/run.sh` runs hyperfine with 200 runs each (learn: 20) and reports p50 and p95.
Docker was cut, as the plan's cut order allows.

| Benchmark | Variant | p50 (ms) | p95 (ms) | vs bare |
|---|---|---|---|---|
| `/bin/true` | bare | 0.20 | 0.26 | |
| | zaun | 2.26 | 2.96 | +2.06 ms |
| | bubblewrap | 1.59 | 2.36 | +1.39 ms |
| 1M `getppid` | bare | 123.1 | 157.5 | |
| | zaun, baseline filter | 166.9 | 240.2 | +35.5% |
| | zaun, allowlist filter | 165.0 | 208.4 | +34.0% |
| 1M open+close | bare | 683.8 | 836.6 | |
| | zaun, baseline filter | 793.1 | 955.3 | +16.0% |
| | zaun, allowlist filter | 795.2 | 932.1 | +16.3% |
| `zaun learn` vs `zaun run` (pandas script) | run | 530.3 | 621.9 | |
| | learn | 1016.2 | 1174.0 | +91.6% |

What the numbers say:

- **Startup: met.** Zaun adds about 2 ms over bare, against a 25 ms target. That is 0.7 ms more than
  bubblewrap, mostly from the cgroup and the Landlock and seccomp setup.
- **Syscall-heavy loop: missed.** The target was under 5%. Each syscall pays about 20 ns for seccomp's
  slow entry path on this kernel and VM, whatever the filter looks like. A linear filter and libseccomp's
  binary tree measured the same, and so did a baseline and an allowlist filter. Opting out of the SSB
  mitigation (`SCMP_FLTATR_CTL_SSB`) changed nothing either. Open+close also pays for Landlock's path checks.
  This is a worst case: real programs do work between syscalls.
- **pandas CSV: inconclusive here.** The 200-run blocks drifted by ±20% because the host was noisy
  (bare 681 ms, then allowlist 543 ms), so the full-run numbers are left out. A quieter 5-run smoke run
  gave bare 507, zaun baseline 512 (+1.0%), zaun allowlist 533 (+5.1%) and bubblewrap 526 (+3.7%).
  Rerun `bench/run.sh` on bare metal before quoting a figure.
- **Learn mode** roughly doubles runtime, because every syscall makes a round trip to the supervisor.
  That's fine for a one-off learning run.

## Generalization study

Cut: the agent script and the 20-task study need an LLM and were dropped from the MVP.
`integrations/py/zaun.py` (`zaun_exec`) is the hook they would use.
