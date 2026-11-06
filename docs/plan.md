# Zaun build plan

Step-by-step plan derived from [*Zaun — Design Doc & Build Plan*](<Zaun — Design Doc & Build Plan.pdf>) (2026-09-22).
MVP date: **2026-11-01**. Budget: ~10–12 h/week. Each week ends with a working
binary and a pass/fail exit check; a bad week cuts scope, not the date.

## Decisions made

| Question | Decision |
|---|---|
| Policy format | TOML via toml++ |
| C++ deps | CMake FetchContent (toml++ v3.4.0, nlohmann/json v3.11.3, GoogleTest v1.15.2); libseccomp from apt |
| Dev environment | Apple Silicon Mac → Ubuntu 24.04 **aarch64** VM; CI is **x86_64** (`ubuntu-24.04`) |
| Language | C++17, Linux only (CMake refuses other platforms) |
| Workdir | Bind the real directory read-write (no overlay/diff in MVP) |
| Dev VM | Lima + vz, created by `scripts/vm-setup.sh` |
| cgroup delegation | Use `user@UID.service` only when zaun already runs inside it (`systemd-run --user --scope`); otherwise rlimit fallback with a hint |
| `/tmp` size | Memory limit if set, else 256M |
| Learn view | Host root ro, except `/proc /sys /dev /tmp /run`; secrets under `$HOME` covered (`kSecretPaths`) |
| Allowlist denials | Default action is `SECCOMP_RET_USER_NOTIF`; supervisor replies EPERM and reports (no notify without a supervisor) |
| Learned syscall mode | Always `allowlist` |
| Baseline policy | Adds `/etc/alternatives` (numpy's BLAS goes through it) |
| Cut | Agent script and generalization study (needs an LLM); Docker in benchmarks |

Consequence of the arch split: PRIV-6 (`int 0x80`) is x86-only. It runs in CI
and is skipped locally with a reason. libseccomp resolves syscall names
per arch, so never hardcode syscall numbers.

## Still open (decide by the week noted)

- **Network allowlist design** (post-MVP): HTTP CONNECT proxy over a Unix socket vs Landlock TCP rules.

## Setup invariant (read before touching the launcher)

Every restriction is in place before `execve`. Order inside the target:
`setsid` → `close_range(3, ~0U, 0)` → scrub env → drop all caps →
`PR_SET_NO_NEW_PRIVS` → Landlock → **seccomp last** → `execve`.

---

## Status (2026-11-05)

Weeks 0–4 done except Week 4 step 7 (agent script, cut). Week 5: escape results, benchmarks,
README, `docs/threat-model.md`, `docs/results.md` done; study cut; recording and write-up left to the author.
Benchmark misses: syscall-loop overhead is +16–35% (seccomp entry cost), see `docs/results.md`.

## Week 0 — Environment and spike (Sep 23–27)

1. Run `scripts/vm-setup.sh`: creates the Lima VM (Ubuntu 24.04, 4 CPU, 4 GiB,
   repo mounted rw at the same path), installs `clang cmake ninja-build pkg-config
   libseccomp-dev hyperfine`, sets the AppArmor userns sysctl. **(scaffolded)**
2. → verify: the script ends by printing `uname` (≥ 6.8) and running the unit tests
   in `build-vm/`; they pass.
3. Read `man 7 user_namespaces`, `man 2 seccomp_unotify`, kernel Landlock docs.
   Confirm the kernel-minimums table below.
4. Throwaway spike (~100 lines, not in `src/`): unshare user+mount ns, write
   uid/gid map, `pivot_root`, exec `/bin/sh`.
   → verify: shell runs, `id` shows your uid, `/` is the new root.
5. Repo, CMake skeleton, CI with AppArmor sysctl. **(scaffolded)**
6. `zaun doctor`: kernel version, Landlock ABI (`landlock_create_ruleset(NULL,0,LANDLOCK_CREATE_RULESET_VERSION)`),
   userns allowed?, AppArmor `apparmor_restrict_unprivileged_userns`, cgroup delegation.
   → verify: correct output in VM and in CI log.

**Exit:** VM up; spike runs `/bin/sh`; `zaun doctor` prints all four statuses.

| Feature | Min kernel |
|---|---|
| Landlock ABI 4 (TCP) | 6.7 |
| Landlock ABI 3 (truncate) | 6.2 |
| Landlock ABI 2 (REFER) | 5.19 |
| `cgroup.kill` | 5.14 |
| Landlock ABI 1 | 5.13 |
| `close_range` | 5.9 |
| `SECCOMP_USER_NOTIF_FLAG_CONTINUE` | 5.5 |

Verified Sep 22 on the dev VM (6.8.0 aarch64): Landlock ABI 4, `cgroup.kill` present,
`close_range` works, seccomp notify headers present.

## Week 1 — Launcher and filesystem isolation (Sep 28–Oct 4)

Files: `src/sandbox/` (launcher, init, fs), `src/cli/`, `tests/escape/`.

1. Launcher: `clone(NEWUSER|NEWNS|NEWPID|NEWNET|NEWIPC|NEWUTS)`, sync pipe;
   supervisor writes `setgroups=deny`, then uid_map/gid_map (self → self), then releases pipe.
2. Init (PID 1): `mount / rprivate`; size-limited tmpfs root; ro binds of
   `/usr /lib /lib64 /bin /etc/ld.so.cache /etc/ssl/certs` each **remounted**
   with `MS_RDONLY|MS_NOSUID|MS_NODEV`; workdir rw; fresh tmpfs `/tmp`;
   generated `/etc/passwd`; `/dev` with only null, zero, full, random, urandom;
   `pivot_root`; fresh `/proc`. No `/sys`, no `$HOME`.
3. Init forks target, reaps zombies, forwards signals, propagates exit code.
4. Target: `setsid`, `close_range`, env allowlist (`PATH LANG TERM`, `HOME=workdir`).
5. `zaun run [--workdir DIR] -- CMD...` wired in CLI.
6. Escape harness: each test runs **bare (must succeed)** then **under zaun (must fail for the expected reason)**.
   Outcome in a sidecar file next to each test.
7. First tests: FS-1–4, FS-6, PROC-1–3, LEAK-1–2.

**Exit:** `zaun run -- python3 script.py` works; `$HOME` invisible; those 10 tests pass; CI builds.

## Week 2 — Lockdown and policies (Oct 5–11)

Files: `src/sandbox/` (caps, landlock, seccomp), `src/policy/`.

1. Clear effective, permitted, inheritable, ambient and bounding cap sets; `PR_SET_NO_NEW_PRIVS`.
2. Landlock via raw syscalls (`<linux/landlock.h>`): per-dir read/write/exec/REFER
   rules; detect ABI at runtime, degrade with a warning.
3. Seccomp (libseccomp): bad-arch → kill; binary-tree optimization on.
   - Always-deny (kill): `io_uring_*`, `bpf`, `perf_event_open`, `userfaultfd`,
     `ptrace`, `process_vm_readv/writev`, `keyctl`, `add_key`, `request_key`,
     `kexec_*`, module loading, `mount` + new mount API, `pivot_root`, `unshare`,
     `setns`, `clone` with any namespace flag.
   - `clone3` → `ENOSYS` (glibc falls back to `clone`).
   - `ioctl` `TIOCSTI` / `TIOCLINUX` → `EPERM`.
4. TOML loader: strict, rejects unknown keys. Compiler: policy → mount plan,
   Landlock ruleset, seccomp filter, limits. Unit tests for both (valid, unknown key,
   bad type, missing required).
5. Escape tests FS-5, FS-7, PRIV-1–7 (PRIV-6 x86 only), TTY-1.

**Exit:** loader + compiler unit-tested; always-deny live; those tests pass.

## Week 3 — Limits, network, learn-mode tracer (Oct 12–18)

Files: `src/cgroup/`, `src/learn/`.

1. cgroup v2: create `zaun-<pid>` under the delegated `user@<uid>.service`;
   `memory.max`, `memory.swap.max=0`, `pids.max`, `cpu.max`; timeout writes `1`
   to `cgroup.kill`; read `memory.peak`.
2. No delegation → `setrlimit` (`RLIMIT_AS/CPU/NPROC`) + a warning that guarantees are weaker.
3. Network `none`: empty netns, loopback only; confirm abstract-socket isolation.
4. Learn view: host root ro; tmpfs over `~/.ssh ~/.aws ~/.gnupg ~/.config/gh`,
   browser profiles, credential files. Always-deny, netns and limits stay on.
5. Notify supervisor: target installs `SECCOMP_RET_USER_NOTIF` filter, sends
   listener fd via `SCM_RIGHTS`; supervisor reads paths with `process_vm_readv`,
   checks `NOTIF_ID_VALID`, logs, replies `CONTINUE`. **Observe only, never enforce** (TOCTOU).
6. Raw trace log format. Escape tests RES-1–3, NET-1–4, FS-8.

**Exit:** limits + timeout work; RES/NET/FS-8 pass; raw trace captured for a pandas script.
Resource tests skip in CI with a reason if the runner lacks delegation.

## Week 4 — Generalizer, tooling, agent demo (Oct 19–25)

Files: `src/learn/`, `src/report/`, `integrations/py/`.

1. Generalizer rules, each with a unit test on recorded traces:
   1. Normalize paths to sandbox view; drop `/proc/self` and fd paths.
   2. Classify read / write-create / exec.
   3. Collapse under `/usr /lib /etc/ssl` when ≥ 3 files share a dir.
   4. Never collapse into `/`, `$HOME`, `/etc`, `/proc/sys` → single-file rules + warning.
   5. Temp files → `/tmp` tmpfs; workdir files → workdir rule.
   6. Syscalls = observed ∪ base set − always-deny.
   7. Multi-run merge by union with support counts ("seen in 3/3 runs").
2. `zaun learn --out p.toml [--runs N] -- CMD...`.
3. `zaun check p.toml`: warn on `/`, `$HOME`, `/etc`.
4. `--report r.json`: exit reason, duration, `memory.peak`, violations.
   Allowlist-mode denials captured by notifying only on denied calls.
5. `zaun diff a.toml b.toml` (first to cut).
6. Python `zaun_exec(code, policy, timeout)`: temp workdir → `zaun run` → parse report.
7. Agent script: 20 tasks × (1 learning sample + 5 test samples).

**Exit:** learn writes a readable policy; check + report work; `zaun_exec` runs the agent over 20 tasks.

## Week 5 — Results, write-up, buffer (Oct 26–Nov 1)

1. Full escape suite → results table (CI artifact + README).
2. Benchmarks (hyperfine, 200 runs, p50/p95) in `bench/`:
   `/bin/true` startup (< 25 ms over bare; vs bubblewrap, docker),
   1M getppid / open-close (< 5%; baseline vs allowlist),
   pandas CSV (< 5%; vs bare, bubblewrap), learn tracing cost.
3. Generalization study: success rate, failure causes, avg rules per policy (target ≥ 90%).
4. README (quick start, threat model, results, limitations), `docs/threat-model.md`, `docs/results.md`.
5. Terminal recording: learn → review → run → blocked attack. Write-up post. Resume bullet.

## Exit codes

| Code | Meaning |
|---|---|
| child's own | target exited normally |
| 125 | zaun failed before `execve` |
| 137 | killed by memory or timeout (report says which; pids.max fails forks instead, `pids_limited` in the report) |
| 159 | killed by seccomp always-deny (128 + SIGSYS) |

## CI growth

- Now: unit tests on `ubuntu-24.04`, plain debug and ASan+UBSan (matrix).
- Week 1: add escape-suite job; upload results table as artifact.
- Week 2: add clang-tidy job.

## Cut order if short on time

1. `zaun diff` 2. Syscall allowlist mode 3. Docker in benchmarks 4. Study 20 → 10 tasks.
**Never cut:** escape suite, threat model, overhead numbers.
