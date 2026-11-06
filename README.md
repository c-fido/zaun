# Zaun

Zaun is a Linux sandbox for running untrusted, LLM-generated code with only the access that code
needs. `zaun learn` traces a run and writes a least-privilege policy. `zaun run` enforces a policy
with namespaces, Landlock, seccomp-bpf and cgroups v2, as an unprivileged user.

## Quick start

Zaun needs Linux 6.2 or later with unprivileged user namespaces (Ubuntu 24.04 is the target).

```sh
sudo apt-get install clang cmake ninja-build pkg-config libseccomp-dev
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=clang++ && cmake --build build
./build/zaun doctor          # kernel, Landlock ABI, userns, AppArmor, cgroup delegation
```

On Ubuntu 23.10 and later, AppArmor blocks unprivileged user namespaces. For development, turn
that off with `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`.

```sh
# Run under the baseline policy: /usr and a few /etc files read-only, the workdir read-write, no network.
zaun run -- python3 script.py

# Learn a policy from 3 runs, review it, lint it, then enforce it.
zaun learn --out script.toml --runs 3 -- python3 script.py
$EDITOR script.toml
zaun check script.toml
zaun run --policy script.toml --timeout 60s --mem 512M --report report.json -- python3 script.py

# What changed between two policies.
zaun diff old.toml new.toml
```

Memory, pids and CPU limits need a delegated cgroup. Systemd user sessions provide one:
`systemd-run --user --scope zaun run ...`. Without one, zaun warns and caps only memory, with rlimits.

From Python:

```python
from zaun import zaun_exec   # integrations/py/zaun.py
r = zaun_exec(code, policy="script.toml", timeout=60, files={"data.csv": csv_text})
r.stdout, r.exit_reason, r.violations
```

## Policy

```toml
version = 1
name = "csv-report"

[workdir]
mode = "rw"                       # or "ro"

[filesystem]
read = ["/etc/ld.so.cache", "/usr/lib"]
write = []
exec = ["/usr/bin/python3.12"]

[network]
mode = "none"                     # the only mode

[env]
keep = ["PATH", "LANG"]           # HOME is always the workdir

[limits]
memory = "512M"
pids = 128
cpu = 1.0
timeout = "60s"

[syscalls]
mode = "allowlist"                # or "baseline": everything but the always-deny list
allow = ["read", "write", "openat", "mmap"]
```

Unknown keys are errors. The always-deny syscalls (`ptrace`, `bpf`, `io_uring_*`, `mount`,
`unshare`, `keyctl`, ...) can't be allowed.

## Exit codes

| Code | Meaning |
|---|---|
| the target's own | It exited normally |
| 125 | Zaun failed before `execve` |
| 137 | Killed by a limit: memory or timeout (`--report` says which) |
| 159 | Killed by seccomp for an always-deny syscall (128 + SIGSYS) |

## Results

Full tables are in [docs/results.md](docs/results.md).

- **Escape suite:** 27 of 27 attacks blocked, and PRIV-6 runs on x86 CI only. Every test is also run
  bare, where it must succeed.
- **Startup:** +2.1 ms over bare `/bin/true` (bubblewrap: +1.4 ms).
- **Syscall-heavy loop:** +34% on 1M `getppid` and +16% on open+close. That is seccomp's per-syscall
  entry cost on this VM, and the <5% target was missed for pure syscall loops.

## Threat model and limitations

See [docs/threat-model.md](docs/threat-model.md). In short: the code inside is fully hostile and the
kernel is trusted. Zaun doesn't defend against kernel exploits or side channels. The only network
mode is none. Learned policies must be reviewed, because hostile code can widen them while it is
being learned. The LLM-driven generalization study was not done.

## Development

`scripts/vm-setup.sh` creates the Ubuntu VM on macOS (Lima), builds, and runs the tests. Inside the VM:

```sh
systemd-run --user --scope -q --same-dir ctest --test-dir build-vm   # unit tests, cgroup tests included
python3 tests/escape/run.py --zaun build-vm/zaun --bin build-vm/escape
ZAUN=build-vm/zaun python3 integrations/py/test_zaun.py
systemd-run --user --scope bench/run.sh                              # benchmarks
```
