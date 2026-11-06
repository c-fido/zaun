#!/usr/bin/env bash
# Benchmarks from the design doc, with hyperfine. Run in the VM from the repo root:
#   systemd-run --user --scope bench/run.sh [build-vm]
# (the scope gives zaun a delegated cgroup, as in normal use). Writes
# bench/out/*.json and prints a p50/p95 table, also saved as bench/out/results.md.
set -euo pipefail
build=$(realpath "${1:-build-vm}")
zaun="$build/zaun"
out=$(realpath bench)/out
runs=${RUNS:-200}
mkdir -p "$out"
wd=$(mktemp -d /tmp/zaun-bench-XXXXXX)
trap 'rm -rf "$wd"' EXIT
cc -O2 -o "$wd/syscalls" bench/syscalls.c
cp bench/pandas_csv.py "$wd/"
cd "$wd"

# Roughly zaun's baseline view, for bubblewrap.
bwrap=(bwrap --unshare-all --die-with-parent --new-session --ro-bind /usr /usr
       --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/sbin /sbin
       --ro-bind /etc/ld.so.cache /etc/ld.so.cache --ro-bind /etc/alternatives /etc/alternatives
       --proc /proc --dev /dev --tmpfs /tmp
       --bind "$wd" "$wd" --chdir "$wd")
[ -e /lib64 ] && bwrap+=(--symlink usr/lib64 /lib64)

# Learned allowlist policies, so the filter cost of allowlist mode is measured too.
"$zaun" learn --out getppid.toml -- ./syscalls getppid 1000 2>/dev/null
"$zaun" learn --out open.toml -- ./syscalls open 1000 2>/dev/null
"$zaun" learn --out pandas.toml -- python3 pandas_csv.py >/dev/null 2>&1

hf() {  # name, then commands
    local name=$1; shift
    hyperfine -N --warmup 5 --runs "$runs" --export-json "$out/$name.json" "$@" >/dev/null
}
z="$zaun run --workdir $wd --"
hf true -n bare "/bin/true" -n zaun "$z /bin/true" -n bubblewrap "${bwrap[*]} /bin/true"
hf getppid -n bare "./syscalls getppid 1000000" -n zaun-baseline "$z ./syscalls getppid 1000000" \
   -n zaun-allowlist "$zaun run --policy getppid.toml --workdir $wd -- ./syscalls getppid 1000000"
hf open -n bare "./syscalls open 1000000" -n zaun-baseline "$z ./syscalls open 1000000" \
   -n zaun-allowlist "$zaun run --policy open.toml --workdir $wd -- ./syscalls open 1000000"
RUNS=${PANDAS_RUNS:-$runs}
hyperfine -N --warmup 3 --runs "$RUNS" --export-json "$out/pandas.json" \
   -n bare "python3 pandas_csv.py" -n zaun-baseline "$z python3 pandas_csv.py" \
   -n zaun-allowlist "$zaun run --policy pandas.toml --workdir $wd -- python3 pandas_csv.py" \
   -n bubblewrap "${bwrap[*]} python3 pandas_csv.py" >/dev/null
hyperfine -N --warmup 2 --runs "${LEARN_RUNS:-20}" --export-json "$out/learn.json" \
   -n zaun-run "$z python3 pandas_csv.py" \
   -n zaun-learn "$zaun learn --out $wd/l.toml --workdir $wd -- python3 pandas_csv.py" >/dev/null

python3 - "$out" <<'PY' | tee "$out/results.md"
import json, statistics, sys
from pathlib import Path
out = Path(sys.argv[1])
print("| Benchmark | Variant | p50 (ms) | p95 (ms) | vs first |")
print("|---|---|---|---|---|")
for name in ["true", "getppid", "open", "pandas", "learn"]:
    results = json.loads((out / f"{name}.json").read_text())["results"]
    base = None
    for r in results:
        q = statistics.quantiles(r["times"], n=100)
        p50, p95 = statistics.median(r["times"]) * 1000, q[94] * 1000
        if base is None:
            base, delta = p50, ""
        else:
            delta = f"+{p50 - base:.2f} ms" if name == "true" else f"{(p50 / base - 1) * 100:+.1f}%"
        print(f"| {name} | {r['command']} | {p50:.2f} | {p95:.2f} | {delta} |")
PY
