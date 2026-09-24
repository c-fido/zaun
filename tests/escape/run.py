#!/usr/bin/env python3
"""Escape suite: runs each attack bare (it must escape) and under zaun (it must
be blocked for the reason in its sidecar). A test that can't escape bare is
broken, not passing.

Each tests/escape/<ID>.expect sidecar holds `key: value` lines:
  attack, defense  - for the results table
  args             - optional; {home}, {victim} and {pidns} are substituted
  blocked          - expected reason under zaun: an errno name, a string the
                     test prints, or "signal SIGxxx" if zaun kills it
"""

import argparse
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CANARY = "sk-zaun-escape-canary"
# fd 3 is opened on the secret file for every run, for LEAK-2.
FD3_WRAPPER = 'exec 3<"$0"; exec "$@"'


def read_sidecar(path):
    fields = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields


def outcome(proc):
    """Returns (escaped, reason) for a finished test run."""
    lines = proc.stdout.strip().splitlines()
    last = lines[-1] if lines else ""
    if proc.returncode == 0 and last.startswith("escaped:"):
        return True, last.removeprefix("escaped:").strip()
    if proc.returncode == 1 and last.startswith("blocked:"):
        return False, last.removeprefix("blocked:").strip()
    if proc.returncode > 128:
        return False, "signal " + signal.Signals(proc.returncode - 128).name
    detail = (proc.stderr.strip() or last or "no output").splitlines()[-1]
    return False, f"exit {proc.returncode}: {detail}"


class Victim:
    """A host process for the PROC-* tests, holding the canary in its environment."""

    def __init__(self, binary, env):
        self.proc = subprocess.Popen([binary], env=env, stdout=subprocess.PIPE, text=True)
        if self.proc.stdout.readline().strip() != "ready":
            raise RuntimeError("victim failed to start")

    @property
    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        if self.alive:
            self.proc.kill()
        self.proc.wait()


def run_attack(binary, args, secret, env, zaun=None):
    with tempfile.TemporaryDirectory(prefix="zaun-escape-wd-") as workdir:
        shutil.copy2(binary, workdir)
        cmd = [f"./{binary.name}", *args]
        if zaun:
            cmd = [zaun, "run", "--workdir", workdir, "--", *cmd]
        return subprocess.run(["sh", "-c", FD3_WRAPPER, secret, *cmd], cwd=workdir, env=env,
                              capture_output=True, text=True, timeout=60)


def run_test(test_id, sidecar, bindir, zaun, home, secret, env):
    """Returns (status, detail)."""
    binary = bindir / test_id
    if not binary.exists():
        return "BROKEN", f"{binary} not built"
    victim = Victim(bindir / "victim", env)
    try:
        subst = {"home": str(home), "victim": str(victim.proc.pid),
                 "pidns": os.readlink("/proc/self/ns/pid")}
        args = [a.format(**subst) for a in shlex.split(sidecar.get("args", ""))]

        escaped, reason = outcome(run_attack(binary, args, secret, env))
        if not escaped:
            return "BROKEN", f"bare run did not escape ({reason})"

        if not victim.alive:  # PROC-2 kills it bare
            victim.stop()
            victim = Victim(bindir / "victim", env)
            subst["victim"] = str(victim.proc.pid)
            args = [a.format(**subst) for a in shlex.split(sidecar.get("args", ""))]

        escaped, reason = outcome(run_attack(binary, args, secret, env, zaun))
        if escaped:
            return "FAIL", f"escaped under zaun: {reason}"
        if not victim.alive:
            return "FAIL", "victim was killed under zaun"
        if reason != sidecar["blocked"]:
            return "FAIL", f"blocked for the wrong reason: {reason} (want {sidecar['blocked']})"
        return "PASS", reason
    finally:
        victim.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("ids", nargs="*", help="tests to run (default: all)")
    parser.add_argument("--zaun", default=ROOT / "build/zaun", type=Path)
    parser.add_argument("--bin", default=ROOT / "build/escape", type=Path,
                        help="directory with the built test programs")
    parser.add_argument("--results", type=Path, help="write a markdown results table here")
    opts = parser.parse_args()

    sidecars = {p.stem: p for p in sorted(HERE.glob("*.expect"))}
    ids = opts.ids or list(sidecars)
    unknown = [i for i in ids if i not in sidecars]
    if unknown:
        parser.error(f"unknown tests: {' '.join(unknown)}")

    # Fixtures live under the real $HOME, which the sandbox must hide.
    home = Path(tempfile.mkdtemp(prefix=".zaun-escape-", dir=Path.home()))
    try:
        (home / ".ssh").mkdir(mode=0o700)
        (home / ".ssh/id_ed25519").write_text("zaun escape fixture key\n")
        (home / ".bashrc").write_text("# zaun escape fixture\n")
        secret = home / "fd3-secret"
        secret.write_text(CANARY + "\n")
        env = dict(os.environ, ANTHROPIC_API_KEY=CANARY)

        rows = []
        for test_id in ids:
            sidecar = read_sidecar(sidecars[test_id])
            status, detail = run_test(test_id, sidecar, opts.bin, str(opts.zaun.resolve()),
                                      home, str(secret), env)
            rows.append((test_id, sidecar.get("attack", ""), sidecar.get("defense", ""),
                         status, detail))
            print(f"{status:6} {test_id:8} {detail}")
    finally:
        shutil.rmtree(home)

    passed = sum(r[3] == "PASS" for r in rows)
    print(f"\n{passed}/{len(rows)} blocked")
    if opts.results:
        table = ["| ID | Attack | Expected defense | Result | Detail |", "|---|---|---|---|---|"]
        table += ["| " + " | ".join(r) + " |" for r in rows]
        opts.results.write_text(f"{passed}/{len(rows)} blocked\n\n" + "\n".join(table) + "\n")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
