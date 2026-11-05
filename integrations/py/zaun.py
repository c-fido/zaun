"""zaun_exec: run untrusted Python code under zaun, from an agent's code tool.

    from zaun import zaun_exec
    result = zaun_exec(code, policy="policies/csv-report.toml", timeout=60)
    result.stdout, result.exit_reason, result.violations
"""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field


@dataclass
class Result:
    stdout: str
    stderr: str
    exit_code: int
    # "exit", "signal", "seccomp", "timeout", "memory", or "setup" if zaun
    # failed before running the code (bad policy, missing kernel feature).
    exit_reason: str
    violations: list = field(default_factory=list)  # [{"kind", "name", "count"}]
    duration_ms: int | None = None
    memory_peak: int | None = None  # bytes; None without a delegated cgroup


def zaun_exec(code, policy=None, timeout=60, files=None, zaun="zaun", python="python3"):
    """Runs `code` as main.py in a fresh workdir under `policy` (default: zaun's
    baseline). `files` maps names to str or bytes to put next to it."""
    with tempfile.TemporaryDirectory(prefix="zaun-exec-") as tmp:
        workdir = os.path.join(tmp, "work")
        os.mkdir(workdir)
        # Outside the workdir, so the code can't plant or forge it.
        report = os.path.join(tmp, "report.json")
        for name, data in {"main.py": code, **(files or {})}.items():
            path = os.path.join(workdir, name)
            if os.path.dirname(os.path.abspath(path)) != workdir:
                raise ValueError(f"file name must be a plain name: {name!r}")
            with open(path, "wb") as f:
                f.write(data.encode() if isinstance(data, str) else data)

        cmd = [zaun, "run", "--workdir", workdir, "--report", report]
        if policy:
            cmd += ["--policy", os.path.abspath(policy)]
        if timeout:
            cmd += ["--timeout", f"{timeout}s"]
        cmd += ["--", python, "main.py"]
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")

        try:
            with open(report) as f:
                rep = json.load(f)
        except FileNotFoundError:
            return Result(proc.stdout, proc.stderr, proc.returncode, "setup")
        return Result(proc.stdout, proc.stderr, rep["exit_code"], rep["exit_reason"],
                      rep["violations"], rep["duration_ms"], rep["memory_peak"])
