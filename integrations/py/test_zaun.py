"""Runs zaun_exec against a built zaun: ZAUN=build-vm/zaun python3 integrations/py/test_zaun.py"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from zaun import zaun_exec  # noqa: E402

ZAUN = os.path.abspath(os.environ.get("ZAUN", "build/zaun"))


class ZaunExec(unittest.TestCase):
    def run_code(self, code, **kw):
        return zaun_exec(code, zaun=ZAUN, **kw)

    def test_output_and_files(self):
        r = self.run_code("print(open('in.txt').read().upper())", files={"in.txt": "hi"})
        self.assertEqual((r.exit_code, r.exit_reason, r.stdout), (0, "exit", "HI\n"))

    def test_error_exit(self):
        r = self.run_code("raise SystemExit(3)")
        self.assertEqual((r.exit_code, r.exit_reason), (3, "exit"))

    def test_timeout(self):
        r = self.run_code("while True: pass", timeout=1)
        self.assertEqual((r.exit_code, r.exit_reason), (137, "timeout"))

    def test_home_hidden(self):
        r = self.run_code(f"open({str(Path.home() / '.bashrc')!r})")
        self.assertNotEqual(r.exit_code, 0)
        self.assertIn("No such file", r.stderr)

    def test_bad_policy_is_setup_failure(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml") as p:
            p.write("version = 1\nbogus = 1\n")
            p.flush()
            r = self.run_code("print(1)", policy=p.name)
        self.assertEqual((r.exit_code, r.exit_reason), (125, "setup"))

    def test_learned_policy_reports_violations(self):
        with tempfile.TemporaryDirectory() as wd:
            policy = os.path.join(wd, "p.toml")
            subprocess.run([ZAUN, "learn", "--out", policy, "--workdir", wd, "--", "python3", "-c", "pass"],
                           check=True, capture_output=True)
            r = self.run_code("import os; os.getppid()", policy=policy)
        self.assertEqual(r.exit_code, 0)
        self.assertIn({"kind": "syscall", "name": "getppid", "count": 1}, r.violations)


if __name__ == "__main__":
    unittest.main()
