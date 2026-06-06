"""
Conftest runner — executes OPA/Conftest policy tests against input files.
"""
from __future__ import annotations
import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class ConftestResult:
    passed: int
    failed: int
    warnings: int
    messages: list[dict] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.failed == 0

    def summary(self) -> str:
        return f"Passed: {self.passed}, Failed: {self.failed}, Warnings: {self.warnings}"


class ConftestRunner:
    def __init__(self, policy_dir: str, binary: str = "conftest") -> None:
        self._policy_dir = Path(policy_dir)
        self._binary = binary
        if not shutil.which(binary):
            raise RuntimeError(f"'{binary}' not found in PATH. Install conftest: https://conftest.dev")

    def test(
        self,
        input_file: str | Path,
        policy: Optional[str] = None,
        namespace: Optional[str] = None,
        all_namespaces: bool = False,
    ) -> ConftestResult:
        cmd = [self._binary, "test", str(input_file), "--output", "json"]
        policy_path = str(policy or self._policy_dir)
        cmd += ["--policy", policy_path]
        if namespace:
            cmd += ["--namespace", namespace]
        if all_namespaces:
            cmd.append("--all-namespaces")

        log.debug("Running: %s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True)
        stdout = proc.stdout.strip()

        if not stdout:
            # No output means all passed or error
            if proc.returncode == 0:
                return ConftestResult(passed=1, failed=0, warnings=0)
            log.error("Conftest error: %s", proc.stderr)
            return ConftestResult(passed=0, failed=1, warnings=0,
                                  messages=[{"message": proc.stderr, "type": "error"}])

        return self.parse_output(stdout)

    def parse_output(self, stdout: str) -> ConftestResult:
        try:
            results = json.loads(stdout)
        except json.JSONDecodeError:
            log.warning("Could not parse conftest output: %s", stdout[:200])
            return ConftestResult(passed=0, failed=1, warnings=0)

        passed = failed = warnings = 0
        messages: list[dict] = []

        for result in results:
            passed += result.get("successes", 0)
            for failure in result.get("failures", []):
                failed += 1
                messages.append({"type": "failure", "message": failure.get("msg", ""),
                                  "metadata": failure.get("metadata", {})})
            for warning in result.get("warnings", []):
                warnings += 1
                messages.append({"type": "warning", "message": warning.get("msg", "")})

        return ConftestResult(passed=passed, failed=failed, warnings=warnings, messages=messages)

    def test_terraform_plan(self, plan_json_path: str | Path) -> ConftestResult:
        policy_path = self._policy_dir / "terraform"
        if not policy_path.exists():
            policy_path = self._policy_dir
        return self.test(plan_json_path, policy=str(policy_path), namespace="terraform")

    def test_k8s_manifests(self, manifest_dir: str | Path) -> list[tuple[str, ConftestResult]]:
        manifest_path = Path(manifest_dir)
        results = []
        for yaml_file in manifest_path.rglob("*.yaml"):
            result = self.test(yaml_file, namespace="kubernetes")
            results.append((str(yaml_file), result))
            if not result.success:
                log.warning("Policy failures in %s: %s", yaml_file, result.summary())
        return results

    def test_all(self, input_dir: str | Path) -> ConftestResult:
        total = ConftestResult(passed=0, failed=0, warnings=0)
        for f in Path(input_dir).rglob("*"):
            if f.suffix in (".json", ".yaml", ".yml", ".tf") and f.is_file():
                r = self.test(f)
                total.passed += r.passed
                total.failed += r.failed
                total.warnings += r.warnings
                total.messages.extend(r.messages)
        return total

# _r 20260606141512-44bb8eee
