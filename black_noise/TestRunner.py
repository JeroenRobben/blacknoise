import subprocess
import traceback

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport, TestStatus
from black_noise.TestTarget import TestTarget


class TestRunner:
    def __init__(self, target: TestTarget, tests: list[AbstractTestCase]):
        self.target = target
        self.tests = tests

    def run_all(self) -> list[TestReport]:
        reports: list[TestReport] = []

        for test in self.tests:
            report = self._run_one(test)
            reports.append(report)

        self._print_summary(reports)

        if self.target.teardown_script:
            self._run_script(self.target.teardown_script, "Teardown")

        return reports

    def _run_one(self, test: AbstractTestCase) -> TestReport:
        print(f"[ RUN ] {test.name}")

        setup_error = self._run_reset_script()
        if setup_error:
            report = TestReport(TestStatus.ERROR, self.target.name, test.name, setup_error)
            print(f"[ERROR] {test.name}: {setup_error}")
            return report

        try:
            report = test.run_test(self.target)
        except Exception as e:
            msg = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
            report = TestReport(TestStatus.ERROR, self.target.name, test.name, msg)

        label = {TestStatus.PASS: " PASS ", TestStatus.FAIL: " FAIL ", TestStatus.ERROR: "ERROR "}[report.status]
        suffix = f": {report.message}" if report.message else ""
        print(f"[{label}] {test.name}{suffix}")
        return report

    def _run_reset_script(self) -> str | None:
        """Run the target's reset script. Returns an error string on failure, None on success."""
        return self._run_script(self.target.reset_script, "Setup")

    def _run_script(self, path: str, label: str) -> str | None:
        """Run a script. Returns an error string on failure, None on success."""
        try:
            result = subprocess.run(
                [path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                return (
                    f"{label} script exited with code {result.returncode}.\n"
                    f"stdout: {result.stdout}\nstderr: {result.stderr}"
                )
        except subprocess.TimeoutExpired:
            return f"{label} script timed out after 60 seconds"
        except Exception as e:
            return f"Failed to run {label.lower()} script: {e}"
        return None

    @staticmethod
    def _print_summary(reports: list[TestReport]) -> None:
        passed = sum(1 for r in reports if r.status == TestStatus.PASS)
        failed = sum(1 for r in reports if r.status == TestStatus.FAIL)
        errors = sum(1 for r in reports if r.status == TestStatus.ERROR)
        total = len(reports)

        print()
        print("=" * 60)
        print(f"Results: {passed}/{total} passed  |  {failed} failed  |  {errors} errors")
        print("=" * 60)
        print()

        for r in reports:
            label = {TestStatus.PASS: " PASS ", TestStatus.FAIL: " FAIL ", TestStatus.ERROR: "ERROR "}[r.status]
            print(f"  [{label}] {r.test_name}")
            if r.message:
                for line in r.message.splitlines():
                    print(f"           {line}")
