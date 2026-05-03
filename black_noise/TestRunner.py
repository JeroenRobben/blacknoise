import csv
import datetime
import os
import select
import signal
import subprocess
import time
import traceback

from black_noise.AbstractTest import AbstractTestCase
from black_noise.TestResult import TestReport, TestStatus
from black_noise.TestTarget import TestTarget


class TestRunner:
    def __init__(self, target: TestTarget, tests: list[AbstractTestCase],
                 results_dir: str | None = None, capture_pcap: bool = True):
        self.target = target
        self.tests = tests
        self.results_dir = results_dir
        self.capture_pcap = capture_pcap
        self._pcap_dir: str | None = None
        self._csv_path: str | None = None

    def run_all(self) -> list[TestReport]:
        reports: list[TestReport] = []

        if self.results_dir is not None:
            os.makedirs(self.results_dir, exist_ok=True)
            self._pcap_dir = os.path.join(self.results_dir, self.target.name)
            os.makedirs(self._pcap_dir, exist_ok=True)
            self._csv_path = os.path.join(self.results_dir, "results.csv")
            self._init_csv()

        for test in self.tests:
            report = self._run_one(test)
            reports.append(report)
            if self._csv_path is not None:
                self._append_csv(report)

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

        pcap_proc = self._start_pcap(test.name) if self._pcap_dir and self.capture_pcap else None
        try:
            try:
                report = test.run_test(self.target)
            except Exception as e:
                msg = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
                report = TestReport(TestStatus.ERROR, self.target.name, test.name, msg)
        finally:
            self._stop_pcap(pcap_proc)

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

    def _start_pcap(self, test_name: str) -> subprocess.Popen | None:
        """Start tcpdump to capture WireGuard UDP traffic for this test."""
        pcap_path = os.path.join(self._pcap_dir, f"{test_name}.pcap")
        bpf = (
            f"udp and host {self.target.target_physical_ip} and ("
            f"port {self.target.target_wg_port} "
            f"or port {self.target.server_wg_port} "
            f"or port {self.target.echo_port})"
        )
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-i", self.target.capture_interface, "--immediate-mode", "-U", "-n", "-w", pcap_path, bpf],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            return None
        # Wait for tcpdump to print "listening on ..." before letting the test
        # send packets. --immediate-mode disables libpcap's 1s kernel buffer
        # timeout, so packets are delivered to tcpdump as soon as they arrive.
        deadline = time.monotonic() + 5.0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([proc.stderr], [], [], remaining)
            if not ready:
                break
            line = proc.stderr.readline()
            if not line or b"listening on" in line:
                break
        return proc

    @staticmethod
    def _stop_pcap(proc: subprocess.Popen | None) -> None:
        if proc is None:
            return
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def _init_csv(self) -> None:
        if not os.path.exists(self._csv_path):
            with open(self._csv_path, "w", newline="") as f:
                csv.writer(f).writerow(["timestamp", "target", "test_name", "status", "message"])

    def _append_csv(self, report: TestReport) -> None:
        with open(self._csv_path, "a", newline="") as f:
            csv.writer(f).writerow([
                datetime.datetime.now().isoformat(timespec="seconds"),
                report.target,
                report.test_name,
                report.status.name,
                (report.message or "").replace("\n", " \\ "),
            ])

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
