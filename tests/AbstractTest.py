from tests.TestResult import TestReport


class AbstractTestCase:
    def run_test(self) -> TestReport:
        raise NotImplementedError()