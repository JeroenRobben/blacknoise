from dataclasses import dataclass
from enum import Enum


class TestStatus(Enum):
    FAIL = 0
    PASS = 1
    ERROR = 2

@dataclass
class TestReport:
    def __init__(self, status: TestStatus, target: str, test_name: str, message: str):
        self.status = status
        self.target = target
        self.test_name = test_name
        self.message = message
