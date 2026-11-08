"""Rerun only ticket 08's accepted flakes, without repeating global fixture setup."""
import json
import os
import runpy
import sys
import time
import unittest
from pathlib import Path


def retry_accepted_failures(runner):
    import frappe
    from frappe.testing.result import TestResult

    allowed = {"test_rq_pool_idle_cpu_usage", "test_remove_failed_jobs"}
    for attempt in range(2, 11):
        failed = [test for test, _ in runner.test_result.failures + runner.test_result.errors]
        if not failed or any(getattr(test, "_testMethodName", "") not in allowed for test in failed):
            return
        names = sorted({test.id() for test in failed})
        runner.test_result.printErrors()
        print(runner.test_result, flush=True)
        print(f"Ticket 08: accepted test retry {attempt}/10: " + ", ".join(names), flush=True)
        time.sleep(10)
        frappe.db.rollback()
        frappe.set_user("Administrator")
        runner.test_result = TestResult(
            stream=sys.stderr, descriptions=True, verbosity=2, failfast=runner.failfast
        )
        runner.test_result.startTestRun()
        unittest.TestLoader().loadTestsFromNames(names)(runner.test_result)
        runner.test_result.stopTestRun()


if __name__ == "__main__":
    definitions = runpy.run_path(str(Path(__file__).with_name("ci.py")), run_name="ticket08_ci_definitions")
    with definitions["CodeCoverage"](
        with_coverage=json.loads(os.environ.get("CAPTURE_COVERAGE", "true").lower()), app="frappe"
    ):
        from frappe.parallel_test_runner import ParallelTestRunner

        runner = ParallelTestRunner(
            "frappe",
            site=os.environ.get("SITE") or "test_site",
            build_number=int(os.environ.get("BUILD_NUMBER")),
            total_builds=int(os.environ.get("TOTAL_BUILDS")),
        )
        print("Ticket 08: one global setup and the unchanged full Integration shard", flush=True)
        runner.setup_test_site()
        runner.run_tests()
        retry_accepted_failures(runner)
        runner.print_result()
