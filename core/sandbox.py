import os
import sys
import tempfile
import time
import subprocess
from core.models import TestRunResponse


class CodeSandbox:
    """Safely executes generated test cases against code in an isolated subprocess."""

    @staticmethod
    def run_tests(code: str, test_code: str, timeout_seconds: int = 5) -> TestRunResponse:
        start_time = time.time()
        with tempfile.TemporaryDirectory() as tmpdir:
            module_file = os.path.join(tmpdir, "solution.py")
            test_file = os.path.join(tmpdir, "test_solution.py")

            with open(module_file, "w", encoding="utf-8") as f:
                f.write(code)

            # Ensure the test imports the solution correctly
            adjusted_test = test_code
            if "from solution import" not in adjusted_test and "import solution" not in adjusted_test:
                adjusted_test = "from solution import *\n" + adjusted_test

            with open(test_file, "w", encoding="utf-8") as f:
                f.write(adjusted_test)

            cmd = [sys.executable, "-m", "pytest", test_file, "-v", "--tb=short"]
            try:
                result = subprocess.run(
                    cmd,
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds
                )
                output = result.stdout + "\n" + result.stderr
                duration = (time.time() - start_time) * 1000

                # Parse pytest output
                passed = output.count("PASSED")
                failed = output.count("FAILED")
                errors = output.count("ERROR")

                success = (result.returncode == 0)

                return TestRunResponse(
                    success=success,
                    passed=passed,
                    failed=failed,
                    errors=errors,
                    output=output.strip(),
                    duration_ms=round(duration, 2)
                )
            except subprocess.TimeoutExpired:
                return TestRunResponse(
                    success=False,
                    passed=0,
                    failed=1,
                    errors=1,
                    output=f"Execution timed out after {timeout_seconds} seconds.",
                    duration_ms=(time.time() - start_time) * 1000
                )
            except Exception as e:
                return TestRunResponse(
                    success=False,
                    passed=0,
                    failed=0,
                    errors=1,
                    output=f"Sandbox error: {str(e)}",
                    duration_ms=(time.time() - start_time) * 1000
                )
