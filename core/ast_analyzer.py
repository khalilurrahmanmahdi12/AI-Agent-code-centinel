import ast
import re
from typing import List, Dict, Any, Tuple
from core.models import AgentFinding, FindingCategory, Severity, CodeMetrics


class ASTAnalyzer:
    """Analyzes Python code using Python's native AST parser and pattern heuristics."""

    def __init__(self, code: str):
        self.code = code
        self.lines = code.splitlines()
        self.tree = None
        self.syntax_error = None
        try:
            self.tree = ast.parse(code)
        except SyntaxError as e:
            self.syntax_error = f"Syntax Error at line {e.lineno}: {e.msg}"

    def get_metrics(self) -> CodeMetrics:
        loc = len([line for line in self.lines if line.strip() and not line.strip().startswith("#")])
        if not self.tree:
            return CodeMetrics(loc=loc, num_functions=0, num_classes=0, cyclomatic_complexity=1, maintainability_index=50.0)

        num_functions = sum(1 for node in ast.walk(self.tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
        num_classes = sum(1 for node in ast.walk(self.tree) if isinstance(node, ast.ClassDef))

        # Cyclomatic complexity approximation: 1 + decision points (if, for, while, and, or, except, with)
        complexity = 1
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.If, ast.For, ast.While, ast.AsyncFor, ast.ExceptHandler, ast.With, ast.AsyncWith)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1

        # Maintainability index simplified approximation (0 to 100)
        # Higher loc & complexity reduces index
        mi = max(10.0, min(100.0, 100.0 - (complexity * 2.5) - (loc * 0.15)))

        return CodeMetrics(
            loc=loc,
            num_functions=num_functions,
            num_classes=num_classes,
            cyclomatic_complexity=complexity,
            maintainability_index=round(mi, 1)
        )

    def find_security_issues(self) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        # 1. Check for hardcoded secrets / credentials / tokens
        secret_patterns = [
            (r'(?i)(api[_-]?key|secret|password|token|auth_token)\s*=\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', "Hardcoded Secret / API Token"),
            (r'(?i)AWS_[A-Z_]*KEY\s*=\s*["\'][^"\']+["\']', "Hardcoded AWS Credentials"),
        ]
        for line_no, line in enumerate(self.lines, start=1):
            for pattern, title in secret_patterns:
                match = re.search(pattern, line)
                if match:
                    findings.append(AgentFinding(
                        category=FindingCategory.SECURITY,
                        severity=Severity.HIGH,
                        title=title,
                        description=f"Potential sensitive credential or secret key exposed directly in code on line {line_no}.",
                        line_number=line_no,
                        suggestion="Use environment variables via `os.getenv()` or a secure secrets vault rather than hardcoding credentials.",
                        rule_id="SEC-001"
                    ))

        # 2. Check for SQL Injection (string concatenation/formatting in query executions)
        sql_patterns = [
            (r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\%.*["\']', "Potential SQL Injection (Percent Formatting)"),
            (r'(?i)(execute|cursor\.execute)\s*\(\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{.*\}', "Potential SQL Injection (f-string)"),
            (r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*\w+', "Potential SQL Injection (String Concatenation)")
        ]
        for line_no, line in enumerate(self.lines, start=1):
            for pattern, title in sql_patterns:
                if re.search(pattern, line):
                    findings.append(AgentFinding(
                        category=FindingCategory.SECURITY,
                        severity=Severity.CRITICAL,
                        title=title,
                        description=f"Direct SQL query construction using user-controlled string formatting found on line {line_no}.",
                        line_number=line_no,
                        suggestion="Use parameterized queries (prepared statements) e.g., `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`.",
                        rule_id="SEC-002"
                    ))

        # 3. AST Inspection for dangerous calls: eval, exec, os.system, subprocess with shell=True
        if self.tree:
            for node in ast.walk(self.tree):
                if isinstance(node, ast.Call):
                    # eval() or exec()
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ('eval', 'exec'):
                            findings.append(AgentFinding(
                                category=FindingCategory.SECURITY,
                                severity=Severity.CRITICAL,
                                title=f"Use of Dangerous Function `{node.func.id}()`",
                                description=f"Dynamic code evaluation using `{node.func.id}()` can lead to arbitrary Remote Code Execution (RCE).",
                                line_number=node.lineno,
                                suggestion=f"Avoid `{node.func.id}()`. Use `ast.literal_eval()` for parsing literals or json.loads for JSON data.",
                                rule_id="SEC-003"
                            ))
                    # os.system()
                    elif isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'system' and getattr(node.func.value, 'id', '') == 'os':
                            findings.append(AgentFinding(
                                category=FindingCategory.SECURITY,
                                severity=Severity.HIGH,
                                title="Insecure Shell Execution (`os.system`)",
                                description="Calling `os.system` without proper sanitization can allow command injection.",
                                line_number=node.lineno,
                                suggestion="Use `subprocess.run([...], shell=False)` with arguments passed as an explicit list.",
                                rule_id="SEC-004"
                            ))
                        # subprocess.run/call/Popen with shell=True
                        elif node.func.attr in ('run', 'Popen', 'call') and getattr(node.func.value, 'id', '') == 'subprocess':
                            for kw in node.keywords:
                                if kw.arg == 'shell' and getattr(kw.value, 'value', False) is True:
                                    findings.append(AgentFinding(
                                        category=FindingCategory.SECURITY,
                                        severity=Severity.HIGH,
                                        title="Subprocess execution with `shell=True`",
                                        description="Running subprocesses with `shell=True` exposes the application to command injection vulnerabilities.",
                                        line_number=node.lineno,
                                        suggestion="Set `shell=False` and supply command arguments as a list of strings.",
                                        rule_id="SEC-005"
                                    ))

        return findings

    def find_quality_issues(self) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        if self.syntax_error:
            findings.append(AgentFinding(
                category=FindingCategory.CODE_QUALITY,
                severity=Severity.CRITICAL,
                title="Syntax Error",
                description=self.syntax_error,
                line_number=1,
                suggestion="Fix the syntax error to allow code execution and compilation.",
                rule_id="QUAL-000"
            ))
            return findings

        if not self.tree:
            return findings

        # 1. Bare except clauses (except:)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    findings.append(AgentFinding(
                        category=FindingCategory.CODE_QUALITY,
                        severity=Severity.MEDIUM,
                        title="Bare `except:` Clause Detected",
                        description=f"Bare except on line {node.lineno} catches all exceptions including SystemExit and KeyboardInterrupt.",
                        line_number=node.lineno,
                        suggestion="Specify precise exceptions e.g. `except (ValueError, KeyError) as e:` or at least `except Exception as e:`.",
                        rule_id="QUAL-001"
                    ))

        # 2. Function length and excessive complexity
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body_length = len(node.body)
                if body_length > 25:
                    findings.append(AgentFinding(
                        category=FindingCategory.MAINTAINABILITY,
                        severity=Severity.LOW,
                        title=f"Function `{node.name}` is Too Long ({body_length} statements)",
                        description=f"Function `{node.name}` at line {node.lineno} exceeds the recommended limit of 25 statements.",
                        line_number=node.lineno,
                        suggestion="Decompose this function into smaller, single-responsibility helper functions.",
                        rule_id="QUAL-002"
                    ))

                # Missing docstring
                if not ast.get_docstring(node):
                    findings.append(AgentFinding(
                        category=FindingCategory.MAINTAINABILITY,
                        severity=Severity.INFO,
                        title=f"Missing Docstring in `{node.name}`",
                        description=f"Function `{node.name}` does not have a docstring documenting its parameters, return values, or behavior.",
                        line_number=node.lineno,
                        suggestion="Add Google-style or PEP 257 docstring explaining function intent and args.",
                        rule_id="QUAL-003"
                    ))

        # 3. Unused imports or wildcard imports
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == '*':
                        findings.append(AgentFinding(
                            category=FindingCategory.CODE_QUALITY,
                            severity=Severity.MEDIUM,
                            title="Wildcard Import (`from module import *`)",
                            description=f"Wildcard import on line {node.lineno} pollutes the global namespace and obfuscates dependency origins.",
                            line_number=node.lineno,
                            suggestion="Import only the specific classes or functions needed e.g., `from math import sqrt, pi`.",
                            rule_id="QUAL-004"
                        ))

        # 4. Inefficient string concatenation in loops
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.For, ast.While)):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.AugAssign) and isinstance(sub.op, ast.Add):
                        # check if string
                        findings.append(AgentFinding(
                            category=FindingCategory.PERFORMANCE,
                            severity=Severity.LOW,
                            title="String Concatenation in Loop (`+=`)",
                            description=f"Iterative string concatenation inside a loop on line {sub.lineno} causes quadratic memory allocation.",
                            line_number=sub.lineno,
                            suggestion="Collect strings into a list and join them using `''.join(items)` for linear performance.",
                            rule_id="PERF-001"
                        ))
                        break

        return findings
