import pytest
import asyncio
from core.models import AnalyzeRequest, Severity
from core.ast_analyzer import ASTAnalyzer
from agents.orchestrator import MasterOrchestrator
from core.sandbox import CodeSandbox

SAMPLE_VULNERABLE = """
import os

API_KEY = "sk-1234567890abcdef123456"

def query_user(user_id):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return query

def run_command(cmd):
    # Insecure shell execution
    os.system(cmd)

def calculate(x):
    try:
        return x / 2
    except:
        return 0
"""

def test_ast_analyzer_detects_issues():
    analyzer = ASTAnalyzer(SAMPLE_VULNERABLE)
    metrics = analyzer.get_metrics()
    assert metrics.loc > 0
    assert metrics.num_functions == 3

    sec_issues = analyzer.find_security_issues()
    qual_issues = analyzer.find_quality_issues()

    assert any(i.severity == Severity.HIGH or i.severity == Severity.CRITICAL for i in sec_issues)
    assert any(i.rule_id == "QUAL-001" for i in qual_issues)  # Bare except


@pytest.mark.anyio
async def test_master_orchestrator_pipeline():
    orchestrator = MasterOrchestrator(provider="built-in")
    response = await orchestrator.execute_pipeline(SAMPLE_VULNERABLE, filename="test.py")

    assert response is not None
    assert response.scores.overall > 0
    assert len(response.findings) >= 3
    assert response.refactor.refactored_code is not None
    assert response.test_suite.test_cases_count >= 1


def test_sandbox_execution():
    code = """
def add(a, b):
    return a + b
"""
    test_code = """
from solution import add

def test_add():
    assert add(2, 3) == 5
"""
    result = CodeSandbox.run_tests(code=code, test_code=test_code)
    assert result.success is True
    assert result.passed >= 1
    assert result.failed == 0
