from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(str, Enum):
    SECURITY = "SECURITY"
    CODE_QUALITY = "CODE_QUALITY"
    PERFORMANCE = "PERFORMANCE"
    MAINTAINABILITY = "MAINTAINABILITY"


class AgentFinding(BaseModel):
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    line_number: Optional[int] = None
    suggestion: str
    rule_id: Optional[str] = None


class CodeMetrics(BaseModel):
    loc: int = 0
    num_functions: int = 0
    num_classes: int = 0
    cyclomatic_complexity: int = 0
    maintainability_index: float = 100.0


class AgentScore(BaseModel):
    overall: float = 0.0
    security: float = 0.0
    maintainability: float = 0.0
    reliability: float = 0.0
    testability: float = 0.0


class RefactorOutput(BaseModel):
    refactored_code: str
    changes_summary: List[str]
    diff_patch: str


class TestSuiteOutput(BaseModel):
    framework: str = "pytest"
    test_code: str
    test_cases_count: int
    coverage_estimate: str


class AgentReviewResponse(BaseModel):
    project_name: str
    language: str
    original_code: str
    metrics: CodeMetrics
    scores: AgentScore
    findings: List[AgentFinding]
    refactor: RefactorOutput
    test_suite: TestSuiteOutput
    agent_logs: List[Dict[str, Any]]
    executive_summary: str


class AnalyzeRequest(BaseModel):
    code: str
    filename: Optional[str] = "main.py"
    language: Optional[str] = "python"
    api_key: Optional[str] = None
    provider: Optional[str] = "built-in"  # 'built-in', 'gemini', 'openai'


class TestRunRequest(BaseModel):
    code: str
    test_code: str


class TestRunResponse(BaseModel):
    success: bool
    passed: int
    failed: int
    errors: int
    output: str
    duration_ms: float
