import asyncio
from typing import Dict, Any, List
from core.llm_client import LLMClient
from core.models import (
    AgentReviewResponse,
    AgentScore,
    AgentFinding,
    CodeMetrics,
    RefactorOutput,
    TestSuiteOutput
)
from agents.quality_agent import QualityAgent
from agents.security_agent import SecurityAgent
from agents.refactor_agent import RefactorAgent
from agents.test_generator_agent import TestGeneratorAgent


class MasterOrchestrator:
    """Coordinates specialized programming agents into a cohesive review and refactoring pipeline."""

    def __init__(self, provider: str = "built-in", api_key: str = None):
        self.llm_client = LLMClient(provider=provider, api_key=api_key)
        self.quality_agent = QualityAgent(self.llm_client)
        self.security_agent = SecurityAgent(self.llm_client)
        self.refactor_agent = RefactorAgent(self.llm_client)
        self.test_agent = TestGeneratorAgent(self.llm_client)

    async def execute_pipeline(self, code: str, filename: str = "main.py") -> AgentReviewResponse:
        agent_logs = []

        # Step 1: Parallel audit (Quality & Security agents)
        quality_task = self.quality_agent.analyze(code, {})
        security_task = self.security_agent.analyze(code, {})

        quality_res, security_res = await asyncio.gather(quality_task, security_task)

        agent_logs.append({
            "agent": self.quality_agent.name,
            "role": self.quality_agent.role,
            "icon": self.quality_agent.icon,
            "logs": quality_res["logs"]
        })
        agent_logs.append({
            "agent": self.security_agent.name,
            "role": self.security_agent.role,
            "icon": self.security_agent.icon,
            "logs": security_res["logs"]
        })

        all_findings: List[AgentFinding] = quality_res["findings"] + security_res["findings"]
        metrics: CodeMetrics = quality_res["metrics"]

        # Step 2: Synthesis and Refactoring based on audit
        context = {
            "all_findings": all_findings,
            "metrics": metrics,
            "filename": filename
        }
        refactor_res = await self.refactor_agent.analyze(code, context)
        agent_logs.append({
            "agent": self.refactor_agent.name,
            "role": self.refactor_agent.role,
            "icon": self.refactor_agent.icon,
            "logs": refactor_res["logs"]
        })

        # Step 3: Test Suite Generation for refactored code
        refactored_code = refactor_res["refactor"].refactored_code
        test_res = await self.test_agent.analyze(refactored_code, context)
        agent_logs.append({
            "agent": self.test_agent.name,
            "role": self.test_agent.role,
            "icon": self.test_agent.icon,
            "logs": test_res["logs"]
        })

        # Step 4: Scoring computation
        security_score = security_res["security_score"]
        maintainability_score = quality_res["quality_score"]
        reliability_score = max(30.0, 100.0 - (len(all_findings) * 8))
        testability_score = min(100.0, max(50.0, test_res["test_suite"].test_cases_count * 30.0))

        overall_score = round(
            (security_score * 0.35) +
            (maintainability_score * 0.25) +
            (reliability_score * 0.20) +
            (testability_score * 0.20),
            1
        )

        scores = AgentScore(
            overall=overall_score,
            security=security_score,
            maintainability=maintainability_score,
            reliability=reliability_score,
            testability=testability_score
        )

        # Step 5: Executive summary
        summary = self._generate_executive_summary(scores, all_findings, metrics)

        return AgentReviewResponse(
            project_name="CodeSentinel AI Review",
            language="python",
            original_code=code,
            metrics=metrics,
            scores=scores,
            findings=all_findings,
            refactor=refactor_res["refactor"],
            test_suite=test_res["test_suite"],
            agent_logs=agent_logs,
            executive_summary=summary
        )

    def _generate_executive_summary(self, scores: AgentScore, findings: List[AgentFinding], metrics: CodeMetrics) -> str:
        crit = sum(1 for f in findings if f.severity.value == "CRITICAL")
        high = sum(1 for f in findings if f.severity.value == "HIGH")

        status = "PASSED" if scores.overall >= 80 and crit == 0 else "ACTION REQUIRED"

        summary = (
            f"### Status: **{status}** (Overall Index: {scores.overall}/100)\n\n"
            f"- **Security Posture**: {scores.security}/100 with {crit} critical and {high} high severity risks detected.\n"
            f"- **Maintainability**: {scores.maintainability}/100 (Cyclomatic Complexity: {metrics.cyclomatic_complexity}, LOC: {metrics.loc}).\n"
            f"- **Actionable Resolutions**: RefactorSentinel has generated a patch resolving security leaks and code smells, "
            f"and TestSentinel has constructed automated unit tests for validation."
        )
        return summary
