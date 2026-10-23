from typing import Dict, Any, List
from agents.base_agent import BaseAgent
from core.ast_analyzer import ASTAnalyzer
from core.models import AgentFinding, CodeMetrics


class QualityAgent(BaseAgent):
    """Specialized agent focusing on Code Quality, PEP 8, Architecture, and Maintainability."""

    def __init__(self, llm_client):
        super().__init__(
            name="QualitySentinel",
            role="Code Quality & Clean Architecture Specialist",
            icon="💎",
            llm_client=llm_client
        )

    async def analyze(self, code: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.log("Parsing AST and extracting structural complexity metrics...")
        analyzer = ASTAnalyzer(code)
        metrics: CodeMetrics = analyzer.get_metrics()

        self.log(f"Computed metrics: LOC={metrics.loc}, Complexity={metrics.cyclomatic_complexity}, Functions={metrics.num_functions}")
        quality_findings: List[AgentFinding] = analyzer.find_quality_issues()
        self.log(f"Identified {len(quality_findings)} code quality and maintainability observations.")

        # Calculate maintainability score out of 100
        penalty = sum(
            15 if f.severity.value == "CRITICAL" else
            10 if f.severity.value == "HIGH" else
            5 if f.severity.value == "MEDIUM" else 2
            for f in quality_findings
        )
        score = max(20.0, min(100.0, metrics.maintainability_index - penalty))

        return {
            "metrics": metrics,
            "findings": quality_findings,
            "quality_score": round(score, 1),
            "logs": self.logs
        }
