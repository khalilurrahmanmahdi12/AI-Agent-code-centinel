from typing import Dict, Any, List
from agents.base_agent import BaseAgent
from core.ast_analyzer import ASTAnalyzer
from core.models import AgentFinding, Severity


class SecurityAgent(BaseAgent):
    """Specialized agent auditing for Security Vulnerabilities (OWASP Top 10, CWE)."""

    def __init__(self, llm_client):
        super().__init__(
            name="SecuritySentinel",
            role="Application Security (AppSec) Auditor",
            icon="🛡️",
            llm_client=llm_client
        )

    async def analyze(self, code: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.log("Auditing code for critical vulnerabilities, hardcoded secrets, injection vectors...")
        analyzer = ASTAnalyzer(code)
        security_findings: List[AgentFinding] = analyzer.find_security_issues()

        critical_count = sum(1 for f in security_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in security_findings if f.severity == Severity.HIGH)

        self.log(f"Security audit complete. Found {critical_count} CRITICAL and {high_count} HIGH risk items.")

        # Calculate security posture score out of 100
        penalty = (critical_count * 35) + (high_count * 20)
        security_score = max(0.0, 100.0 - penalty)

        return {
            "findings": security_findings,
            "security_score": round(security_score, 1),
            "logs": self.logs
        }
