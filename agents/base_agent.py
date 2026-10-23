from abc import ABC, abstractmethod
from typing import Dict, Any, List
from core.llm_client import LLMClient


class BaseAgent(ABC):
    """Abstract base class for all specialized programming agents."""

    def __init__(self, name: str, role: str, icon: str, llm_client: LLMClient):
        self.name = name
        self.role = role
        self.icon = icon
        self.llm_client = llm_client
        self.logs: List[str] = []

    def log(self, message: str):
        self.logs.append(f"[{self.name}] {message}")

    @abstractmethod
    async def analyze(self, code: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the agent task on the given code and context."""
        pass
