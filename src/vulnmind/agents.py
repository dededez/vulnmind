from typing import Protocol
from vulnmind.graph.state import VulnMindState
from vulnmind.schemas import AgentContext, AgentResult


class BaseAgent(Protocol):
    name: str

    async def run(self, state: VulnMindState, context: AgentContext) -> AgentResult: ...
