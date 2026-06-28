"""Planner agent — the master controller.

Produces a `Plan` of tasks for the engagement. With Claude available it reasons
about the objective and rationale; without it, it emits a sound deterministic
plan for the passive-recon workflow. Either way the task graph (recon →
analysis → reporting) is well-formed with explicit dependencies.
"""

from __future__ import annotations

from recon_platform.agents.base import BaseAgent
from recon_platform.domain.enums import AgentRole, MessagePriority
from recon_platform.domain.interfaces import LLMProvider, Memory, MessageBus
from recon_platform.domain.schemas import EngagementContext, Plan, ReasoningTrace, Task
from recon_platform.recon.modules import build_passive_modules

_SYSTEM = (
    "You are the Planner for an authorized web-app security reconnaissance "
    "platform. Produce a concise objective and rationale for a PASSIVE recon "
    "engagement. Passive means no intrusive probing — DNS, public certificates, "
    "archived URLs, served documents, and response headers only."
)


class PlannerAgent(BaseAgent):
    def __init__(self, bus: MessageBus, memory: Memory, llm: LLMProvider) -> None:
        super().__init__(AgentRole.PLANNER, bus, memory, llm)

    async def make_plan(self, engagement: EngagementContext) -> Plan:
        module_names = [m.name for m in build_passive_modules()]

        objective = f"Passive reconnaissance of {engagement.target}"
        rationale = (
            "Enumerate the externally observable attack surface using only "
            "passive sources, then correlate findings and report."
        )

        # Optional LLM refinement of objective/rationale.
        schema = {
            "type": "object",
            "properties": {
                "objective": {"type": "string"},
                "rationale": {"type": "string"},
            },
            "required": ["objective", "rationale"],
        }
        refined = await self.reason_json(
            _SYSTEM,
            f"Target: {engagement.target}\nWorkflow: {engagement.workflow}\n"
            f"Available passive modules: {', '.join(module_names)}",
            schema,
        )
        if refined:
            objective = refined.get("objective", objective)
            rationale = refined.get("rationale", rationale)

        recon_task = Task(
            title="Passive recon sweep",
            description="Run all passive recon modules and collect assets.",
            assigned_role=AgentRole.RECON,
            priority=MessagePriority.HIGH,
            params={"modules": module_names},
        )
        analysis_task = Task(
            title="Correlate findings",
            description="Analyze assets, derive findings, rank severity.",
            assigned_role=AgentRole.ANALYSIS,
            depends_on=[recon_task.id],
        )
        report_task = Task(
            title="Generate report",
            description="Assemble the report bundle.",
            assigned_role=AgentRole.REPORTING,
            depends_on=[analysis_task.id],
        )

        plan = Plan(
            engagement_id=engagement.id,
            objective=objective,
            rationale=rationale,
            tasks=[recon_task, analysis_task, report_task],
        )

        await self.record(
            ReasoningTrace(
                agent=self.role,
                thought=f"Plan a passive engagement for {engagement.target}.",
                plan=objective,
                reason=rationale,
                action="emit_plan",
                result=f"{len(plan.tasks)} tasks",
                confidence=0.9 if self.llm.available else 0.75,
                next_action="dispatch recon",
            )
        )
        await self.announce(
            recipient=AgentRole.RECON,
            reason=f"Plan ready: {objective}",
            result={"plan_id": plan.id, "tasks": [t.title for t in plan.tasks]},
            confidence=0.9,
            priority=MessagePriority.HIGH,
        )
        return plan
