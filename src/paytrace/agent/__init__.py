"""Agentic wrapper over the attribution toolkit.

    from paytrace.agent import Agent, Toolbox, FixtureFetcher

    box = Toolbox(FixtureFetcher(poisoned=True), FixtureIndex())
    run = Agent(box, guards_enabled=True).run("attribute scraper-site.example")
    print(report(run))
"""

from .agent import Agent, AgentRun, Decision, LLMBrain, ScriptedBrain, report
from .fixtures import DECOY_ENTITY, REAL_ENTITY, FixtureFetcher, FixtureIndex
from .guards import GuardReport, PlanInvariants, Severity, apply_all, scan
from .tools import Tool, Toolbox, ToolResult, Trust

__all__ = [
    "Agent", "AgentRun", "Decision", "ScriptedBrain", "LLMBrain", "report",
    "Toolbox", "Tool", "ToolResult", "Trust",
    "scan", "apply_all", "GuardReport", "PlanInvariants", "Severity",
    "FixtureFetcher", "FixtureIndex", "REAL_ENTITY", "DECOY_ENTITY",
]
