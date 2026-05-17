from typing import Any

from app.agents import MultiAgentInvestigator


def run_auto_investigation(selected_files: list[str] | None = None) -> dict[str, Any]:
    """
    Run the multi-agent investigation workflow across uploaded workspace files.

    The UI keeps calling this legacy entry point, while the implementation now
    delegates to explicit specialist agents coordinated by MultiAgentInvestigator.
    """
    return MultiAgentInvestigator(selected_files=selected_files).run()
