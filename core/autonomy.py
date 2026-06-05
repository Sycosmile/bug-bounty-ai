"""
Autonomy controller for safe self-running analysis loop
"""

import time
from core.context import Context
from ai.planner import choose_skill, choose_skill_batch


class AutonomyController:
    """Controls when engine continues or stops"""

    def __init__(self):
        self.max_cycles = 20
        self.min_findings_to_stop = 10
        self.stability_rounds = 3

    def should_continue(self, context: Context, cycle: int) -> bool:
        """Decide if system should keep running"""

        # safety stop
        if cycle >= self.max_cycles:
            return False

        # stop if enough intelligence gathered
        if len(context.findings) >= self.min_findings_to_stop:
            return False

        return True

    def choose_mode(self, context: Context) -> str:
        """Decide sequential vs parallel mode"""

        if len(context.findings) < 3:
            return "parallel"
        return "sequential"
