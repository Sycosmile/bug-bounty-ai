"""LLM enhancement layer for scoring (optional brain upgrade)"""

from config import LLM_PROVIDER, LLM_API_KEY


class LLMSmartScorer:
    """Enhances scoring engine using LLM reasoning"""

    def __init__(self):
        self.enabled = LLM_PROVIDER != "none" and LLM_API_KEY

    def enrich(self, finding: dict) -> dict:
        """Adds AI reasoning to a finding"""

        if not self.enabled:
            return finding

        # placeholder (plug OpenAI/Anthropic later)
        finding["ai_reason"] = "LLM analysis disabled or not configured"

        return finding
