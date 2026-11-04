"""computer-audit core algorithms.

Three audit domains, each AI-enhanceable:
  1. iam_auditor   - IAM permission graphs + blast radius
  2. forensics     - memory/log triage for threat hunting
  3. api_scanner   - API security & microservice scanning

AI enhancement is opt-in via core/ai_enhancer.py and works offline by default
(rule-based heuristics). Wire an LLM provider through env vars when desired.
"""

from .ai_enhancer import AIEnhancer, RuleBasedEnhancer, LLMEnhancer

__all__ = ["AIEnhancer", "RuleBasedEnhancer", "LLMEnhancer"]
