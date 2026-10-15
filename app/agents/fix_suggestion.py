"""LLM-driven remediation agent for proposing vulnerability fixes and diffs."""

import difflib
import logging
from typing import Dict, List, Optional, Tuple

from app.models.schemas import FixSuggestion, NormalizedFinding, TriageResult
from app.services.ollama import (
    OllamaError,
    OllamaMalformedResponseError,
    OllamaService,
    OllamaUnavailableError,
)
from app.utils.code_context import extract_code_context

logger = logging.getLogger(__name__)

FIX_SYSTEM_PROMPT = """You are a software security engineer providing code fixes for confirmed vulnerabilities.
Your goal is to suggest a safe, clean, and minimal code replacement that remediates the reported vulnerability.

Remediation Rules:
1. Fix the underlying security issue directly (e.g., parameterized queries for SQLi, proper escaping, safe subprocess args, env vars for secrets).
2. Keep changes minimal and preserve existing application behavior and formatting style.
3. Avoid introducing regressions, unnecessary refactoring, or new dependencies unless required.
4. Provide a clear, practical explanation of the fix.

Respond strictly in valid JSON matching this schema:
{
  "finding_id": "<finding_id>",
  "vulnerability_type": "<vulnerability_type>",
  "file_path": "<file_path>",
  "explanation": "Clear explanation of how the patch resolves the issue.",
  "remediation_strategy": "Short name for the fix pattern (e.g., Parameterized Queries)",
  "suggested_code": "Replacement code snippet.",
  "diff": "Unified diff or null"
}"""


class FixSuggestionAgent:
    """Generates remediation advice and code patches for confirmed security vulnerabilities."""

    def __init__(self, ollama_service: Optional[OllamaService] = None) -> None:
        self.ollama_service = ollama_service or OllamaService()

    def _generate_diff(self, original_code: str, suggested_code: str, file_path: str) -> str:
        """Create a unified diff between the original code snippet and suggested fix."""
        old_lines = original_code.splitlines(keepends=True)
        new_lines = suggested_code.splitlines(keepends=True)
        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)

    def _build_fix_prompt(
        self,
        finding: NormalizedFinding,
        triage_result: TriageResult,
        code_context: str,
        raw_code: str,
    ) -> str:
        snippet = finding.code_snippet or raw_code or "Code snippet unavailable"
        context_block = code_context or "Context unavailable"
        attack_vector = triage_result.attack_vector_summary or "Direct exploitation"
        sev_val = triage_result.severity.value if hasattr(triage_result.severity, "value") else str(triage_result.severity)

        return (
            f"Suggest a secure remediation patch for this confirmed issue:\n\n"
            f"Vulnerability Details:\n"
            f"- Finding ID: {finding.id}\n"
            f"- Type: {finding.vulnerability_type}\n"
            f"- File: {finding.file_path}:{finding.line_number}\n"
            f"- Rule: {finding.rule_id}\n"
            f"- Assessed Severity: {sev_val}\n\n"
            f"Triage Notes:\n"
            f"- Reasoning: {triage_result.reasoning}\n"
            f"- Attack Vector: {attack_vector}\n\n"
            f"Flagged Code:\n"
            f"```python\n{snippet}\n```\n\n"
            f"Surrounding Context:\n"
            f"```python\n{context_block}\n```\n\n"
            f"Return the remediation details and replacement code in the specified JSON schema."
        )

    def suggest_fix(
        self,
        finding: NormalizedFinding,
        triage_result: TriageResult,
        base_dir: Optional[str] = None,
    ) -> FixSuggestion:
        """Generate a remediation suggestion for a confirmed vulnerability."""
        ctx = extract_code_context(
            file_path=finding.file_path,
            line_number=finding.line_number,
            context_lines=8,
            base_dir=base_dir,
        )

        code_context = ctx.get("context") or ""
        raw_code = ctx.get("raw_code") or (finding.code_snippet or "")

        prompt = self._build_fix_prompt(
            finding=finding,
            triage_result=triage_result,
            code_context=code_context,
            raw_code=raw_code,
        )

        logger.info("Generating remediation for %s (%s)", finding.id, finding.vulnerability_type)

        try:
            suggestion = self.ollama_service.generate_structured(
                prompt=prompt,
                schema_class=FixSuggestion,
                system=FIX_SYSTEM_PROMPT,
            )

            # Preserve finding metadata
            suggestion.finding_id = finding.id
            suggestion.file_path = finding.file_path
            suggestion.vulnerability_type = finding.vulnerability_type

            # Produce local unified diff if model didn't provide one
            if not suggestion.diff and raw_code and suggestion.suggested_code:
                suggestion.diff = self._generate_diff(raw_code, suggestion.suggested_code, finding.file_path)

            return suggestion
        except OllamaUnavailableError:
            raise
        except OllamaMalformedResponseError as e:
            logger.warning("Malformed LLM response during fix generation for %s: %s", finding.id, e)
            return FixSuggestion(
                finding_id=finding.id,
                vulnerability_type=finding.vulnerability_type,
                file_path=finding.file_path,
                explanation=f"LLM produced invalid response format ({e}). Manual review needed.",
                remediation_strategy="Manual remediation required",
                suggested_code=finding.code_snippet or "# Please review and fix manually",
                diff=None,
            )
        except OllamaError as e:
            logger.error("Ollama error during fix generation for %s: %s", finding.id, e)
            return FixSuggestion(
                finding_id=finding.id,
                vulnerability_type=finding.vulnerability_type,
                file_path=finding.file_path,
                explanation=f"Fix generation failed due to Ollama error: {e}",
                remediation_strategy="Manual remediation required",
                suggested_code=finding.code_snippet or "# Please review and fix manually",
                diff=None,
            )

    def suggest_fixes(
        self,
        findings: List[NormalizedFinding],
        triage_results: List[TriageResult],
        base_dir: Optional[str] = None,
    ) -> Tuple[List[FixSuggestion], List[str]]:
        """Generate remediation suggestions for all confirmed true-positive findings."""
        confirmed = [t for t in triage_results if t.is_true_positive]
        if not confirmed:
            logger.info("No confirmed vulnerabilities to remediate")
            return [], []

        logger.info("Generating fixes for %d confirmed findings", len(confirmed))
        findings_map: Dict[str, NormalizedFinding] = {f.id: f for f in findings}

        suggestions: List[FixSuggestion] = []
        errors: List[str] = []

        for triage_res in confirmed:
            finding = findings_map.get(triage_res.finding_id)
            if not finding:
                logger.warning("Finding ID %s missing from findings map", triage_res.finding_id)
                continue

            try:
                fix = self.suggest_fix(finding, triage_res, base_dir=base_dir)
                suggestions.append(fix)
            except OllamaUnavailableError as e:
                # Backend unavailable, stop further attempts
                msg = f"Fix generation aborted: {e}"
                logger.error(msg)
                errors.append(msg)
                break
            except Exception as e:
                msg = f"Failed to generate fix for {finding.id}: {e}"
                logger.exception(msg)
                errors.append(msg)

        return suggestions, errors
