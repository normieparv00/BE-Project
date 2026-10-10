"""LLM-powered remediation and fix-suggestion agent."""

import difflib
import logging
from typing import Dict, List, Optional, Tuple

from app.config import get_settings
from app.models.schemas import FixSuggestion, NormalizedFinding, TriageResult
from app.services.ollama import (
    OllamaError,
    OllamaMalformedResponseError,
    OllamaService,
    OllamaUnavailableError,
)
from app.utils.code_context import extract_code_context

logger = logging.getLogger(__name__)

FIX_SYSTEM_PROMPT = """You are a Principal Secure Software Engineer and Secure Coding Expert.
Your responsibility is to analyze confirmed security vulnerabilities and propose concrete, safe, and minimal remediation code.

Remediation Guidelines:
1. Provide a precise, production-ready replacement for the vulnerable code.
2. Adhere to security best practices (e.g., parameterized SQL queries, secure credential storage via environment variables, safe deserialization libraries, safe subprocess execution).
3. Do NOT introduce new vulnerabilities or functional regressions.
4. Keep the patch concise and idiomatic to the language/framework used.
5. Provide a clear, educational explanation of the vulnerability and the fix.

You MUST respond strictly with valid JSON conforming to this structure:
{
  "finding_id": "<finding_id>",
  "vulnerability_type": "<vulnerability_type>",
  "file_path": "<file_path>",
  "explanation": "Detailed explanation of why the fix eliminates the vulnerability.",
  "remediation_strategy": "High-level summary of the remediation pattern (e.g., Parameterized Queries)",
  "suggested_code": "The clean, corrected code replacement.",
  "diff": "Optional unified diff string, or null"
}
"""


class FixSuggestionAgent:
    """Agent 3: Generates secure remediation proposals for confirmed vulnerabilities."""

    def __init__(self, ollama_service: Optional[OllamaService] = None) -> None:
        self.ollama_service = ollama_service or OllamaService()

    def _generate_diff(self, original_code: str, suggested_code: str, file_path: str) -> str:
        """Generate unified diff string between original and suggested code."""
        orig_lines = original_code.splitlines(keepends=True)
        new_lines = suggested_code.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
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
        """Construct the prompt sent to the LLM for fix suggestion."""
        return f"""Generate a secure code remediation for the following confirmed vulnerability:

Vulnerability Information:
- Finding ID: {finding.id}
- Vulnerability Type: {finding.vulnerability_type}
- File Path: {finding.file_path}
- Line Number: {finding.line_number}
- Scanner Rule: {finding.rule_id}
- Assessed Severity: {triage_result.severity.value}

Triage Assessment:
- Justification: {triage_result.reasoning}
- Attack Vector: {triage_result.attack_vector_summary or 'Direct exploitation'}

Vulnerable Code Snippet:
```python
{finding.code_snippet or raw_code or 'Code snippet unavailable'}
```

Surrounding Code Context:
```python
{code_context or 'Context unavailable'}
```

Provide the secure replacement code, strategy, and explanation in the specified JSON format."""

    def suggest_fix(
        self,
        finding: NormalizedFinding,
        triage_result: TriageResult,
        base_dir: Optional[str] = None,
    ) -> FixSuggestion:
        """Generate a remediation suggestion for a confirmed vulnerability.

        Args:
            finding: Normalized finding details.
            triage_result: Confirmed triage judgment.
            base_dir: Base repository path for source context extraction.

        Returns:
            FixSuggestion instance.

        Raises:
            OllamaUnavailableError: If Ollama is unreachable.
        """
        context_data = extract_code_context(
            file_path=finding.file_path,
            line_number=finding.line_number,
            context_lines=8,
            base_dir=base_dir,
        )

        code_context = context_data.get("context") or ""
        raw_code = context_data.get("raw_code") or (finding.code_snippet or "")

        prompt = self._build_fix_prompt(
            finding=finding,
            triage_result=triage_result,
            code_context=code_context,
            raw_code=raw_code,
        )

        logger.info("Generating remediation for finding %s (%s)", finding.id, finding.vulnerability_type)

        try:
            suggestion = self.ollama_service.generate_structured(
                prompt=prompt,
                schema_class=FixSuggestion,
                system=FIX_SYSTEM_PROMPT,
            )
            # Ensure finding ID and paths match accurately
            suggestion.finding_id = finding.id
            suggestion.file_path = finding.file_path
            suggestion.vulnerability_type = finding.vulnerability_type

            # If diff was not generated by model, generate a unified diff locally
            if not suggestion.diff and raw_code and suggestion.suggested_code:
                suggestion.diff = self._generate_diff(raw_code, suggestion.suggested_code, finding.file_path)

            return suggestion
        except OllamaUnavailableError:
            raise
        except OllamaMalformedResponseError as exc:
            logger.warning("Malformed LLM response for fix of %s: %s. Using basic fallback.", finding.id, exc)
            return FixSuggestion(
                finding_id=finding.id,
                vulnerability_type=finding.vulnerability_type,
                file_path=finding.file_path,
                explanation=f"LLM produced malformed response during fix generation: {exc}.",
                remediation_strategy="Manual remediation required",
                suggested_code=finding.code_snippet or "# Please review and fix manually",
                diff=None,
            )
        except OllamaError as exc:
            logger.error("Ollama error during fix generation for %s: %s", finding.id, exc)
            return FixSuggestion(
                finding_id=finding.id,
                vulnerability_type=finding.vulnerability_type,
                file_path=finding.file_path,
                explanation=f"Failed to generate fix due to Ollama error: {exc}.",
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
        """Generate remediation suggestions for all confirmed vulnerabilities.

        Args:
            findings: Normalized scanner findings.
            triage_results: Results from the triage stage.
            base_dir: Base repository path.

        Returns:
            Tuple of (fix suggestions, error messages).
        """
        suggestions: List[FixSuggestion] = []
        errors: List[str] = []

        findings_map: Dict[str, NormalizedFinding] = {f.id: f for f in findings}

        # Filter only confirmed true positives
        confirmed = [t for t in triage_results if t.is_true_positive]
        logger.info("Generating fixes for %d confirmed vulnerabilities", len(confirmed))

        for triage_res in confirmed:
            finding = findings_map.get(triage_res.finding_id)
            if not finding:
                logger.warning("Finding ID %s not found in original findings map", triage_res.finding_id)
                continue

            try:
                fix = self.suggest_fix(finding, triage_res, base_dir=base_dir)
                suggestions.append(fix)
            except OllamaUnavailableError as exc:
                msg = f"Fix generation halted: {exc}"
                logger.error(msg)
                errors.append(msg)
                break
            except Exception as exc:
                msg = f"Unexpected error generating fix for {finding.id}: {exc}"
                logger.exception(msg)
                errors.append(msg)

        return suggestions, errors
