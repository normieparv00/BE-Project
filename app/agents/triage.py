"""LLM-powered security triage agent using Ollama and Qwen2.5-Coder."""

import logging
from typing import List, Optional, Tuple

from app.config import get_settings
from app.models.schemas import (
    ConfidenceLevel,
    NormalizedFinding,
    Severity,
    TriageResult,
)
from app.services.ollama import (
    OllamaError,
    OllamaMalformedResponseError,
    OllamaService,
    OllamaUnavailableError,
)
from app.utils.code_context import extract_code_context

logger = logging.getLogger(__name__)

TRIAGE_SYSTEM_PROMPT = """You are an elite Application Security Engineer specializing in static code analysis triage.
Your task is to analyze static analysis findings against the provided source code context and determine whether each finding is a TRUE POSITIVE or a FALSE POSITIVE.

Evaluation Guidelines:
1. Carefully inspect the code context around the reported line.
2. Verify if user-controlled input reaches a dangerous sink without sanitization or parameterization.
3. If the input is hardcoded, constant, properly parameterized, sanitized, or in a harmless context, classify as FALSE POSITIVE (is_true_positive: false).
4. Do NOT hallucinate variables, functions, or vulnerabilities not present in the code context.
5. Provide a rigorous, objective security justification in 'reasoning'.
6. Assess contextual severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) and confidence (HIGH, MEDIUM, LOW).
7. Do not modify or suggest fixes in this step.

You MUST respond strictly with valid JSON conforming to this structure:
{
  "finding_id": "<finding_id>",
  "is_true_positive": true,
  "severity": "HIGH",
  "confidence": "HIGH",
  "reasoning": "Detailed explanation of why this is or is not an exploitable vulnerability.",
  "attack_vector_summary": "Brief summary of the attack vector, or null if false positive"
}
"""


class TriageAgent:
    """Agent 2: Performs LLM-based contextual security reasoning on static findings."""

    def __init__(self, ollama_service: Optional[OllamaService] = None) -> None:
        self.ollama_service = ollama_service or OllamaService()

    def _build_triage_prompt(
        self,
        finding: NormalizedFinding,
        code_context: str,
        start_line: Optional[int],
        end_line: Optional[int],
    ) -> str:
        """Construct the prompt sent to the LLM for finding evaluation."""
        return f"""Evaluate the following static security analysis finding:

Finding Details:
- Finding ID: {finding.id}
- Scanner Engine: {finding.scanner.value}
- Rule Identifier: {finding.rule_id}
- Vulnerability Type: {finding.vulnerability_type}
- Reported File: {finding.file_path}
- Target Line: {finding.line_number}
- Scanner Message: {finding.message}
- Initial Scanner Severity: {finding.severity.value}

Source Code Context (Lines {start_line or '?'}-{end_line or '?'}):
```python
{code_context or finding.code_snippet or 'No additional source code context available.'}
```

Determine whether this is a genuine security vulnerability (true positive) or an erroneous/benign alert (false positive).
Respond with the specified JSON object format."""

    def triage_finding(
        self,
        finding: NormalizedFinding,
        base_dir: Optional[str] = None,
    ) -> TriageResult:
        """Evaluate a single normalized finding against its source code context.

        Args:
            finding: The normalized finding to triage.
            base_dir: Optional base repository directory for file resolution.

        Returns:
            Structured TriageResult.

        Raises:
            OllamaUnavailableError: If Ollama service is unreachable.
        """
        context_data = extract_code_context(
            file_path=finding.file_path,
            line_number=finding.line_number,
            context_lines=8,
            base_dir=base_dir,
        )

        code_context = context_data.get("context") or ""
        start_line = context_data.get("start_line")
        end_line = context_data.get("end_line")

        prompt = self._build_triage_prompt(
            finding=finding,
            code_context=code_context,
            start_line=start_line,
            end_line=end_line,
        )

        logger.info("Triaging finding %s (%s at line %d)", finding.id, finding.vulnerability_type, finding.line_number)

        try:
            result = self.ollama_service.generate_structured(
                prompt=prompt,
                schema_class=TriageResult,
                system=TRIAGE_SYSTEM_PROMPT,
            )
            # Ensure finding_id is correctly mapped
            result.finding_id = finding.id
            return result
        except OllamaUnavailableError:
            raise
        except OllamaMalformedResponseError as exc:
            logger.warning("Malformed LLM response for finding %s: %s. Using heuristic fallback.", finding.id, exc)
            return TriageResult(
                finding_id=finding.id,
                is_true_positive=True,  # Default cautiously to scanner's judgment if parsing fails
                severity=finding.severity,
                confidence=ConfidenceLevel.LOW,
                reasoning=f"Automated LLM triage produced malformed response ({exc}). Retaining scanner alert cautiously.",
                attack_vector_summary=None,
            )
        except OllamaError as exc:
            logger.error("Ollama error during triage of %s: %s", finding.id, exc)
            return TriageResult(
                finding_id=finding.id,
                is_true_positive=True,
                severity=finding.severity,
                confidence=ConfidenceLevel.LOW,
                reasoning=f"LLM triage failed with error: {exc}. Retaining scanner finding.",
                attack_vector_summary=None,
            )

    def triage_all(
        self,
        findings: List[NormalizedFinding],
        base_dir: Optional[str] = None,
    ) -> Tuple[List[TriageResult], List[str]]:
        """Triage all supplied findings sequentially.

        Args:
            findings: List of normalized scanner findings.
            base_dir: Base repository path for source context extraction.

        Returns:
            Tuple of (triage results, error messages).
        """
        results: List[TriageResult] = []
        errors: List[str] = []

        for finding in findings:
            try:
                triage_res = self.triage_finding(finding, base_dir=base_dir)
                results.append(triage_res)
            except OllamaUnavailableError as exc:
                msg = f"Triage halted: {exc}"
                logger.error(msg)
                errors.append(msg)
                break
            except Exception as exc:
                msg = f"Unexpected error triaging finding {finding.id}: {exc}"
                logger.exception(msg)
                errors.append(msg)

        return results, errors
