"""LLM-assisted security triage agent for filtering false positives."""

import logging
from typing import List, Optional, Tuple

from app.models.schemas import (
    ConfidenceLevel,
    NormalizedFinding,
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

TRIAGE_SYSTEM_PROMPT = """You are an application security triage assistant.
Your task is to analyze static analysis findings against source code context and determine whether each alert is a TRUE POSITIVE or a FALSE POSITIVE.

Evaluation Criteria:
1. Examine the source code around the reported line number carefully.
2. Check if untrusted user input actually reaches a sensitive sink without validation, sanitization, or parameterization.
3. If the input is constant, safely parameterized, sanitized, test mock data, or unreachable, classify as FALSE POSITIVE (is_true_positive: false).
4. Do not speculate or invent variables, functions, or vulnerabilities not present in the provided context.
5. Provide concise, technical security reasoning grounded strictly in the code.
6. Assess severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) and confidence (HIGH, MEDIUM, LOW) based on actual impact.
7. Do not propose code fixes in this triage phase.

Respond strictly in valid JSON adhering to this schema:
{
  "finding_id": "<finding_id>",
  "is_true_positive": true,
  "severity": "HIGH",
  "confidence": "HIGH",
  "reasoning": "Technical justification of why this issue is or is not exploitable.",
  "attack_vector_summary": "Brief summary of attack vector if true positive, else null"
}"""


class TriageAgent:
    """Evaluates static analysis alerts using an LLM to distinguish genuine bugs from false alarms."""

    def __init__(self, ollama_service: Optional[OllamaService] = None) -> None:
        self.ollama_service = ollama_service or OllamaService()

    def _build_triage_prompt(
        self,
        finding: NormalizedFinding,
        code_context: str,
        start_line: Optional[int],
        end_line: Optional[int],
    ) -> str:
        line_range = f"{start_line}-{end_line}" if start_line and end_line else str(finding.line_number)
        snippet = code_context.strip() or finding.code_snippet or "No source code available."
        severity_val = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        scanner_val = finding.scanner.value if hasattr(finding.scanner, "value") else str(finding.scanner)

        return (
            f"Evaluate the following security finding:\n\n"
            f"Finding Details:\n"
            f"- Finding ID: {finding.id}\n"
            f"- Scanner: {scanner_val}\n"
            f"- Rule ID: {finding.rule_id}\n"
            f"- Vulnerability: {finding.vulnerability_type}\n"
            f"- Location: {finding.file_path}:{finding.line_number}\n"
            f"- Scanner Message: {finding.message}\n"
            f"- Initial Severity: {severity_val}\n\n"
            f"Source Code (lines {line_range}):\n"
            f"```python\n{snippet}\n```\n\n"
            f"Determine if this is an authentic vulnerability (true positive) or a false alarm. "
            f"Reply using the required JSON format."
        )

    def triage_finding(
        self,
        finding: NormalizedFinding,
        base_dir: Optional[str] = None,
    ) -> TriageResult:
        """Triage an individual finding against its extracted source code context."""
        ctx = extract_code_context(
            file_path=finding.file_path,
            line_number=finding.line_number,
            context_lines=8,
            base_dir=base_dir,
        )

        prompt = self._build_triage_prompt(
            finding=finding,
            code_context=ctx.get("context") or "",
            start_line=ctx.get("start_line"),
            end_line=ctx.get("end_line"),
        )

        logger.info("Triaging %s (%s at %s:%d)", finding.id, finding.vulnerability_type, finding.file_path, finding.line_number)

        try:
            result = self.ollama_service.generate_structured(
                prompt=prompt,
                schema_class=TriageResult,
                system=TRIAGE_SYSTEM_PROMPT,
            )
            # Ensure finding ID matches even if omitted or changed by LLM
            result.finding_id = finding.id
            return result
        except OllamaUnavailableError:
            raise
        except OllamaMalformedResponseError as e:
            logger.warning("Malformed LLM response for %s: %s (falling back cautiously)", finding.id, e)
            return TriageResult(
                finding_id=finding.id,
                is_true_positive=True,
                severity=finding.severity,
                confidence=ConfidenceLevel.LOW,
                reasoning=f"LLM produced malformed response ({e}); keeping scanner alert as fallback.",
                attack_vector_summary=None,
            )
        except OllamaError as e:
            logger.error("Ollama error during triage of %s: %s", finding.id, e)
            return TriageResult(
                finding_id=finding.id,
                is_true_positive=True,
                severity=finding.severity,
                confidence=ConfidenceLevel.LOW,
                reasoning=f"LLM triage failed ({e}); retaining scanner finding.",
                attack_vector_summary=None,
            )

    def triage_all(
        self,
        findings: List[NormalizedFinding],
        base_dir: Optional[str] = None,
    ) -> Tuple[List[TriageResult], List[str]]:
        """Run triage sequentially across all provided findings."""
        results: List[TriageResult] = []
        errors: List[str] = []

        for finding in findings:
            try:
                res = self.triage_finding(finding, base_dir=base_dir)
                results.append(res)
            except OllamaUnavailableError as e:
                # Ollama is offline or unreachable - stop processing further
                msg = f"Triage aborted: {e}"
                logger.error(msg)
                errors.append(msg)
                break
            except Exception as e:
                msg = f"Unexpected error triaging finding {finding.id}: {e}"
                logger.exception(msg)
                errors.append(msg)

        return results, errors
