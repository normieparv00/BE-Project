"""Data models representing normalized findings, triage judgments, and remediation suggestions."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Normalized security severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConfidenceLevel(str, Enum):
    """Categorical confidence levels for LLM evaluations."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScannerType(str, Enum):
    """Static analysis scanner engines."""

    SEMGREP = "SEMGREP"
    BANDIT = "BANDIT"
    UNKNOWN = "UNKNOWN"


class NormalizedFinding(BaseModel):
    """Unified internal representation of a static security analysis finding."""

    id: str = Field(description="Unique identifier for the finding")
    scanner: ScannerType = Field(description="Scanner tool that produced the finding")
    rule_id: str = Field(description="Scanner-specific rule ID or signature")
    vulnerability_type: str = Field(description="Categorized vulnerability class (e.g., SQL Injection)")
    file_path: str = Field(description="Path to the vulnerable file")
    line_number: int = Field(ge=1, description="Starting line number of finding")
    end_line_number: Optional[int] = Field(default=None, description="Ending line number of finding if available")
    message: str = Field(description="Scanner description or explanation")
    severity: Severity = Field(default=Severity.MEDIUM, description="Normalized severity")
    code_snippet: Optional[str] = Field(default=None, description="Offending code snippet")
    cwe: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID if available")


class TriageResult(BaseModel):
    """Structured security triage assessment produced by the LLM."""

    finding_id: str = Field(description="Identifier of the triaged finding")
    is_true_positive: bool = Field(description="Whether the finding represents a genuine security issue")
    severity: Severity = Field(description="Contextual severity assessed by the triage agent")
    confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.MEDIUM,
        description="Categorical confidence assessment from the LLM",
    )
    confidence_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional calibrated numerical confidence score if available",
    )
    reasoning: str = Field(description="Detailed contextual reasoning explaining the triage decision")
    attack_vector_summary: Optional[str] = Field(
        default=None,
        description="Brief summary of potential exploitability or threat scenario",
    )


class FixSuggestion(BaseModel):
    """Remediation proposal generated for confirmed vulnerabilities."""

    finding_id: str = Field(description="Identifier of the triaged finding")
    vulnerability_type: str = Field(description="Vulnerability category being addressed")
    file_path: str = Field(description="File requiring remediation")
    explanation: str = Field(description="Detailed explanation of why the fix resolves the vulnerability")
    remediation_strategy: str = Field(description="High-level description of the fix approach")
    suggested_code: str = Field(description="Proposed corrected code replacement")
    diff: Optional[str] = Field(default=None, description="Unified diff patch representation if available")


class ReviewRequest(BaseModel):
    """Payload to trigger an automated security code review."""

    target_path: str = Field(description="Local repository or directory path to review")
    include_semgrep: bool = Field(default=True, description="Enable Semgrep analysis")
    include_bandit: bool = Field(default=True, description="Enable Bandit analysis")


class ReviewResult(BaseModel):
    """Final aggregated response for a code review execution."""

    target_path: str
    total_scanner_findings: int = 0
    total_triaged: int = 0
    total_confirmed_vulnerabilities: int = 0
    total_false_positives: int = 0
    findings: List[NormalizedFinding] = Field(default_factory=list)
    triage_results: List[TriageResult] = Field(default_factory=list)
    fix_suggestions: List[FixSuggestion] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    status: str = "completed"
