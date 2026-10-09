"""Semgrep static security analysis service adapter."""

import hashlib
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.models.schemas import NormalizedFinding, ScannerType, Severity

logger = logging.getLogger(__name__)


class SemgrepError(Exception):
    """Raised when Semgrep encounters an execution or configuration error."""
    pass


class SemgrepService:
    """Adapter for running Semgrep security scans and normalizing findings."""

    def __init__(self, executable_path: str = "semgrep") -> None:
        self.executable_path = executable_path

    def _resolve_executable(self) -> str:
        """Resolve executable path, handling platform-specific binary locations."""
        resolved = shutil.which(self.executable_path)
        if not resolved:
            raise SemgrepError(
                f"Semgrep executable '{self.executable_path}' not found on PATH. "
                "Ensure semgrep is installed and accessible."
            )
        return resolved

    def _map_severity(self, semgrep_severity: str) -> Severity:
        """Map Semgrep severity string to normalized Severity enum."""
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
            "EXPERIMENT": Severity.INFO,
        }
        return mapping.get(semgrep_severity.upper(), Severity.MEDIUM)

    def _extract_cwe(self, metadata: Dict[str, Any]) -> Optional[str]:
        """Extract CWE identifier from Semgrep finding metadata if available."""
        cwe = metadata.get("cwe")
        if isinstance(cwe, list) and cwe:
            return str(cwe[0])
        elif isinstance(cwe, str):
            return cwe
        return None

    def _extract_vulnerability_type(self, check_id: str, metadata: Dict[str, Any]) -> str:
        """Derive readable vulnerability category from check ID and metadata."""
        category = metadata.get("category")
        if category and isinstance(category, str):
            return category.replace("-", " ").title()

        check_lower = check_id.lower()
        if "sql" in check_lower:
            return "SQL Injection"
        elif "secret" in check_lower or "credential" in check_lower or "token" in check_lower:
            return "Hardcoded Secret"
        elif "command" in check_lower or "exec" in check_lower or "shell" in check_lower:
            return "Command Injection"
        elif "deserializ" in check_lower or "pickle" in check_lower:
            return "Unsafe Deserialization"
        elif "path" in check_lower or "traversal" in check_lower:
            return "Path Traversal"
        elif "crypto" in check_lower or "hash" in check_lower or "cipher" in check_lower:
            return "Weak Cryptography"
        elif "xss" in check_lower:
            return "Cross-Site Scripting (XSS)"
        elif "auth" in check_lower:
            return "Authentication / Authorization Issue"

        # Fallback to last segment of check_id
        parts = check_id.split(".")
        return parts[-1].replace("-", " ").replace("_", " ").title()

    def run_scan(
        self,
        target_path: str,
        config: str = "auto",
        timeout_seconds: int = 120,
    ) -> List[NormalizedFinding]:
        """Execute Semgrep scan against target path and return normalized findings.

        Args:
            target_path: File or directory path to scan.
            config: Semgrep rule configuration (defaults to 'auto').
            timeout_seconds: Process execution timeout.

        Returns:
            List of normalized security findings.

        Raises:
            SemgrepError: If scanner fails, repository path is invalid, or output is malformed.
        """
        target = Path(target_path)
        if not target.exists():
            raise SemgrepError(f"Target path does not exist: {target_path}")

        executable = self._resolve_executable()

        cmd = [
            executable,
            "scan",
            "--json",
            "--quiet",
            f"--config={config}",
            str(target.resolve()),
        ]

        logger.info("Executing Semgrep: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SemgrepError(f"Semgrep scan timed out after {timeout_seconds} seconds") from exc
        except Exception as exc:
            raise SemgrepError(f"Failed to execute Semgrep process: {exc}") from exc

        # Semgrep returns exit code 0 or 1 (on finding issues or minor warnings).
        # Exit codes > 1 usually indicate a fatal configuration error.
        raw_output = result.stdout.strip()
        if not raw_output and result.returncode > 1:
            raise SemgrepError(
                f"Semgrep failed with exit code {result.returncode}: {result.stderr.strip()}"
            )

        if not raw_output:
            logger.info("Semgrep returned empty stdout")
            return []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise SemgrepError(
                f"Malformed Semgrep JSON output: {exc}. Raw stdout was: {raw_output[:200]}"
            ) from exc

        semgrep_results = data.get("results", [])
        findings: List[NormalizedFinding] = []

        for item in semgrep_results:
            try:
                check_id = item.get("check_id", "unknown-rule")
                path_str = item.get("path", "")
                start_obj = item.get("start", {})
                end_obj = item.get("end", {})
                line_no = start_obj.get("line", 1)
                end_line_no = end_obj.get("line")
                extra = item.get("extra", {})
                message = extra.get("message", "Security issue detected by Semgrep")
                raw_severity = extra.get("severity", "WARNING")
                lines_snippet = extra.get("lines")
                metadata = extra.get("metadata", {})

                # Generate deterministic finding ID
                id_basis = f"semgrep:{path_str}:{line_no}:{check_id}"
                finding_id = f"semgrep-{hashlib.sha256(id_basis.encode()).hexdigest()[:12]}"

                finding = NormalizedFinding(
                    id=finding_id,
                    scanner=ScannerType.SEMGREP,
                    rule_id=check_id,
                    vulnerability_type=self._extract_vulnerability_type(check_id, metadata),
                    file_path=path_str,
                    line_number=max(1, int(line_no)),
                    end_line_number=int(end_line_no) if end_line_no else None,
                    message=message,
                    severity=self._map_severity(raw_severity),
                    code_snippet=lines_snippet.strip() if lines_snippet else None,
                    cwe=self._extract_cwe(metadata),
                )
                findings.append(finding)
            except Exception as item_err:
                logger.warning("Skipping malformed Semgrep finding entry: %s", item_err)
                continue

        logger.info("Semgrep scan identified %d normalized findings", len(findings))
        return findings
