"""Bandit static security analysis service adapter for Python codebases."""

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


class BanditError(Exception):
    """Raised when Bandit encounters an execution or configuration error."""
    pass


class BanditService:
    """Adapter for running Bandit security scans on Python source code."""

    def __init__(self, executable_path: str = "bandit") -> None:
        self.executable_path = executable_path

    def _resolve_executable(self) -> str:
        """Resolve executable path, handling platform-specific binary locations."""
        resolved = shutil.which(self.executable_path)
        if not resolved:
            raise BanditError(
                f"Bandit executable '{self.executable_path}' not found on PATH. "
                "Ensure bandit is installed and accessible."
            )
        return resolved

    def _map_severity(self, bandit_severity: str) -> Severity:
        """Map Bandit severity string to normalized Severity enum."""
        mapping = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "UNDEFINED": Severity.INFO,
        }
        return mapping.get(bandit_severity.upper(), Severity.MEDIUM)

    def _extract_vulnerability_type(self, test_id: str, test_name: str) -> str:
        """Derive readable vulnerability category from Bandit test ID and name."""
        name_lower = test_name.lower()
        id_upper = test_id.upper()

        if "sql" in name_lower or id_upper in ("B608",):
            return "SQL Injection"
        elif "password" in name_lower or "token" in name_lower or "key" in name_lower or id_upper in ("B105", "B106", "B107"):
            return "Hardcoded Secret"
        elif "subprocess" in name_lower or "shell" in name_lower or "exec" in name_lower or id_upper in ("B602", "B603", "B604", "B605", "B606", "B607"):
            return "Command Injection"
        elif "pickle" in name_lower or "yaml_load" in name_lower or id_upper in ("B301", "B506"):
            return "Unsafe Deserialization"
        elif "hash" in name_lower or "md5" in name_lower or "sha1" in name_lower or id_upper in ("B303", "B324"):
            return "Weak Cryptography"
        elif "eval" in name_lower or id_upper in ("B307",):
            return "Dangerous Function Usage (eval)"
        elif "assert" in name_lower or id_upper in ("B101",):
            return "Improper Verification (Assert Used)"
        elif "xml" in name_lower:
            return "XML Entity Injection"

        # Fallback to test_name formatted
        return test_name.replace("_", " ").title()

    def run_scan(
        self,
        target_path: str,
        timeout_seconds: int = 120,
    ) -> List[NormalizedFinding]:
        """Execute Bandit scan against target path and return normalized findings.

        Args:
            target_path: File or directory path to scan.
            timeout_seconds: Process execution timeout.

        Returns:
            List of normalized security findings.

        Raises:
            BanditError: If scanner fails, repository path is invalid, or output is malformed.
        """
        target = Path(target_path)
        if not target.exists():
            raise BanditError(f"Target path does not exist: {target_path}")

        executable = self._resolve_executable()

        # Build command arguments safely without shell strings
        cmd = [executable, "-f", "json", "-q"]
        if target.is_dir():
            cmd.extend(["-r", str(target.resolve())])
        else:
            cmd.append(str(target.resolve()))

        logger.info("Executing Bandit: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BanditError(f"Bandit scan timed out after {timeout_seconds} seconds") from exc
        except Exception as exc:
            raise BanditError(f"Failed to execute Bandit process: {exc}") from exc

        # Bandit returns 0 (clean), 1 (issues found), or 2 (fatal syntax/config error)
        raw_output = result.stdout.strip()
        if not raw_output and result.returncode > 1:
            raise BanditError(
                f"Bandit failed with exit code {result.returncode}: {result.stderr.strip()}"
            )

        if not raw_output:
            logger.info("Bandit returned empty stdout")
            return []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise BanditError(
                f"Malformed Bandit JSON output: {exc}. Raw stdout was: {raw_output[:200]}"
            ) from exc

        bandit_results = data.get("results", [])
        findings: List[NormalizedFinding] = []

        for item in bandit_results:
            try:
                test_id = item.get("test_id", "unknown-rule")
                test_name = item.get("test_name", "unknown")
                filename = item.get("filename", "")
                line_no = item.get("line_number", 1)
                line_range = item.get("line_range", [])
                end_line_no = line_range[-1] if line_range else None
                message = item.get("issue_text", "Security issue detected by Bandit")
                raw_severity = item.get("issue_severity", "MEDIUM")
                code_snippet = item.get("code")

                # Extract CWE if available
                cwe_info = item.get("issue_cwe", {})
                cwe_id = None
                if isinstance(cwe_info, dict) and "id" in cwe_info:
                    cwe_id = f"CWE-{cwe_info['id']}"

                id_basis = f"bandit:{filename}:{line_no}:{test_id}"
                finding_id = f"bandit-{hashlib.sha256(id_basis.encode()).hexdigest()[:12]}"

                finding = NormalizedFinding(
                    id=finding_id,
                    scanner=ScannerType.BANDIT,
                    rule_id=test_id,
                    vulnerability_type=self._extract_vulnerability_type(test_id, test_name),
                    file_path=filename,
                    line_number=max(1, int(line_no)),
                    end_line_number=int(end_line_no) if end_line_no else None,
                    message=message,
                    severity=self._map_severity(raw_severity),
                    code_snippet=code_snippet.strip() if code_snippet else None,
                    cwe=cwe_id,
                )
                findings.append(finding)
            except Exception as item_err:
                logger.warning("Skipping malformed Bandit finding entry: %s", item_err)
                continue

        logger.info("Bandit scan identified %d normalized findings", len(findings))
        return findings
