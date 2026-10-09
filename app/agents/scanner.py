"""Deterministic security scanner agent coordinating Semgrep and Bandit."""

import logging
from pathlib import Path
from typing import List, Optional, Tuple

from app.config import get_settings
from app.models.schemas import NormalizedFinding
from app.services.bandit import BanditError, BanditService
from app.services.semgrep import SemgrepError, SemgrepService

logger = logging.getLogger(__name__)


class ScannerAgent:
    """Agent 1: Executes deterministic static analysis tools and aggregates findings."""

    def __init__(
        self,
        semgrep_service: Optional[SemgrepService] = None,
        bandit_service: Optional[BanditService] = None,
    ) -> None:
        settings = get_settings()
        self.semgrep_service = semgrep_service or SemgrepService(settings.semgrep_path)
        self.bandit_service = bandit_service or BanditService(settings.bandit_path)

    def scan(
        self,
        target_path: str,
        include_semgrep: bool = True,
        include_bandit: bool = True,
    ) -> Tuple[List[NormalizedFinding], List[str]]:
        """Run configured static analysis scanners on target directory/file.

        Args:
            target_path: Path to codebase or file to scan.
            include_semgrep: Whether to run Semgrep engine.
            include_bandit: Whether to run Bandit engine.

        Returns:
            Tuple of (aggregated normalized findings, list of scanner error messages).
        """
        findings: List[NormalizedFinding] = []
        errors: List[str] = []

        path_obj = Path(target_path)
        if not path_obj.exists():
            error_msg = f"Target repository path does not exist: {target_path}"
            logger.error(error_msg)
            return [], [error_msg]

        # 1. Execute Semgrep scan
        if include_semgrep:
            try:
                semgrep_findings = self.semgrep_service.run_scan(target_path)
                findings.extend(semgrep_findings)
            except SemgrepError as exc:
                msg = f"Semgrep scan failed: {exc}"
                logger.error(msg)
                errors.append(msg)
            except Exception as exc:
                msg = f"Unexpected error during Semgrep execution: {exc}"
                logger.exception(msg)
                errors.append(msg)

        # 2. Execute Bandit scan (for Python files)
        if include_bandit:
            # Check if directory contains python files or target itself is python
            has_py = False
            if path_obj.is_file() and path_obj.suffix == ".py":
                has_py = True
            elif path_obj.is_dir():
                has_py = any(path_obj.glob("**/*.py"))

            if has_py:
                try:
                    bandit_findings = self.bandit_service.run_scan(target_path)
                    findings.extend(bandit_findings)
                except BanditError as exc:
                    msg = f"Bandit scan failed: {exc}"
                    logger.error(msg)
                    errors.append(msg)
                except Exception as exc:
                    msg = f"Unexpected error during Bandit execution: {exc}"
                    logger.exception(msg)
                    errors.append(msg)
            else:
                logger.info("No Python files detected, skipping Bandit scan")

        logger.info(
            "Scanner agent completed with %d findings and %d errors",
            len(findings),
            len(errors),
        )
        return findings, errors
