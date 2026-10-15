"""Static analysis scanner agent orchestrating Semgrep and Bandit."""

import logging
from pathlib import Path
from typing import List, Optional, Tuple

from app.config import get_settings
from app.models.schemas import NormalizedFinding
from app.services.bandit import BanditError, BanditService
from app.services.semgrep import SemgrepError, SemgrepService

logger = logging.getLogger(__name__)


def _has_python_files(path: Path) -> bool:
    """Check if target path is a Python file or contains any .py files."""
    if path.is_file():
        return path.suffix.lower() == ".py"
    return any(path.rglob("*.py"))


class ScannerAgent:
    """Coordinates static analysis scanners and consolidates findings."""

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
        """Run enabled scanners against target directory or file."""
        findings: List[NormalizedFinding] = []
        errors: List[str] = []

        target = Path(target_path)
        if not target.exists():
            msg = f"Target repository path does not exist: {target_path}"
            logger.error(msg)
            return [], [msg]

        # Semgrep scan
        if include_semgrep:
            try:
                semgrep_findings = self.semgrep_service.run_scan(target_path)
                findings.extend(semgrep_findings)
            except SemgrepError as e:
                err_msg = f"Semgrep scan failed: {e}"
                logger.error(err_msg)
                errors.append(err_msg)
            except Exception as e:
                err_msg = f"Unexpected error during Semgrep execution: {e}"
                logger.exception(err_msg)
                errors.append(err_msg)

        # Bandit scan (Python-only)
        if include_bandit:
            if _has_python_files(target):
                try:
                    bandit_findings = self.bandit_service.run_scan(target_path)
                    findings.extend(bandit_findings)
                except BanditError as e:
                    err_msg = f"Bandit scan failed: {e}"
                    logger.error(err_msg)
                    errors.append(err_msg)
                except Exception as e:
                    err_msg = f"Unexpected error during Bandit execution: {e}"
                    logger.exception(err_msg)
                    errors.append(err_msg)
            else:
                logger.info("No Python files found in target, skipping Bandit scan")

        logger.info(
            "Scan complete: %d findings, %d errors encountered",
            len(findings),
            len(errors),
        )
        return findings, errors
