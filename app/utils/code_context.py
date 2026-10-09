"""Safe file reading and source code context extraction."""

from pathlib import Path
from typing import Dict, Optional, Tuple


def extract_code_context(
    file_path: str,
    line_number: int,
    context_lines: int = 8,
    base_dir: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """Safely extracts surrounding source code lines around a target line number.

    Args:
        file_path: Relative or absolute path to the file.
        line_number: 1-indexed target line number.
        context_lines: Number of lines to capture before and after target line.
        base_dir: Optional base directory to resolve relative file paths.

    Returns:
        Dict with keys:
            'context': Formatted line-numbered string snippet.
            'raw_code': Raw un-numbered string snippet.
            'start_line': First line included (1-indexed).
            'end_line': Last line included (1-indexed).
    """
    path_obj = Path(file_path)
    if not path_obj.is_absolute() and base_dir:
        path_obj = Path(base_dir) / path_obj

    if not path_obj.exists() or not path_obj.is_file():
        return {
            "context": None,
            "raw_code": None,
            "start_line": None,
            "end_line": None,
        }

    try:
        content = path_obj.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {
            "context": None,
            "raw_code": None,
            "start_line": None,
            "end_line": None,
        }

    lines = content.splitlines()
    total_lines = len(lines)
    if total_lines == 0:
        return {
            "context": "",
            "raw_code": "",
            "start_line": 1,
            "end_line": 1,
        }

    target_idx = max(0, line_number - 1)
    start_idx = max(0, target_idx - context_lines)
    end_idx = min(total_lines, target_idx + context_lines + 1)

    selected_lines = lines[start_idx:end_idx]
    formatted = []
    for offset, line_text in enumerate(selected_lines):
        curr_line = start_idx + offset + 1
        marker = ">> " if curr_line == line_number else "   "
        formatted.append(f"{marker}{curr_line:4d} | {line_text}")

    return {
        "context": "\n".join(formatted),
        "raw_code": "\n".join(selected_lines),
        "start_line": start_idx + 1,
        "end_line": end_idx,
    }
