"""
Unified diff parser — maps diff hunks to correct new-file line numbers.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class DiffFile:
    filename: str
    old_filename: str
    status: str  # added, modified, deleted, renamed
    hunks: list["DiffHunk"] = field(default_factory=list)
    language: str = "unknown"


@dataclass
class DiffHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list["DiffLine"] = field(default_factory=list)


@dataclass
class DiffLine:
    kind: str  # context, added, deleted
    content: str
    old_lineno: int | None
    new_lineno: int | None


LANGUAGE_MAP = {
    "py": "python", "js": "javascript", "ts": "typescript",
    "jsx": "javascript", "tsx": "typescript", "java": "java",
    "go": "go", "rb": "ruby", "cs": "csharp", "php": "php",
}


class DiffParser:
    HUNK_HEADER = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    FILE_HEADER_OLD = re.compile(r"^--- a/(.+)$")
    FILE_HEADER_NEW = re.compile(r"^\+\+\+ b/(.+)$")

    # `--- /dev/null` marks a newly added file and has no `a/` prefix, so it
    # needs its own pattern rather than being matched by FILE_HEADER_OLD.
    FILE_HEADER_OLD_ANY = re.compile(r"^--- (?:a/)?(.+)$")

    def parse(self, diff_text: str) -> list[DiffFile]:
        """Parse unified diff text into structured DiffFile objects."""
        files: list[DiffFile] = []
        current_file: DiffFile | None = None
        current_hunk: DiffHunk | None = None
        old_lineno = 0
        new_lineno = 0
        # Carries the `---` line across to the `+++` line that follows it. The
        # previous version assigned this to a local and then read a
        # `self._last_old` attribute that was never set, so `old_filename`
        # always mirrored the new name and `status` was never "added".
        pending_old: str | None = None

        for line in diff_text.splitlines():
            # File header
            m_old = self.FILE_HEADER_OLD_ANY.match(line)
            if m_old:
                pending_old = m_old.group(1).strip()
                continue

            m_new = self.FILE_HEADER_NEW.match(line)
            if m_new:
                new_name = m_new.group(1)
                ext = new_name.rsplit(".", 1)[-1].lower() if "." in new_name else ""
                lang = LANGUAGE_MAP.get(ext, "unknown")
                old_name_clean = pending_old if pending_old is not None else new_name
                pending_old = None
                if old_name_clean == "/dev/null":
                    status = "added"
                elif old_name_clean != new_name:
                    status = "renamed"
                else:
                    status = "modified"
                current_file = DiffFile(
                    filename=new_name,
                    old_filename=old_name_clean,
                    status=status,
                    language=lang,
                )
                files.append(current_file)
                current_hunk = None
                continue

            # Hunk header
            m_hunk = self.HUNK_HEADER.match(line)
            if m_hunk and current_file:
                old_start = int(m_hunk.group(1))
                new_start = int(m_hunk.group(3))
                current_hunk = DiffHunk(
                    old_start=old_start,
                    old_count=int(m_hunk.group(2) or 1),
                    new_start=new_start,
                    new_count=int(m_hunk.group(4) or 1),
                )
                current_file.hunks.append(current_hunk)
                old_lineno = old_start
                new_lineno = new_start
                continue

            if current_hunk is None:
                continue

            if line.startswith("+") and not line.startswith("+++"):
                current_hunk.lines.append(DiffLine("added", line[1:], None, new_lineno))
                new_lineno += 1
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk.lines.append(DiffLine("deleted", line[1:], old_lineno, None))
                old_lineno += 1
            elif line.startswith(" "):
                current_hunk.lines.append(DiffLine("context", line[1:], old_lineno, new_lineno))
                old_lineno += 1
                new_lineno += 1

        return files

    def get_changed_line_numbers(self, diff_file: DiffFile) -> set[int]:
        """Return set of new-file line numbers that were added/modified."""
        changed = set()
        for hunk in diff_file.hunks:
            for dl in hunk.lines:
                if dl.kind == "added" and dl.new_lineno:
                    changed.add(dl.new_lineno)
        return changed

    def extract_added_code(self, diff_file: DiffFile) -> str:
        """Extract only added lines as a code block."""
        lines = []
        for hunk in diff_file.hunks:
            for dl in hunk.lines:
                if dl.kind in ("added", "context"):
                    lines.append(dl.content)
        return "\n".join(lines)
