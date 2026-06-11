"""
Core scanning engine for SkillGuard.
Zero dependencies - uses only Python standard library.
"""

import os
import re
import json
import hashlib
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from .patterns import PATTERNS_DB, get_severity_score, CRITICAL, HIGH, MEDIUM, LOW


class Finding:
    """Represents a single security finding."""

    def __init__(self, pattern, file_path, line_no, matched_text, context=""):
        self.pattern = pattern
        self.file_path = file_path
        self.line_no = line_no
        self.matched_text = matched_text
        self.context = context
        self.severity = pattern.severity
        self.category = pattern.category
        self.pid = pattern.pid
        self.name = pattern.name
        self.confidence = pattern.confidence
        self.recommendation = pattern.recommendation

    def to_dict(self):
        return {
            "pid": self.pid,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file_path,
            "line": self.line_no,
            "match": self.matched_text,
            "context": self.context,
            "recommendation": self.recommendation,
        }


class ScanResult:
    """Aggregated result of a security scan."""

    def __init__(self, target, findings=None, metadata=None):
        self.target = target
        self.findings = findings or []
        self.metadata = metadata or {}
        self.scan_time = datetime.utcnow().isoformat() + "Z"
        self._score = None

    @property
    def score(self):
        if self._score is None:
            self._score = self._calculate_score()
        return self._score

    def _calculate_score(self):
        """Calculate risk score 0-100."""
        base = 0
        executable_multiplier = 1.0
        for f in self.findings:
            base += get_severity_score(f.severity)
            if self._is_executable(f.file_path):
                executable_multiplier = 1.3
        score = int(min(100, base * executable_multiplier))
        return score

    @staticmethod
    def _is_executable(file_path):
        """Check if file is executable."""
        if not file_path:
            return False
        ext = Path(file_path).suffix.lower()
        executable_exts = {'.py', '.sh', '.js', '.ts', '.rb', '.pl', '.bat', '.cmd', '.ps1'}
        return ext in executable_exts

    @property
    def severity_level(self):
        s = self.score
        if s <= 20:
            return "LOW"
        elif s <= 50:
            return "MEDIUM"
        elif s <= 80:
            return "HIGH"
        else:
            return "CRITICAL"

    @property
    def recommendation(self):
        levels = {
            "LOW": "SAFE - No immediate action required.",
            "MEDIUM": "CAUTION - Review findings before installation.",
            "HIGH": "DO NOT INSTALL - Significant security risks detected.",
            "CRITICAL": "DO NOT INSTALL - Critical vulnerabilities present.",
        }
        return levels.get(self.severity_level, "Review findings carefully.")

    def summary(self):
        """Return summary statistics."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cats = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            cats[f.category] = cats.get(f.category, 0) + 1
        return {
            "total_findings": len(self.findings),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "score": self.score,
            "severity_level": self.severity_level,
            "categories": cats,
            "files_scanned": self.metadata.get("files_scanned", 0),
            "lines_scanned": self.metadata.get("lines_scanned", 0),
        }

    def to_dict(self):
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "score": self.score,
            "severity_level": self.severity_level,
            "recommendation": self.recommendation,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_sarif(self):
        """Generate SARIF 2.1.0 format output."""
        rules = []
        results = []
        rule_ids = set()

        for f in self.findings:
            if f.pid not in rule_ids:
                rule_ids.add(f.pid)
                rules.append({
                    "id": f.pid,
                    "name": f.name,
                    "shortDescription": {"text": f.pattern.description},
                    "defaultConfiguration": {"level": f.severity.lower()},
                })

            results.append({
                "ruleId": f.pid,
                "level": f.severity.lower(),
                "message": {"text": f"{f.name}: {f.matched_text}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {
                            "startLine": f.line_no,
                            "snippet": {"text": f.context},
                        }
                    }
                }]
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SkillGuard",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/gitstq/SkillGuard-CLI",
                    }
                },
                "results": results,
                "taxonomies": [{
                    "name": "SkillGuard Rules",
                    "version": "1.0.0",
                    "taxa": [{"id": r["id"], "name": r["name"]} for r in rules],
                }],
            }]
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def to_markdown(self):
        """Generate Markdown report."""
        s = self.summary()
        lines = [
            "# SkillGuard Security Report",
            "",
            f"**Target:** `{self.target}`  ",
            f"**Scan Time:** {self.scan_time}  ",
            f"**Risk Score:** {self.score}/100  ",
            f"**Severity:** {self.severity_level}  ",
            f"**Recommendation:** {self.recommendation}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Findings | {s['total_findings']} |",
            f"| Critical | {s['critical']} |",
            f"| High | {s['high']} |",
            f"| Medium | {s['medium']} |",
            f"| Low | {s['low']} |",
            f"| Files Scanned | {s['files_scanned']} |",
            f"| Lines Scanned | {s['lines_scanned']} |",
            "",
            "## Findings",
            "",
        ]

        for f in self.findings:
            lines.extend([
                f"### [{f.severity}] {f.pid} - {f.name}",
                "",
                f"- **Category:** {f.category}",
                f"- **File:** `{f.file_path}` (Line {f.line_no})",
                f"- **Match:** `{f.matched_text}`",
                f"- **Confidence:** {f.confidence}%",
                f"- **Context:** `{f.context}`",
                f"- **Recommendation:** {f.recommendation}",
                "",
            ])

        return "\n".join(lines)


class SkillScanner:
    """Main scanner engine."""

    # File extensions to scan
    SCAN_EXTENSIONS = {
        '.md', '.txt', '.py', '.js', '.ts', '.sh', '.yaml', '.yml',
        '.json', '.toml', '.ini', '.cfg', '.rb', '.pl', '.bat', '.cmd',
        '.ps1', '.skill', '.agent', '.mcp', '.prompt',
    }

    # Files to skip
    SKIP_FILES = {
        '.gitignore', 'license', 'LICENSE', 'readme.md', 'README.md',
        'changelog.md', 'CHANGELOG.md', 'contributing.md', 'CONTRIBUTING.md',
        '.DS_Store', 'Thumbs.db',
    }

    # Directories to skip
    SKIP_DIRS = {
        '.git', '.github', '.vscode', 'node_modules', '__pycache__',
        '.venv', 'venv', 'env', 'dist', 'build', '.pytest_cache',
        '.mypy_cache', '.tox', '.eggs', '*.egg-info',
    }

    def __init__(self, patterns=None):
        self.patterns = patterns or PATTERNS_DB

    def scan_path(self, path, recursive=True):
        """Scan a file or directory."""
        target = str(path)
        p = Path(path)

        if p.is_file():
            findings, meta = self._scan_file(p)
            result = ScanResult(target, findings, meta)
            return result

        if p.is_dir():
            all_findings = []
            total_files = 0
            total_lines = 0
            for fp in self._walk_files(p, recursive):
                findings, meta = self._scan_file(fp)
                all_findings.extend(findings)
                total_files += meta.get("files_scanned", 1)
                total_lines += meta.get("lines_scanned", 0)
            result = ScanResult(
                target, all_findings,
                {"files_scanned": total_files, "lines_scanned": total_lines}
            )
            return result

        raise ValueError(f"Path not found: {path}")

    def scan_text(self, text, file_path="<inline>"):
        """Scan raw text content."""
        findings = []
        lines = text.split('\n')
        for pattern in self.patterns:
            matches = pattern.match(text)
            for line_no, matched_text, _ in matches:
                context = self._get_context(lines, line_no)
                finding = Finding(pattern, file_path, line_no, matched_text, context)
                findings.append(finding)
        meta = {"files_scanned": 1, "lines_scanned": len(lines)}
        return ScanResult(file_path, findings, meta)

    def _scan_file(self, file_path):
        """Scan a single file."""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return findings, {"files_scanned": 0, "lines_scanned": 0}

        lines = content.split('\n')
        for pattern in self.patterns:
            matches = pattern.match(content)
            for line_no, matched_text, _ in matches:
                context = self._get_context(lines, line_no)
                finding = Finding(
                    pattern, str(file_path), line_no, matched_text, context
                )
                findings.append(finding)

        meta = {"files_scanned": 1, "lines_scanned": len(lines)}
        return findings, meta

    def _walk_files(self, root, recursive=True):
        """Yield files to scan."""
        if recursive:
            for p in root.rglob('*'):
                if p.is_file() and self._should_scan(p):
                    yield p
        else:
            for p in root.iterdir():
                if p.is_file() and self._should_scan(p):
                    yield p

    def _should_scan(self, path):
        """Determine if a file should be scanned."""
        name = path.name.lower()
        if name in self.SKIP_FILES:
            return False
        if path.suffix.lower() not in self.SCAN_EXTENSIONS:
            return False
        for part in path.parts:
            if part in self.SKIP_DIRS:
                return False
        return True

    @staticmethod
    def _get_context(lines, line_no, context_lines=1):
        """Get surrounding context for a line."""
        start = max(0, line_no - context_lines - 1)
        end = min(len(lines), line_no + context_lines)
        ctx = lines[start:end]
        return " | ".join(ctx).strip()[:150]

    @staticmethod
    def detect_skill_format(file_path, content=""):
        """Detect the AI agent skill format."""
        path_str = str(file_path).lower()

        if 'claude' in path_str or 'claude-code' in path_str:
            return "Claude Code Skill"
        if 'cursor' in path_str:
            return "Cursor Skill"
        if 'windsurf' in path_str:
            return "Windsurf Skill"
        if 'copilot' in path_str:
            return "GitHub Copilot Skill"
        if 'codex' in path_str:
            return "OpenAI Codex Skill"
        if 'gemini' in path_str:
            return "Gemini CLI Skill"
        if '.mcp' in path_str or 'mcp' in path_str:
            return "MCP Server"
        if 'skill.md' in path_str or 'skills' in path_str:
            return "Generic Skill"

        # Content-based detection
        if content:
            if 'claude' in content.lower()[:500]:
                return "Claude Code Skill"
            if 'mcp' in content.lower()[:500]:
                return "MCP Server"

        return "Unknown"
