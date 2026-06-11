"""
Command-line interface for SkillGuard.
Zero dependencies - uses only Python standard library.
"""

import argparse
import sys
import os
import json
from pathlib import Path

from .scanner import SkillScanner, ScanResult
from .tui import TUI
from .patterns import PATTERNS_DB, CRITICAL, HIGH, MEDIUM, LOW
from . import __version__


def create_parser():
    parser = argparse.ArgumentParser(
        prog="skillguard",
        description="🛡️ SkillGuard - Lightweight AI Agent Skill Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  skillguard scan ./my-skill/              Scan a local skill directory
  skillguard scan ./SKILL.md               Scan a single skill file
  skillguard scan ./my-skill/ --json       Output JSON report
  skillguard scan ./my-skill/ --sarif      Output SARIF report
  skillguard scan ./my-skill/ --markdown   Output Markdown report
  skillguard scan ./my-skill/ -o report.md Save report to file
  skillguard scan ./my-skill/ --severity HIGH  Only show HIGH and above
  skillguard scan ./my-skill/ --no-tui     Disable TUI, plain text output

For more info: https://github.com/gitstq/SkillGuard-CLI
        """
    )
    parser.add_argument("--version", action="version", version=f"SkillGuard {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a skill file or directory")
    scan_parser.add_argument("target", help="Path to skill file or directory")
    scan_parser.add_argument("--format", "-f", choices=["terminal", "json", "sarif", "markdown"],
                             default="terminal", help="Output format")
    scan_parser.add_argument("--output", "-o", help="Output file path")
    scan_parser.add_argument("--severity", "-s", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                             default="LOW", help="Minimum severity to report")
    scan_parser.add_argument("--no-tui", action="store_true", help="Disable TUI dashboard")
    scan_parser.add_argument("--no-recursive", action="store_true", help="Disable recursive scanning")
    scan_parser.add_argument("--category", help="Filter by category")

    # list command
    list_parser = subparsers.add_parser("list", help="List all vulnerability patterns")
    list_parser.add_argument("--category", "-c", help="Filter by category")
    list_parser.add_argument("--severity", "-s", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                             help="Filter by severity")

    # info command
    info_parser = subparsers.add_parser("info", help="Show scanner information")

    return parser


def filter_findings(result, min_severity="LOW", category=None):
    """Filter findings by severity and category."""
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_level = severity_order.get(min_severity, 1)

    filtered = []
    for f in result.findings:
        f_level = severity_order.get(f.severity, 0)
        if f_level < min_level:
            continue
        if category and f.category != category:
            continue
        filtered.append(f)

    result.findings = filtered
    result._score = None  # reset cached score
    return result


def format_terminal_plain(result):
    """Plain text terminal output (no TUI)."""
    lines = []
    s = result.summary()
    lines.append(f"SkillGuard Security Report v{__version__}")
    lines.append(f"Target: {result.target}")
    lines.append(f"Score: {result.score}/100 | Severity: {result.severity_level}")
    lines.append(f"Findings: {s['total_findings']} (C:{s['critical']} H:{s['high']} M:{s['medium']} L:{s['low']})")
    lines.append("")

    for f in result.findings:
        lines.append(f"[{f.severity}] {f.pid} - {f.name}")
        lines.append(f"  Category: {f.category}")
        lines.append(f"  File: {f.file_path}:{f.line_no}")
        lines.append(f"  Match: {f.matched_text[:100]}")
        lines.append(f"  Confidence: {f.confidence}%")
        if f.recommendation:
            lines.append(f"  Fix: {f.recommendation}")
        lines.append("")

    return "\n".join(lines)


def cmd_scan(args):
    """Execute scan command."""
    target = args.target

    if not os.path.exists(target):
        print(f"Error: Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    scanner = SkillScanner()
    tui = TUI()

    # Show scanning progress if TUI enabled
    if not args.no_tui and args.format == "terminal":
        tui.clear()
        tui.header("🛡️  SkillGuard - Scanning")
        print(f"\n  Scanning: {target}")
        print(f"  Please wait...")

    result = scanner.scan_path(target, recursive=not args.no_recursive)
    result = filter_findings(result, args.severity, args.category)

    # Generate output
    if args.format == "json":
        output = result.to_json()
    elif args.format == "sarif":
        output = result.to_sarif()
    elif args.format == "markdown":
        output = result.to_markdown()
    else:
        if args.no_tui:
            output = format_terminal_plain(result)
        else:
            tui.render_report(result)
            output = None

    if output:
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Report saved to: {args.output}")
        else:
            print(output)

    # Exit with non-zero if critical/high findings
    s = result.summary()
    if s['critical'] > 0 or s['high'] > 0:
        sys.exit(2)
    elif s['medium'] > 0:
        sys.exit(1)


def cmd_list(args):
    """Execute list command."""
    patterns = PATTERNS_DB
    if args.category:
        patterns = [p for p in patterns if p.category == args.category]
    if args.severity:
        patterns = [p for p in patterns if p.severity == args.severity]

    tui = TUI()
    tui.header("🛡️  SkillGuard - Vulnerability Patterns")
    print(f"\n  Total patterns: {len(patterns)}\n")

    for p in patterns:
        badge = tui.badge(p.severity, p.severity)
        print(f"  {badge} {p.pid} - {p.name}")
        print(f"     Category: {p.category}")
        print(f"     {p.description}")
        print()


def cmd_info(args):
    """Execute info command."""
    tui = TUI()
    tui.header("🛡️  SkillGuard - Scanner Information")
    print(f"""
  Version:        {__version__}
  License:        MIT
  Author:         SkillGuard Team
  Repository:     https://github.com/gitstq/SkillGuard-CLI

  Patterns:       {len(PATTERNS_DB)}
  Categories:     {len(set(p.category for p in PATTERNS_DB))}
  Severities:     CRITICAL, HIGH, MEDIUM, LOW

  Supported Formats:
    - Claude Code Skills
    - Cursor Skills
    - Windsurf Skills
    - GitHub Copilot Skills
    - OpenAI Codex Skills
    - Gemini CLI Skills
    - MCP Servers
    - Generic Skill Files

  Output Formats:
    - Terminal (TUI)
    - JSON
    - SARIF 2.1.0
    - Markdown
""")


def main():
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "info":
        cmd_info(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
