"""
Terminal User Interface for SkillGuard.
Zero dependencies - uses only ANSI escape codes.
"""

import sys
import shutil


class Colors:
    """ANSI color codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


class TUI:
    """Simple TUI renderer."""

    def __init__(self):
        self.term_width = shutil.get_terminal_size().columns
        self.term_height = shutil.get_terminal_size().lines

    def clear(self):
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

    def header(self, text):
        width = self.term_width
        pad = (width - len(text) - 4) // 2
        line = "=" * width
        print(f"{Colors.CYAN}{line}{Colors.RESET}")
        print(f"{Colors.CYAN}{' ' * pad}  {Colors.BOLD}{text}{Colors.RESET}{Colors.CYAN}  {' ' * pad}{Colors.RESET}")
        print(f"{Colors.CYAN}{line}{Colors.RESET}")

    def section(self, text):
        print(f"\n{Colors.BOLD}{Colors.BLUE}▶ {text}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * min(60, self.term_width)}{Colors.RESET}")

    def success(self, text):
        print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

    def warning(self, text):
        print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

    def error(self, text):
        print(f"{Colors.RED}✗ {text}{Colors.RESET}")

    def info(self, text):
        print(f"{Colors.BLUE}ℹ {text}{Colors.RESET}")

    def badge(self, text, color):
        colors = {
            "CRITICAL": Colors.BG_RED + Colors.WHITE + Colors.BOLD,
            "HIGH": Colors.RED + Colors.BOLD,
            "MEDIUM": Colors.YELLOW + Colors.BOLD,
            "LOW": Colors.GREEN + Colors.BOLD,
            "SAFE": Colors.GREEN + Colors.BOLD,
            "CAUTION": Colors.YELLOW + Colors.BOLD,
        }
        c = colors.get(color, Colors.BLUE)
        return f"{c}[{text}]{Colors.RESET}"

    def progress_bar(self, current, total, width=40):
        if total == 0:
            return ""
        ratio = current / total
        filled = int(width * ratio)
        bar = "█" * filled + "░" * (width - filled)
        pct = int(ratio * 100)
        return f"{Colors.CYAN}[{bar}]{Colors.RESET} {pct}%"

    def render_score_gauge(self, score):
        """Render ASCII score gauge."""
        width = 40
        filled = int(width * score / 100)
        if score <= 20:
            color = Colors.GREEN
        elif score <= 50:
            color = Colors.YELLOW
        elif score <= 80:
            color = Colors.RED
        else:
            color = Colors.BG_RED + Colors.WHITE + Colors.BOLD

        bar = color + "█" * filled + Colors.DIM + "░" * (width - filled) + Colors.RESET
        return f"{bar} {color}{score}/100{Colors.RESET}"

    def render_report(self, result):
        """Render a full scan report in TUI."""
        self.clear()
        self.header("🛡️  SkillGuard Security Report")

        s = result.summary()

        print(f"\n  {Colors.DIM}Target:{Colors.RESET}     {Colors.BOLD}{result.target}{Colors.RESET}")
        print(f"  {Colors.DIM}Scan Time:{Colors.RESET}  {result.scan_time}")
        print(f"  {Colors.DIM}Files:{Colors.RESET}      {s['files_scanned']}")
        print(f"  {Colors.DIM}Lines:{Colors.RESET}      {s['lines_scanned']}")

        print(f"\n  {Colors.BOLD}Risk Score:{Colors.RESET}  {self.render_score_gauge(result.score)}")
        print(f"  {Colors.BOLD}Severity:{Colors.RESET}    {self.badge(result.severity_level, result.severity_level)}")
        print(f"  {Colors.BOLD}Verdict:{Colors.RESET}     {result.recommendation}")

        self.section("Finding Summary")
        print(f"  {self.badge('CRITICAL', 'CRITICAL')} : {s['critical']}")
        print(f"  {self.badge('HIGH', 'HIGH')}     : {s['high']}")
        print(f"  {self.badge('MEDIUM', 'MEDIUM')}   : {s['medium']}")
        print(f"  {self.badge('LOW', 'LOW')}      : {s['low']}")

        if result.findings:
            self.section("Detailed Findings")
            for i, f in enumerate(result.findings, 1):
                badge = self.badge(f.severity, f.severity)
                print(f"\n  {Colors.DIM}[{i}/{len(result.findings)}]{Colors.RESET} {badge} {Colors.BOLD}{f.pid} - {f.name}{Colors.RESET}")
                print(f"     {Colors.DIM}Category:{Colors.RESET} {f.category}")
                print(f"     {Colors.DIM}File:{Colors.RESET}     {f.file_path}:{f.line_no}")
                print(f"     {Colors.DIM}Match:{Colors.RESET}    {Colors.YELLOW}{f.matched_text[:80]}{Colors.RESET}")
                print(f"     {Colors.DIM}Confidence:{Colors.RESET} {f.confidence}%")
                if f.recommendation:
                    print(f"     {Colors.DIM}Fix:{Colors.RESET}      {Colors.GREEN}{f.recommendation}{Colors.RESET}")
        else:
            self.section("Result")
            self.success("No security issues detected!")

        print(f"\n{Colors.DIM}{'=' * min(60, self.term_width)}{Colors.RESET}")
        print(f"{Colors.DIM}  SkillGuard v1.0.0 | https://github.com/gitstq/SkillGuard-CLI{Colors.RESET}")
        print()

    def render_scanning(self, current_file, total_files, current_path):
        """Render scanning progress."""
        self.clear()
        self.header("🛡️  SkillGuard - Scanning")
        print(f"\n  {self.progress_bar(current_file, total_files)}")
        print(f"\n  {Colors.DIM}Scanning:{Colors.RESET} {current_path[:self.term_width-15]}")
        print(f"  {Colors.DIM}Files:{Colors.RESET}    {current_file}/{total_files}")
        sys.stdout.flush()
