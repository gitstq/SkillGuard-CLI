"""Tests for CLI."""
import unittest
import tempfile
import os
import sys
from io import StringIO
from unittest.mock import patch

from skillguard.cli import create_parser, cmd_scan, cmd_list, cmd_info


class TestCLI(unittest.TestCase):
    def test_parser_creation(self):
        parser = create_parser()
        self.assertIsNotNone(parser)

    def test_scan_command(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("exec(bad_code)\n")
            f.flush()

            parser = create_parser()
            args = parser.parse_args(["scan", f.name, "--no-tui", "--format", "json"])
            self.assertEqual(args.command, "scan")
            self.assertEqual(args.target, f.name)
            os.unlink(f.name)

    def test_list_command(self):
        parser = create_parser()
        args = parser.parse_args(["list"])
        self.assertEqual(args.command, "list")

    def test_info_command(self):
        parser = create_parser()
        args = parser.parse_args(["info"])
        self.assertEqual(args.command, "info")

    def test_version_flag(self):
        parser = create_parser()
        with self.assertRaises(SystemExit) as cm:
            parser.parse_args(["--version"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
