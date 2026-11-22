"""Tests for CLI update safety and RPM ownership detection."""
from __future__ import annotations

import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from sentinel import __version__
from sentinel.cli import _rpm_package_owner, update_from_github


class RpmOwnershipTests(unittest.TestCase):
    def test_rpm_unavailable_allows_non_rpm_install(self):
        with patch("sentinel.cli.shutil.which", return_value=None):
            self.assertIsNone(_rpm_package_owner("/usr/local/bin/sentinel"))

    def test_owned_executable_returns_package_name(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "sentinel"
            executable.write_text("#!/bin/sh\n")
            result = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="sentinel", stderr=""
            )
            with (
                patch("sentinel.cli.shutil.which", return_value="/usr/bin/rpm"),
                patch("sentinel.cli.subprocess.run", return_value=result) as run,
            ):
                self.assertEqual(_rpm_package_owner(str(executable)), "sentinel")
            self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")

    def test_confirmed_unowned_executable_returns_none(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "sentinel"
            executable.write_text("#!/bin/sh\n")
            result = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout=f"file {executable} is not owned by any package\n",
                stderr="",
            )
            with (
                patch("sentinel.cli.shutil.which", return_value="/usr/bin/rpm"),
                patch("sentinel.cli.subprocess.run", return_value=result),
            ):
                self.assertIsNone(_rpm_package_owner(str(executable)))

    def test_unexpected_rpm_error_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "sentinel"
            executable.write_text("#!/bin/sh\n")
            result = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr=f"error: file {executable}: No such file or directory",
            )
            with (
                patch("sentinel.cli.shutil.which", return_value="/usr/bin/rpm"),
                patch("sentinel.cli.subprocess.run", return_value=result),
            ):
                with self.assertRaisesRegex(RuntimeError, "could not verify"):
                    _rpm_package_owner(str(executable))

    def test_rpm_query_os_error_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "sentinel"
            executable.write_text("#!/bin/sh\n")
            with (
                patch("sentinel.cli.shutil.which", return_value="/usr/bin/rpm"),
                patch(
                    "sentinel.cli.subprocess.run",
                    side_effect=OSError("simulated execution failure"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "could not be completed"):
                    _rpm_package_owner(str(executable))

    def test_missing_running_executable_fails_closed(self):
        with (
            patch("sentinel.cli.shutil.which", return_value="/usr/bin/rpm"),
            self.assertRaisesRegex(RuntimeError, "Cannot safely resolve"),
        ):
            _rpm_package_owner("/definitely/missing/sentinel")


class UpdateTests(unittest.TestCase):
    @patch("sentinel.cli._package_manager_update_hint", return_value="sudo dnf upgrade sentinel")
    @patch("sentinel.cli._rpm_package_owner", return_value="sentinel")
    @patch("sentinel.cli._get_remote_version")
    def test_rpm_install_uses_system_package_manager(
        self, remote_version, owner, update_hint
    ):
        output = io.StringIO()
        with redirect_stdout(output):
            result = update_from_github()

        self.assertEqual(result, 0)
        self.assertIn("system package manager", output.getvalue())
        self.assertIn("dnf upgrade sentinel", output.getvalue())
        owner.assert_called_once_with()
        remote_version.assert_not_called()
        update_hint.assert_called_once_with("sentinel")

    @patch("sentinel.cli._get_remote_version", return_value=__version__)
    @patch("sentinel.cli._rpm_package_owner", return_value=None)
    def test_manual_install_keeps_github_update_check(
        self, owner, remote_version
    ):
        output = io.StringIO()
        with redirect_stdout(output):
            result = update_from_github()

        self.assertEqual(result, 0)
        self.assertIn("already up to date", output.getvalue())
        owner.assert_called_once_with()
        remote_version.assert_called_once_with()

    @patch(
        "sentinel.cli._rpm_package_owner",
        side_effect=RuntimeError("simulated RPM database failure"),
    )
    @patch("sentinel.cli._get_remote_version")
    def test_uncertain_rpm_state_blocks_self_update(self, remote_version, owner):
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = update_from_github()

        self.assertEqual(result, 1)
        self.assertIn("No update was attempted", errors.getvalue())
        owner.assert_called_once_with()
        remote_version.assert_not_called()


if __name__ == "__main__":
    unittest.main()
