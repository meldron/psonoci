"""Check the local helper's failure paths without Docker or a Psono server."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/local-psono-server.py"
SPEC = importlib.util.spec_from_file_location("local_psono_server", SCRIPT)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class LocalPsonoServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"

    def command(self, *arguments, environment=None):
        return subprocess.run(
            [sys.executable, "-S", str(SCRIPT), "--state-dir", str(self.state), *arguments],
            capture_output=True, text=True, env=environment,
        )

    def manifest(self, status="running"):
        self.state.mkdir(exist_ok=True)
        manifest = {"status": status, "pid": os.getpid(), "run_id": "test-run",
                    "url": "http://127.0.0.1:1/", "binary": sys.executable,
                    "fixtures": {}, "hashes": {}}
        (self.state / "server.json").write_text(json.dumps(manifest))
        return manifest

    def assert_friendly_error(self, result, message):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_state_is_actionable_for_all_commands(self):
        for command in (("check",), ("cli", "api-key", "info"), ("stop",)):
            with self.subTest(command=command):
                self.assert_friendly_error(self.command(*command), "Start the server with 'serve'")

    def test_malformed_and_incomplete_state_are_reported_without_tracebacks(self):
        self.state.mkdir()
        for content in ("not json", "[]", "{}", '{"status":"running"}'):
            (self.state / "server.json").write_text(content)
            for command in (("check",), ("cli", "help"), ("stop",)):
                with self.subTest(content=content, command=command):
                    self.assert_friendly_error(self.command(*command), "Invalid local Psono state")

    def test_stopped_state_is_actionable_for_all_commands(self):
        self.manifest("stopped")
        for command in (("check",), ("cli", "help"), ("stop",)):
            with self.subTest(command=command):
                self.assert_friendly_error(self.command(*command), "server is stopped")

    def test_stale_state_is_actionable_and_stop_does_not_signal_an_unverified_pid(self):
        self.manifest()
        for command in (("check",), ("cli", "help"), ("stop",)):
            with self.subTest(command=command):
                self.assert_friendly_error(self.command(*command), "state is stale or the server is unavailable")
        with patch.object(HELPER, "health", side_effect=RuntimeError("server identity mismatch")), \
                patch.object(HELPER.os, "kill") as kill:
            args = HELPER.argparse.Namespace(command="stop")
            with self.assertRaisesRegex(RuntimeError, "server identity mismatch"):
                HELPER.run(args, self.state, None)
            kill.assert_not_called()

    def test_missing_django_fails_before_creating_state_or_starting_docker(self):
        commands = self.root / "commands"
        commands.mkdir()
        marker = self.root / "docker-called"
        docker = commands / "docker"
        docker.write_text('#!/bin/sh\ntouch "$DOCKER_MARKER"\nexit 99\n')
        docker.chmod(0o755)
        environment = os.environ | {"PATH": str(commands) + os.pathsep + os.environ["PATH"],
                                    "DOCKER_MARKER": str(marker)}
        result = self.command("serve", "--server-source", str(self.root),
                              "--binary", sys.executable, environment=environment)
        self.assert_friendly_error(result, "Django is unavailable")
        self.assertFalse(marker.exists())
        self.assertFalse(self.state.exists())

    def test_missing_config_is_reported_before_invoking_the_binary(self):
        manifest = self.manifest()
        with self.assertRaisesRegex(RuntimeError, "config is missing"):
            HELPER.cli(self.state, manifest, "help")

    def test_cli_forwards_leading_options_after_a_separator(self):
        manifest = self.manifest()
        args = HELPER.argparse.Namespace(command="cli", arguments=["--", "--help"])
        with patch.object(HELPER, "running_manifest", return_value=manifest), \
                patch.object(HELPER, "cli", return_value="help output") as cli, \
                patch("builtins.print"):
            HELPER.run(args, self.state, None)
        cli.assert_called_once_with(self.state, manifest, "--help")


if __name__ == "__main__":
    unittest.main()
