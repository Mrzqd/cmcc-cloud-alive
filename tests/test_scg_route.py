#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for cmcc_cloud_alive.scg_route (SCG keepalive subprocess shim).

All subprocess calls are mocked — no real network / no real SCG connection.
A lightweight smoke test confirms the forked Go binary is a working ELF
executable (banner + usage, no network).
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

# Make the package importable when run directly.
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cmcc_cloud_alive import scg_route  # noqa: E402
from cmcc_cloud_alive.scg_route import (  # noqa: E402
    SCGKeepaliveResult, build_keepalive_args, is_binary_available,
    run_scg_keepalive, write_binary_config, DEFAULT_BINARY, DEFAULT_CONFIG_NAME)


class _FakeCompleted:
    """Mimic subprocess.run result for finite runs."""

    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestBuildKeepaliveArgs(unittest.TestCase):
    """CLI arg assembly must mirror B cmd/keepalive.go flag parsing."""

    def test_default_uses_subcommand_only(self):
        self.assertEqual(build_keepalive_args(), ["keepalive"])

    def test_duration_flag(self):
        self.assertEqual(
            build_keepalive_args(duration=300), ["keepalive", "--duration", "300"])

    def test_duration_float_truncated_to_int(self):
        self.assertEqual(
            build_keepalive_args(duration=120.9),
            ["keepalive", "--duration", "120"])

    def test_forever_flag(self):
        self.assertEqual(
            build_keepalive_args(forever=True), ["keepalive", "--forever"])

    def test_forever_takes_precedence_over_duration(self):
        # --forever sets duration 0 in B; it should win when both given.
        self.assertEqual(
            build_keepalive_args(duration=300, forever=True),
            ["keepalive", "--forever"])


class TestWriteBinaryConfig(unittest.TestCase):
    """cloud_pc.json writing/merging (B config.LoadConfig filename)."""

    def setUp(self):
        self.tmp = Path(ROOT) / "tests" / "_scg_cfg_tmp"
        self.tmp.mkdir(exist_ok=True)

    def tearDown(self):
        for f in self.tmp.glob("*"):
            f.unlink()
        self.tmp.rmdir()

    def test_writes_vm_id(self):
        path = write_binary_config(self.tmp, vm_id="vm-123")
        self.assertEqual(Path(path).name, DEFAULT_CONFIG_NAME)
        cfg = json.loads(Path(path).read_text())
        self.assertEqual(cfg["vm_id"], "vm-123")

    def test_writes_credentials(self):
        path = write_binary_config(
            self.tmp, vm_id="v1", soho_token="tok", user_id="u1",
            user_service_id="us1")
        cfg = json.loads(Path(path).read_text())
        self.assertEqual(cfg["soho_token"], "tok")
        self.assertEqual(cfg["user_id"], "u1")
        self.assertEqual(cfg["user_service_id"], "us1")

    def test_merges_with_existing(self):
        write_binary_config(self.tmp, vm_id="v1", extra={"keep": "yes"})
        # second call must not clobber the extra field
        write_binary_config(self.tmp, soho_token="tok2")
        cfg = json.loads((self.tmp / DEFAULT_CONFIG_NAME).read_text())
        self.assertEqual(cfg["vm_id"], "v1")
        self.assertEqual(cfg["keep"], "yes")
        self.assertEqual(cfg["soho_token"], "tok2")

    def test_empty_fields_not_written(self):
        write_binary_config(self.tmp, vm_id="", soho_token="")
        cfg = json.loads((self.tmp / DEFAULT_CONFIG_NAME).read_text())
        self.assertNotIn("vm_id", cfg)
        self.assertNotIn("soho_token", cfg)


class TestRunScgKeepalive(unittest.TestCase):
    """run_scg_keepalive command assembly + config wiring (subprocess mocked)."""

    def setUp(self):
        self.tmp = Path(ROOT) / "tests" / "_scg_run_tmp"
        self.tmp.mkdir(exist_ok=True)
        # Point at the real binary so isfile() passes, but mock the execution.
        self.binary = str(DEFAULT_BINARY)

    def tearDown(self):
        for f in self.tmp.glob("*"):
            f.unlink()
        if self.tmp.exists():
            self.tmp.rmdir()

    def _patch_run(self, completed=None):
        completed = completed or _FakeCompleted(0, b"ok", b"")
        return mock.patch("cmcc_cloud_alive.scg_route.subprocess.run",
                          return_value=completed)

    def test_finite_run_assembles_command_and_writes_config(self):
        with self._patch_run() as mrun:
            res = run_scg_keepalive(
                scg_ip="1.2.3.4", scg_port="443", sc_auth_code="CODE",
                vm_id="vm-9", duration=600, binary_path=self.binary,
                config_dir=self.tmp)
        mrun.assert_called_once()
        args, kw = mrun.call_args
        cmd = args[0] if args else kw.get("args")
        self.assertEqual(cmd[0], self.binary)
        self.assertEqual(cmd[1:], ["keepalive", "--duration", "600"])
        self.assertEqual(kw["cwd"], str(self.tmp))
        # config written with vm_id
        cfg = json.loads((self.tmp / DEFAULT_CONFIG_NAME).read_text())
        self.assertEqual(cfg["vm_id"], "vm-9")
        # result wrapping
        self.assertIsInstance(res, SCGKeepaliveResult)
        self.assertTrue(res.ok)
        self.assertEqual(res.command, cmd)
        self.assertEqual(res.stdout, "ok")

    def test_forever_returns_popen(self):
        fake_popen = mock.MagicMock(spec=subprocess.Popen)
        with mock.patch("cmcc_cloud_alive.scg_route.subprocess.Popen",
                        return_value=fake_popen) as mpopen:
            res = run_scg_keepalive(
                vm_id="vm-f", forever=True, binary_path=self.binary,
                config_dir=self.tmp)
        mpopen.assert_called_once()
        args, kw = mpopen.call_args
        cmd = args[0] if args else kw.get("args")
        self.assertIn("--forever", cmd)
        self.assertNotIn("--duration", cmd)
        self.assertIs(res, fake_popen)

    def test_default_duration_omits_flag(self):
        with self._patch_run() as mrun:
            run_scg_keepalive(vm_id="v", binary_path=self.binary,
                              config_dir=self.tmp)
        cmd = mrun.call_args[0][0]
        self.assertEqual(cmd[1:], ["keepalive"])

    def test_missing_binary_raises(self):
        with self.assertRaises(FileNotFoundError):
            run_scg_keepalive(binary_path="/no/such/cmcc_keepalive",
                              config_dir=self.tmp)

    def test_env_merged(self):
        with self._patch_run() as mrun:
            run_scg_keepalive(vm_id="v", binary_path=self.binary,
                              config_dir=self.tmp, env={"FOO": "bar"})
        env = mrun.call_args.kwargs["env"]
        self.assertEqual(env.get("FOO"), "bar")
        # os.environ still present
        self.assertIn("PATH", env)

    def test_nonzero_returncode_propagates(self):
        with self._patch_run(_FakeCompleted(1, b"", b"boom")):
            res = run_scg_keepalive(vm_id="v", binary_path=self.binary,
                                    config_dir=self.tmp)
        self.assertFalse(res.ok)
        self.assertEqual(res.returncode, 1)
        self.assertEqual(res.stderr, "boom")


class TestBinarySmoke(unittest.TestCase):
    """The forked Go binary must be a working executable (no network)."""

    def test_binary_present_and_executable(self):
        # Skip gracefully in environments where the binary wasn't built.
        if not DEFAULT_BINARY.exists():
            self.skipTest("scg_go/cmcc_keepalive not built in this env")
        self.assertTrue(is_binary_available())

    def test_binary_prints_usage_without_subcommand(self):
        if not DEFAULT_BINARY.exists():
            self.skipTest("scg_go/cmcc_keepalive not built in this env")
        proc = subprocess.run(
            [str(DEFAULT_BINARY)], capture_output=True, timeout=15)
        # No subcommand -> prints banner + usage, exits non-zero.
        self.assertNotEqual(proc.returncode, 0)
        combined = (proc.stdout + proc.stderr).decode("utf-8", "replace")
        self.assertIn("keepalive", combined)
        self.assertIn("Usage", combined)


if __name__ == "__main__":
    unittest.main()
