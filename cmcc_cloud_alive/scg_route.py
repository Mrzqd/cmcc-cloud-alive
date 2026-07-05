#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCG keepalive route — subprocess shim around the forked Go binary.

When ``product_router`` decides ``route == SCG`` (``scAuthCode`` present), this
module launches the standalone Go keepalive binary
(``scg_go/cmcc_keepalive``, a direct fork of B's ``cloud-computer-keepalive``)
which performs the full SCG flow internally:

    soho token -> cem.GetFirmAuth -> cem.GetConnectInfo (ScgIP/ScgPort/
    ScAuthCode) -> scg.ConnectSCG -> keepalive loop

The Go binary is self-provisioning: ``scg_ip`` / ``scg_port`` / ``sc_auth_code``
are fetched from the CEM API inside the binary (B ``keepalive.go:56-78``), and
``vm_id`` is read from the ``cloud_pc.json`` config next to the binary
(B ``config.LoadConfig``). Therefore this shim does **not** pass
``scg_ip``/``scg_port``/``sc_auth_code`` as CLI flags (the binary has no such
flags — see ``main.go``); it accepts them in the signature for route-interface
uniformity with ``product_router`` and writes ``vm_id`` (plus any provided soho
credentials) into the binary's config so the binary can run unattended.

CLI surface of the binary (B ``main.go`` / ``cmd/keepalive.go``)::

    cmcc_keepalive keepalive [--duration N | --forever]
        --duration N   hold the SCG connection for N seconds (default: 120)
        --forever      persistent connection until Ctrl+C / SIGTERM

ConnectSCG signature (B ``internal/scg/scg.go``)::

    func ConnectSCG(scgIP, scgPort, scAuthCode, vmID string) (net.Conn, uint64, error)
"""

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Union

# --- locations -------------------------------------------------------------

_PKG_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PKG_DIR.parent
DEFAULT_BINARY = _PROJECT_ROOT / "scg_go" / "cmcc_keepalive"
DEFAULT_CONFIG_NAME = "cloud_pc.json"  # B config.LoadConfig() filename

# Subcommand understood by the binary (B main.go switch).
_SUBCOMMAND = "keepalive"


@dataclass
class SCGKeepaliveResult:
    """Outcome of a finite (non-``forever``) SCG keepalive run."""

    returncode: int
    stdout: str
    stderr: str
    command: List[str] = field(default_factory=list)
    config_path: Optional[str] = None

    @property
    def ok(self) -> bool:
        """True when the binary exited cleanly (returncode 0)."""
        return self.returncode == 0


# --- helpers ---------------------------------------------------------------

def _default_binary_path() -> str:
    """Resolve the binary path, honouring the ``CMCC_SCG_BINARY`` override."""
    env = os.environ.get("CMCC_SCG_BINARY")
    if env:
        return env
    return str(DEFAULT_BINARY)


def build_keepalive_args(duration: Optional[Union[int, float]] = None,
                         forever: bool = False) -> List[str]:
    """Build the CLI arg tail for the ``keepalive`` subcommand.

    Mirrors B ``cmd/keepalive.go`` flag parsing:
      * ``--forever``  -> duration 0 (persistent)
      * ``--duration N`` -> hold N seconds
      * neither        -> binary defaults to 120s
    """
    args: List[str] = [_SUBCOMMAND]
    if forever:
        args.append("--forever")
    elif duration is not None:
        args += ["--duration", str(int(duration))]
    return args


def write_binary_config(config_dir: Union[str, Path],
                        vm_id: str = "",
                        soho_token: str = "",
                        user_id: str = "",
                        user_service_id: str = "",
                        extra: Optional[Mapping[str, Any]] = None) -> str:
    """Write/merge ``cloud_pc.json`` next to the binary.

    B ``config.LoadConfig`` reads ``cloud_pc.json`` from the binary's directory
    (``os.Executable`` dir). We merge with any existing file so a real user
    config is not clobbered. Only non-empty fields are written.
    """
    cfg_path = Path(config_dir) / DEFAULT_CONFIG_NAME
    cfg: Dict[str, Any] = {}
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text() or "{}")
        except (ValueError, OSError):
            cfg = {}
    if extra:
        for k, v in extra.items():
            cfg.setdefault(k, v)
    if vm_id:
        cfg["vm_id"] = vm_id
    if soho_token:
        cfg["soho_token"] = soho_token
    if user_id:
        cfg["user_id"] = user_id
    if user_service_id:
        cfg["user_service_id"] = user_service_id
    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    return str(cfg_path)


# --- public API ------------------------------------------------------------

def run_scg_keepalive(scg_ip: str = "",
                      scg_port: str = "",
                      sc_auth_code: str = "",
                      vm_id: str = "",
                      duration: Optional[Union[int, float]] = None,
                      forever: bool = False,
                      binary_path: Optional[str] = None,
                      config_dir: Optional[Union[str, Path]] = None,
                      soho_token: str = "",
                      user_id: str = "",
                      user_service_id: str = "",
                      config_extra: Optional[Mapping[str, Any]] = None,
                      env: Optional[Mapping[str, str]] = None,
                      stdout: Optional[int] = None,
                      stderr: Optional[int] = None,
                      timeout: Optional[float] = None,
                      **kwargs: Any) -> Union[SCGKeepaliveResult,
                                              subprocess.Popen]:
    """Launch the forked Go SCG keepalive binary.

    The Go binary is self-provisioning (B ``keepalive.go``): it loads the soho
    token, calls ``cem.GetFirmAuth`` / ``GetConnectInfo`` to obtain
    ``scg_ip``/``scg_port``/``sc_auth_code``, then
    ``scg.ConnectSCG(scgIP, scgPort, scAuthCode, vmID)``. Hence
    ``scg_ip``/``scg_port``/``sc_auth_code`` are accepted for route-interface
    uniformity with ``product_router`` but are fetched internally by the binary;
    ``vm_id`` is written to the binary's ``cloud_pc.json`` config so the binary
    can use it.

    Args:
        scg_ip / scg_port / sc_auth_code: SCG endpoint + auth code. Self-
            provisioned by the binary via the CEM API; kept in the signature for
            ``product_router`` contract uniformity.
        vm_id: target VM id, written to the binary config.
        duration: hold the SCG connection for N seconds (binary default 120).
        forever: persistent connection. When True a ``subprocess.Popen`` is
            returned (caller manages the lifecycle / termination).
        binary_path: override the binary location (default ``scg_go/cmcc_keepalive``
            or ``$CMCC_SCG_BINARY``).
        config_dir: directory for ``cloud_pc.json`` (default: binary dir).
        soho_token / user_id / user_service_id: written to the binary config so
            the binary can run unattended.
        config_extra: extra fields merged into ``cloud_pc.json``.
        env: extra environment variables merged over ``os.environ``.
        stdout / stderr: passed through to subprocess (default: captured).
        timeout: timeout in seconds for finite runs (``subprocess.run``).
        **kwargs: forwarded to ``subprocess.run`` (finite runs only).

    Returns:
        ``SCGKeepaliveResult`` for finite runs, or ``subprocess.Popen`` when
        ``forever=True``.
    """
    binary = binary_path or _default_binary_path()
    if not os.path.isfile(binary):
        raise FileNotFoundError(f"SCG keepalive binary not found: {binary}")

    cmd = [binary] + build_keepalive_args(duration=duration, forever=forever)
    cfg_dir = str(config_dir or os.path.dirname(os.path.abspath(binary)))
    cfg_path = write_binary_config(
        cfg_dir, vm_id=vm_id, soho_token=soho_token, user_id=user_id,
        user_service_id=user_service_id, extra=config_extra)

    run_env = dict(os.environ)
    if env:
        run_env.update(env)

    if forever:
        return subprocess.Popen(
            cmd, cwd=cfg_dir, env=run_env,
            stdout=stdout if stdout is not None else subprocess.PIPE,
            stderr=stderr if stderr is not None else subprocess.PIPE)

    proc = subprocess.run(
        cmd, cwd=cfg_dir, env=run_env,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=stderr if stderr is not None else subprocess.PIPE,
        timeout=timeout, **kwargs)
    out = proc.stdout if isinstance(proc.stdout, str) else (
        proc.stdout.decode("utf-8", "replace") if proc.stdout else "")
    err = proc.stderr if isinstance(proc.stderr, str) else (
        proc.stderr.decode("utf-8", "replace") if proc.stderr else "")
    return SCGKeepaliveResult(
        returncode=proc.returncode, stdout=out, stderr=err,
        command=cmd, config_path=cfg_path)


def is_binary_available(binary_path: Optional[str] = None) -> bool:
    """True when the SCG keepalive binary exists and is executable."""
    binary = binary_path or _default_binary_path()
    return os.path.isfile(binary) and os.access(binary, os.X_OK)
