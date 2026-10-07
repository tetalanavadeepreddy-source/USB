"""
VMware integration via vmrun (VMware Workstation/Player's official CLI
automation tool). Supports real VM snapshot revert/create/compare
around a guest execution using vmrun's `snapshot`, `revertToSnapshot`,
`runProgramInGuest`, and `copyFileFromHostToGuest` commands.

Requires:
  - VMware Workstation/Player installed (vmrun.exe does NOT need to be on
    PATH - see _locate_vmrun() below, which also checks the standard
    install directories and the registry).
  - A pre-built analysis VM registered with a clean baseline snapshot
    named "clean_baseline" and VMware Tools installed in the guest.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

import config
from utils.logger import get_logger

logger = get_logger(__name__)

_BASELINE_SNAPSHOT = "clean_baseline"
_GUEST_STAGING_PATH = r"C:\Sandbox"

# VMware Workstation/Player installers do NOT reliably add vmrun.exe to
# the system PATH, so PATH-only detection (shutil.which) produces false
# negatives on machines where VMware is genuinely installed. These are
# the standard install locations across VMware product/version history.
_COMMON_INSTALL_DIRS = (
    r"C:\Program Files (x86)\VMware\VMware Workstation",
    r"C:\Program Files\VMware\VMware Workstation",
    r"C:\Program Files (x86)\VMware\VMware Player",
    r"C:\Program Files\VMware\VMware Player",
    r"C:\Program Files (x86)\VMware\VMware VIX",
    r"C:\Program Files\VMware\VMware VIX",
)

# Registry locations that store VMware's actual install directory,
# checked when vmrun.exe isn't found on PATH or in the common paths above.
_REGISTRY_LOOKUPS = (
    (r"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation", "InstallPath"),
    (r"SOFTWARE\VMware, Inc.\VMware Workstation", "InstallPath"),
    (r"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Player", "InstallPath"),
    (r"SOFTWARE\VMware, Inc.\VMware Player", "InstallPath"),
)

_resolved_vmrun_path: Optional[str] = None  # cached after first successful lookup


def _registry_install_dirs() -> list[str]:
    """Read VMware's install directory from HKLM, if the registry keys exist."""
    dirs: list[str] = []
    try:
        import winreg
    except ImportError:
        return dirs

    for key_path, value_name in _REGISTRY_LOOKUPS:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
            install_path, _ = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            if install_path:
                dirs.append(install_path)
        except OSError:
            continue
    return dirs


def _locate_vmrun() -> Optional[str]:
    """
    Resolve the full path to vmrun.exe using, in order:
      1. PATH (shutil.which) - fastest, works if the user added it manually.
      2. Standard VMware install directories.
      3. The install directory recorded in the Windows registry by the
         VMware installer itself - the most reliable source, since it
         reflects wherever VMware was actually installed even if it's a
         non-default location, as long as it matches one of the known
         product registry keys.
    Result is cached in-process after the first successful lookup.
    """
    global _resolved_vmrun_path
    if _resolved_vmrun_path and Path(_resolved_vmrun_path).exists():
        return _resolved_vmrun_path

    exe_name = "vmrun.exe" if os.name == "nt" else "vmrun"

    on_path = shutil.which("vmrun")
    if on_path:
        _resolved_vmrun_path = on_path
        return on_path

    for directory in _COMMON_INSTALL_DIRS:
        candidate = Path(directory) / exe_name
        if candidate.exists():
            _resolved_vmrun_path = str(candidate)
            return _resolved_vmrun_path

    for directory in _registry_install_dirs():
        candidate = Path(directory) / exe_name
        if candidate.exists():
            _resolved_vmrun_path = str(candidate)
            return _resolved_vmrun_path

    return None


def is_available() -> bool:
    """
    Detect whether VMware's vmrun CLI is installed. Checks PATH, the
    standard VMware install directories, and the registry install path -
    not PATH alone, since VMware does not always register itself there.
    """
    return _locate_vmrun() is not None


def get_vmrun_path() -> Optional[str]:
    """Public accessor for the resolved vmrun.exe path, mainly for diagnostics/UI display."""
    return _locate_vmrun()


def _run_vmrun(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    vmrun_path = _locate_vmrun() or "vmrun"  # fall back to bare name so the error is descriptive
    cmd = [vmrun_path] + args
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def list_registered_vms() -> list[str]:
    """List VMs currently registered/running under vmrun (best-effort)."""
    if not is_available():
        return []
    try:
        result = _run_vmrun(["list"])
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip().endswith(".vmx")]
        return lines
    except (subprocess.SubprocessError, OSError) as exc:
        logger.warning("Could not list VMware VMs: %s", exc)
        return []


def run_in_sandbox(file_path: str | Path, vmx_path: str, scan_id: str,
                    guest_user: str = "analyst", guest_password: str = "analysis") -> dict:
    """
    Revert the analysis VM to its clean baseline snapshot, copy the
    suspicious file into the guest, execute it, take a fresh snapshot,
    and report the two snapshot names for comparison. The host process
    only ever calls vmrun; the target file itself runs solely inside
    the isolated VM guest.
    """
    file_path = Path(file_path)

    if not is_available():
        return {"sandbox_type": "VMware", "status": "unavailable",
                "message": "vmrun CLI not found; VMware Workstation/Player is not installed or not on PATH."}

    if not Path(vmx_path).exists():
        return {"sandbox_type": "VMware", "status": "error",
                "message": f"VMX file not found: {vmx_path}"}

    started_at = time.time()
    before_snapshot_name = f"before_{scan_id}"
    after_snapshot_name = f"after_{scan_id}"

    try:
        logger.info("Reverting VMware VM %s to baseline snapshot", vmx_path)
        _run_vmrun(["revertToSnapshot", vmx_path, _BASELINE_SNAPSHOT])
        _run_vmrun(["start", vmx_path, "nogui"])
        time.sleep(15)  # allow guest OS to finish booting

        _run_vmrun(["snapshot", vmx_path, before_snapshot_name])

        guest_target = f"{_GUEST_STAGING_PATH}\\{file_path.name}"
        _run_vmrun([
            "-gu", guest_user, "-gp", guest_password,
            "copyFileFromHostToGuest", vmx_path, str(file_path), guest_target,
        ])

        logger.info("Executing sample inside VMware guest: %s", guest_target)
        _run_vmrun([
            "-gu", guest_user, "-gp", guest_password,
            "runProgramInGuest", vmx_path, guest_target,
        ], timeout=config.SANDBOX_RUN_TIMEOUT_SECONDS)

        time.sleep(5)
        _run_vmrun(["snapshot", vmx_path, after_snapshot_name])
        _run_vmrun(["stop", vmx_path, "hard"])

    except subprocess.TimeoutExpired:
        logger.info("VMware guest execution reached timeout for %s", file_path.name)
    except (subprocess.SubprocessError, OSError) as exc:
        logger.exception("VMware sandbox run failed: %s", exc)
        return {"sandbox_type": "VMware", "status": "error", "message": str(exc)}

    finished_at = time.time()

    return {
        "sandbox_type": "VMware",
        "status": "completed",
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(finished_at - started_at, 1),
        "before_snapshot_name": before_snapshot_name,
        "after_snapshot_name": after_snapshot_name,
        "note": (
            "VM-level snapshots were captured via vmrun. Use VMware Snapshot "
            "Manager or `vmrun listSnapshots` to inspect full disk-state diffs; "
            "this tool records snapshot names for traceability in the forensic report."
        ),
    }
