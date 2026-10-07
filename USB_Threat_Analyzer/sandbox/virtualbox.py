"""
VirtualBox integration via VBoxManage (Oracle VirtualBox's official CLI).
Supports real VM snapshot restore/take and guest control execution
using VBoxManage's `snapshot`, `guestcontrol copyto`, and
`guestcontrol run` commands.

Requires:
  - VirtualBox installed with VBoxManage on PATH.
  - A pre-built analysis VM with Guest Additions installed and a clean
    baseline snapshot named "clean_baseline".
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import config
from utils.logger import get_logger

logger = get_logger(__name__)

_BASELINE_SNAPSHOT = "clean_baseline"
_GUEST_STAGING_PATH = r"C:\Sandbox"


def is_available() -> bool:
    """Detect whether VirtualBox's VBoxManage CLI is installed."""
    return shutil.which("VBoxManage") is not None


def _run_vboxmanage(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    cmd = ["VBoxManage"] + args
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def list_vms() -> list[str]:
    """List registered VirtualBox VM names."""
    if not is_available():
        return []
    try:
        result = _run_vboxmanage(["list", "vms"])
        return [line.split('"')[1] for line in result.stdout.splitlines() if '"' in line]
    except (subprocess.SubprocessError, OSError, IndexError) as exc:
        logger.warning("Could not list VirtualBox VMs: %s", exc)
        return []


def run_in_sandbox(file_path: str | Path, vm_name: str, scan_id: str,
                    guest_user: str = "analyst", guest_password: str = "analysis") -> dict:
    """
    Restore the analysis VM to its clean baseline snapshot, start it
    headless, copy the suspicious file into the guest via Guest
    Additions, execute it, take an after-snapshot, and report the
    snapshot names. The suspicious file only ever runs inside the
    isolated VM guest, never on the host.
    """
    file_path = Path(file_path)

    if not is_available():
        return {"sandbox_type": "VirtualBox", "status": "unavailable",
                "message": "VBoxManage CLI not found; VirtualBox is not installed or not on PATH."}

    if vm_name not in list_vms():
        return {"sandbox_type": "VirtualBox", "status": "error",
                "message": f"VM '{vm_name}' is not registered in VirtualBox."}

    started_at = time.time()
    before_snapshot_name = f"before_{scan_id}"
    after_snapshot_name = f"after_{scan_id}"

    try:
        logger.info("Restoring VirtualBox VM %s to baseline snapshot", vm_name)
        _run_vboxmanage(["snapshot", vm_name, "restore", _BASELINE_SNAPSHOT])
        _run_vboxmanage(["startvm", vm_name, "--type", "headless"])
        time.sleep(20)  # allow guest OS + Guest Additions to come up

        _run_vboxmanage(["snapshot", vm_name, "take", before_snapshot_name])

        guest_target = f"{_GUEST_STAGING_PATH}\\{file_path.name}"
        _run_vboxmanage([
            "guestcontrol", vm_name, "copyto", str(file_path), guest_target,
            "--username", guest_user, "--password", guest_password,
        ])

        logger.info("Executing sample inside VirtualBox guest: %s", guest_target)
        _run_vboxmanage([
            "guestcontrol", vm_name, "run", "--exe", guest_target,
            "--username", guest_user, "--password", guest_password,
        ], timeout=config.SANDBOX_RUN_TIMEOUT_SECONDS)

        time.sleep(5)
        _run_vboxmanage(["snapshot", vm_name, "take", after_snapshot_name])
        _run_vboxmanage(["controlvm", vm_name, "poweroff"])

    except subprocess.TimeoutExpired:
        logger.info("VirtualBox guest execution reached timeout for %s", file_path.name)
    except (subprocess.SubprocessError, OSError) as exc:
        logger.exception("VirtualBox sandbox run failed: %s", exc)
        return {"sandbox_type": "VirtualBox", "status": "error", "message": str(exc)}

    finished_at = time.time()

    return {
        "sandbox_type": "VirtualBox",
        "status": "completed",
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(finished_at - started_at, 1),
        "before_snapshot_name": before_snapshot_name,
        "after_snapshot_name": after_snapshot_name,
        "note": (
            "VM-level snapshots were captured via VBoxManage. Use "
            "`VBoxManage snapshot <vm> list` to inspect full disk-state diffs; "
            "this tool records snapshot names for traceability in the forensic report."
        ),
    }
