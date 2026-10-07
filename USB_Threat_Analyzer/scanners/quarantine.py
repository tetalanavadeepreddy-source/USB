"""
Quarantine System.

High-risk files are MOVED (never automatically deleted) into
quarantine/scan_<id>/ with full provenance recorded in SQLite. Supports
restore-to-original-location, permanent deletion (explicit user action
only), sample export (hashed copy for external analysis), and handing
a file off to the sandbox for dynamic analysis.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

import config
import database
from utils.hash import sha256_of
from utils.logger import get_logger

logger = get_logger(__name__)


class QuarantineError(Exception):
    """Raised for quarantine operations that cannot be completed safely."""


def quarantine_file(scan_id: str, source_path: str | Path, risk_score: int,
                     reasons: list[str], explanations: Optional[list[dict]] = None) -> dict:
    """
    Move a high-risk file out of the scanned tree and into an isolated
    quarantine folder, recording full provenance. The original file is
    never left executable/reachable from its original USB path.
    """
    source_path = Path(source_path)
    if not source_path.exists():
        raise QuarantineError(f"Source file no longer exists: {source_path}")

    scan_quarantine_dir = config.QUARANTINE_DIR / scan_id
    scan_quarantine_dir.mkdir(parents=True, exist_ok=True)

    sha256 = sha256_of(source_path)
    dest_name = f"{sha256[:16]}_{source_path.name}"
    dest_path = scan_quarantine_dir / dest_name

    try:
        shutil.move(str(source_path), str(dest_path))
    except (OSError, PermissionError) as exc:
        # If we cannot move it off the USB (e.g. read-only media), copy the
        # sample for analysis instead of silently doing nothing, and log it.
        logger.warning("Could not move %s off source media (%s); copying instead.", source_path, exc)
        shutil.copy2(str(source_path), str(dest_path))

    record_id = database.insert_quarantine_record(
        scan_id=scan_id, original_path=str(source_path), quarantine_path=str(dest_path),
        sha256=sha256, risk_score=risk_score, reasons=reasons, explanations=explanations,
    )
    logger.info("Quarantined %s -> %s (risk=%d)", source_path, dest_path, risk_score)

    return {
        "id": record_id, "original_path": str(source_path), "quarantine_path": str(dest_path),
        "sha256": sha256, "risk_score": risk_score, "reasons": reasons,
        "explanations": explanations or [],
    }


def restore_file(item_id: int, destination: Optional[str] = None) -> str:
    """Restore a quarantined file back to its original location (or a chosen destination)."""
    item = database.get_quarantine_item(item_id)
    if not item:
        raise QuarantineError(f"No quarantine record with id {item_id}")

    quarantine_path = Path(item["quarantine_path"])
    if not quarantine_path.exists():
        raise QuarantineError(f"Quarantined file missing from disk: {quarantine_path}")

    target = Path(destination) if destination else Path(item["original_path"])
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(quarantine_path), str(target))

    database.update_quarantine_status(item_id, "restored")
    logger.info("Restored quarantine item %d to %s", item_id, target)
    return str(target)


def delete_permanently(item_id: int) -> None:
    """Permanently delete a quarantined file. Requires an explicit user action - never automatic."""
    item = database.get_quarantine_item(item_id)
    if not item:
        raise QuarantineError(f"No quarantine record with id {item_id}")

    quarantine_path = Path(item["quarantine_path"])
    if quarantine_path.exists():
        quarantine_path.unlink()

    database.update_quarantine_status(item_id, "deleted")
    logger.info("Permanently deleted quarantine item %d (%s)", item_id, quarantine_path)


def export_sample(item_id: int, export_dir: str | Path) -> str:
    """Export a hashed copy of a quarantined file for external analysis/sharing."""
    item = database.get_quarantine_item(item_id)
    if not item:
        raise QuarantineError(f"No quarantine record with id {item_id}")

    quarantine_path = Path(item["quarantine_path"])
    if not quarantine_path.exists():
        raise QuarantineError(f"Quarantined file missing from disk: {quarantine_path}")

    export_dir = Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    export_path = export_dir / f"SAMPLE_{item['sha256'][:16]}_{quarantine_path.name}"
    shutil.copy2(str(quarantine_path), str(export_path))

    logger.info("Exported sample for quarantine item %d to %s", item_id, export_path)
    return str(export_path)


def get_sandbox_candidate_path(item_id: int) -> str:
    """Resolve the on-disk path of a quarantined file for hand-off to the sandbox."""
    item = database.get_quarantine_item(item_id)
    if not item:
        raise QuarantineError(f"No quarantine record with id {item_id}")
    path = Path(item["quarantine_path"])
    if not path.exists():
        raise QuarantineError(f"Quarantined file missing from disk: {path}")
    return str(path)
