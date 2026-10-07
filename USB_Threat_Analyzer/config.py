"""
Central configuration for USB Threat Analyzer.

Every module reads limits, paths, and risk weights from here instead of
hard-coding values, so the whole engine can be tuned from one file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Base paths
#
# RESOURCE_DIR: read-only files shipped with the app (templates/, static/).
#   In a PyInstaller one-file EXE these are unpacked to a temporary folder
#   (sys._MEIPASS) that is DELETED when the app exits.
# DATA_DIR: everything the app writes (history DB, logs, quarantine, reports).
#   Must survive restarts, so in the EXE it lives under %LOCALAPPDATA%
#   instead of next to the (temporary) code. From source it stays in the
#   project folder exactly as before.
# ---------------------------------------------------------------------------
IS_FROZEN = bool(getattr(sys, "frozen", False))
BASE_DIR = Path(__file__).resolve().parent
RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", BASE_DIR))

if IS_FROZEN:
    _local_appdata = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    DATA_DIR = Path(_local_appdata) / "USBThreatAnalyzer"
else:
    DATA_DIR = BASE_DIR

HISTORY_DIR = DATA_DIR / "history"
QUARANTINE_DIR = DATA_DIR / "quarantine"
REPORTS_DIR = DATA_DIR / "reports"
SAFE_EXTRACTION_ROOT = Path.home() / "AppData" / "Local" / "Temp" / "USB_Sandbox"

DATABASE_PATH = HISTORY_DIR / "history.db"

for _d in (HISTORY_DIR, QUARANTINE_DIR, REPORTS_DIR, REPORTS_DIR / "exported_samples",
           SAFE_EXTRACTION_ROOT):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# USB monitor
# ---------------------------------------------------------------------------
USB_POLL_INTERVAL_SECONDS = 2.0

# ---------------------------------------------------------------------------
# Level 1 - file scanner
# ---------------------------------------------------------------------------
NON_EXECUTABLE_EXTENSIONS = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".ico",
    # Documents / office
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt",
    # Text
    ".txt", ".csv", ".md", ".log", ".json", ".xml",
    # Audio
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma",
    # Video
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".msi", ".scr", ".inf", ".ps1", ".vbs", ".com", ".sys",
}

ARCHIVE_EXTENSIONS = {".zip", ".jar", ".apk"}

SCRIPT_LANGUAGE_EXTENSIONS = {
    ".py": "Python", ".java": "Java", ".c": "C", ".cpp": "C++", ".cc": "C++",
    ".js": "JavaScript", ".php": "PHP", ".ps1": "PowerShell", ".vbs": "VBScript",
}

# Reasonable maximum size (bytes) for common "small" file types, used by the
# abnormal-size heuristic. Files far beyond these are flagged, not blocked.
EXPECTED_MAX_SIZE = {
    ".txt": 2 * 1024 * 1024,        # 2 MB
    ".jpg": 25 * 1024 * 1024,       # 25 MB
    ".jpeg": 25 * 1024 * 1024,
    ".png": 25 * 1024 * 1024,
    ".csv": 50 * 1024 * 1024,
    ".ico": 1 * 1024 * 1024,
}

HIDDEN_ATTRIBUTE_RISK_NAMES = ("Hidden", "System", "Read Only", "Archive")

# ---------------------------------------------------------------------------
# Level 2 - zip / archive safety limits
# ---------------------------------------------------------------------------
ZIP_MAX_NESTED_DEPTH = 3
ZIP_MAX_TOTAL_EXTRACTED_BYTES = 500 * 1024 * 1024  # 500 MB
ZIP_MAX_FILE_COUNT = 5000
ZIP_BOMB_RATIO_THRESHOLD = 100  # extraction ratio above this is suspicious

# ---------------------------------------------------------------------------
# Risk engine weights
# ---------------------------------------------------------------------------
RISK_WEIGHTS = {
    "double_extension": 25,
    "hidden_system_file": 15,
    "mime_mismatch": 30,
    "disguised_executable": 35,
    "zip_bomb": 30,
    "zip_slip": 30,
    "high_entropy": 20,
    "appended_payload": 20,
    "abnormal_size": 10,
    "registry_api": 15,
    "network_api": 15,
    "process_api": 15,
    "crypto_api": 15,
    "unsigned_exe": 10,
    "packed_exe": 15,
    "dangerous_script_call": 15,
    "nested_zip_depth": 10,
}

RISK_LEVELS = (
    (0, 29, "Low"),
    (30, 59, "Medium"),
    (60, 79, "High"),
    (80, 100, "Critical"),
)

# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------
SANDBOX_STAGING_DIR = SAFE_EXTRACTION_ROOT / "sandbox_payloads"
SANDBOX_STAGING_DIR.mkdir(parents=True, exist_ok=True)
SANDBOX_RUN_TIMEOUT_SECONDS = 120

FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
FLASK_DEBUG = False
