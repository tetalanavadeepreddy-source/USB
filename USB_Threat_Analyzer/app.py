"""
USB Threat Analyzer - main Flask application.

Wires together the USB monitor (Level 0), the Level 1-3 scanners, the
risk engine, quarantine system, Level 4 sandbox manager, SQLite
history, and the PDF report generator behind a single-page
Glassmorphism dashboard.

On startup, a background USB monitor begins watching for removable
drives. The instant one is inserted, a scan thread walks the drive
running every applicable level of analysis, scores each file, and
quarantines anything that crosses the High risk threshold. All of this
is exposed to the frontend over a small JSON API which the dashboard
polls / drives via fetch().
"""

from __future__ import annotations

import hmac
import threading
import uuid
from pathlib import Path

from flask import Flask, abort, jsonify, make_response, render_template, request, send_file

import config
import database
from report_generator import generate_report
from sandbox import sandbox_manager
from scanners import level1_scanner, level2_zip_ast, level3_pe, quarantine, risk_engine
from scanners.usb_monitor import USBDeviceInfo, USBMonitor
from utils import startup_manager
from utils.logger import get_logger

logger = get_logger(__name__)

# templates/ and static/ are read from config.RESOURCE_DIR so the same code works
# from source and inside the PyInstaller one-file EXE (where they are unpacked
# to a temporary folder).
app = Flask(
    __name__,
    static_folder=str(config.RESOURCE_DIR / "static"),
    template_folder=str(config.RESOURCE_DIR / "templates"),
)

# Desktop mode (desktop.py) sets a random per-launch token here. When set, every
# request must carry it (as the cookie planted by the first page load), so a
# web page open in some other browser cannot drive this app's local API -
# which can restore or delete quarantined files. Unset when running
# `python app.py` for development, which behaves exactly as before.
_TOKEN_COOKIE = "uta_token"
app.config["ACCESS_TOKEN"] = None


@app.before_request
def _require_access_token():
    token = app.config.get("ACCESS_TOKEN")
    if not token:
        return None
    if request.path == "/" and hmac.compare_digest(request.args.get("t", ""), token):
        return None  # first load: index() converts this into the cookie
    if hmac.compare_digest(request.cookies.get(_TOKEN_COOKIE, ""), token):
        return None
    abort(403)

# In-memory live state the frontend polls; SQLite remains the source of
# truth for anything that must survive a restart.
_state_lock = threading.Lock()
_live_state = {
    "connected_devices": [],
    "active_scan": None,   # scan_id currently running, or None
    "scan_progress": {},   # scan_id -> {"total": int, "done": int, "current_file": str}
    "recent_findings": {}, # scan_id -> list[dict] (grows as the scan progresses)
}

_HIGH_RISK_QUARANTINE_THRESHOLD = 60  # "High" and above get quarantined automatically

# Level 3 only has analyzers for these; other "executable" extensions (e.g. .com)
# fall through to the generic record instead of raising mid-scan.
_LEVEL3_EXTENSIONS = level3_pe.PE_EXTENSIONS | level3_pe.SCRIPT_EXECUTABLE_EXTENSIONS


# ---------------------------------------------------------------------------
# USB Monitor wiring (Level 0)
# ---------------------------------------------------------------------------
def _on_usb_connected(device: USBDeviceInfo) -> None:
    with _state_lock:
        _live_state["connected_devices"] = usb_monitor.current_devices()
    threading.Thread(target=_run_full_scan, args=(device,), daemon=True, name="ScanThread").start()


def _on_usb_disconnected(drive_letter: str) -> None:
    with _state_lock:
        _live_state["connected_devices"] = usb_monitor.current_devices()


usb_monitor = USBMonitor(on_connect=_on_usb_connected, on_disconnect=_on_usb_disconnected)


# ---------------------------------------------------------------------------
# Core scan pipeline
# ---------------------------------------------------------------------------
def _run_full_scan(device: USBDeviceInfo) -> None:
    """Runs Levels 1-3 across an inserted drive, scores, and auto-quarantines."""
    scan_id = f"scan_{uuid.uuid4().hex[:10]}"
    root = Path(device.drive_letter)
    logger.info("Starting scan %s for device %s", scan_id, device.drive_letter)

    database.create_scan(scan_id, device.label or "Removable Disk", device.drive_letter,
                          device.capacity_bytes, device.file_system)

    with _state_lock:
        _live_state["active_scan"] = scan_id
        _live_state["scan_progress"][scan_id] = {"total": 0, "done": 0, "current_file": ""}
        _live_state["recent_findings"][scan_id] = []

    files_scanned = 0
    suspicious_count = 0
    highest_risk = 0

    try:
        all_paths = [p for p in root.rglob("*") if p.is_file()]
        with _state_lock:
            _live_state["scan_progress"][scan_id]["total"] = len(all_paths)

        for path in all_paths:
            try:
                result = _analyze_single_file(scan_id, path)
            except Exception as exc:  # noqa: BLE001 - one bad file must never abort the whole scan
                logger.warning("Skipping file that could not be analyzed during scan %s: %s (%s)",
                               scan_id, path, exc)
                continue

            files_scanned += 1
            with _state_lock:
                _live_state["scan_progress"][scan_id]["done"] = files_scanned
                _live_state["scan_progress"][scan_id]["current_file"] = str(path)
                _live_state["recent_findings"][scan_id].append(result)

            risk_score = result["risk_score"]
            highest_risk = max(highest_risk, risk_score)
            if risk_score >= 30:
                suspicious_count += 1

            if risk_score >= _HIGH_RISK_QUARANTINE_THRESHOLD:
                try:
                    q = quarantine.quarantine_file(scan_id, path, risk_score, result["reasons"],
                                                   result.get("explanations"))
                    result["quarantined"] = True
                    result["quarantine_id"] = q["id"]
                except quarantine.QuarantineError as exc:
                    logger.warning("Could not quarantine %s: %s", path, exc)

            database.insert_file_result(scan_id, result)
    except Exception:  # noqa: BLE001 - e.g. the drive was pulled mid-scan
        logger.exception("Scan %s stopped early", scan_id)
    finally:
        database.finish_scan(scan_id, files_scanned, suspicious_count, highest_risk,
                              sandbox_used=None, report_path=None)
        with _state_lock:
            _live_state["active_scan"] = None

    logger.info("Scan %s complete: %d files, %d suspicious, highest risk %d",
                scan_id, files_scanned, suspicious_count, highest_risk)


def _analyze_single_file(scan_id: str, path: Path) -> dict:
    """Route a single file through the correct level(s) and compute its final risk score."""
    ext = path.suffix.lower()

    if ext in _LEVEL3_EXTENSIONS:
        # Level 3
        analysis = level3_pe.analyze_executable(path)
        data = analysis.to_dict()
        if isinstance(analysis, level3_pe.PEAnalysisResult):
            assessment = risk_engine.score_pe(data)
            level = 3
        else:
            assessment = risk_engine.score_script_executable(data)
            level = 3
        from utils.hash import sha256_of
        stat_result = path.stat()
        from datetime import datetime as _dt
        return {
            "file_name": path.name, "extension": ext, "absolute_path": str(path),
            "size_bytes": stat_result.st_size, "sha256": sha256_of(path),
            "mime_type": "", "created_date": _dt.fromtimestamp(stat_result.st_ctime).isoformat(),
            "modified_date": _dt.fromtimestamp(stat_result.st_mtime).isoformat(),
            "level": level, "risk_score": assessment.score, "risk_level": assessment.level,
            "reasons": assessment.reasons, "explanations": assessment.explanations,
            "quarantined": False, "detail": data,
        }

    if ext in config.ARCHIVE_EXTENSIONS:
        # Level 2 - zip
        zip_result = level2_zip_ast.analyze_zip(path)
        data = zip_result.to_dict()
        assessment = risk_engine.score_zip(data)
        from utils.hash import sha256_of
        stat_result = path.stat()
        from datetime import datetime as _dt
        return {
            "file_name": path.name, "extension": ext, "absolute_path": str(path),
            "size_bytes": stat_result.st_size, "sha256": sha256_of(path),
            "mime_type": "application/zip",
            "created_date": _dt.fromtimestamp(stat_result.st_ctime).isoformat(),
            "modified_date": _dt.fromtimestamp(stat_result.st_mtime).isoformat(),
            "level": 2, "risk_score": assessment.score, "risk_level": assessment.level,
            "reasons": assessment.reasons, "explanations": assessment.explanations,
            "quarantined": False, "detail": data,
        }

    if ext in config.SCRIPT_LANGUAGE_EXTENSIONS and ext not in config.EXECUTABLE_EXTENSIONS:
        # Level 2 - AST/script analysis
        script_result = level2_zip_ast.analyze_script(path)
        data = script_result.to_dict() if script_result else {}
        assessment = risk_engine.score_script(data)
        from utils.hash import sha256_of
        stat_result = path.stat()
        from datetime import datetime as _dt
        return {
            "file_name": path.name, "extension": ext, "absolute_path": str(path),
            "size_bytes": stat_result.st_size, "sha256": sha256_of(path),
            "mime_type": "text/plain",
            "created_date": _dt.fromtimestamp(stat_result.st_ctime).isoformat(),
            "modified_date": _dt.fromtimestamp(stat_result.st_mtime).isoformat(),
            "level": 2, "risk_score": assessment.score, "risk_level": assessment.level,
            "reasons": assessment.reasons, "explanations": assessment.explanations,
            "quarantined": False, "detail": data,
        }

    if ext in config.NON_EXECUTABLE_EXTENSIONS:
        # Level 1
        finding = level1_scanner.scan_file(path)
        assessment = risk_engine.score_level1(finding.flags, finding.details)
        result = finding.to_dict()
        result["risk_score"] = assessment.score
        result["risk_level"] = assessment.level
        result["reasons"] = assessment.reasons or finding.reasons
        result["explanations"] = assessment.explanations
        result["quarantined"] = False
        return result

    # Unrecognized extension - record minimally at Low risk rather than skipping silently.
    from utils.hash import sha256_of
    stat_result = path.stat()
    from datetime import datetime as _dt
    return {
        "file_name": path.name, "extension": ext, "absolute_path": str(path),
        "size_bytes": stat_result.st_size, "sha256": sha256_of(path),
        "mime_type": "unknown/unknown",
        "created_date": _dt.fromtimestamp(stat_result.st_ctime).isoformat(),
        "modified_date": _dt.fromtimestamp(stat_result.st_mtime).isoformat(),
        "level": 0, "risk_score": 0, "risk_level": "Low",
        "reasons": ["Unrecognized file type - not covered by current scan levels."],
        "explanations": [], "quarantined": False,
    }


# ---------------------------------------------------------------------------
# Routes - pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    response = make_response(render_template("index.html"))
    token = app.config.get("ACCESS_TOKEN")
    if token:
        response.set_cookie(_TOKEN_COOKIE, token, httponly=True, samesite="Strict")
    return response


# ---------------------------------------------------------------------------
# Routes - API: USB / scan status
# ---------------------------------------------------------------------------
@app.route("/api/status")
def api_status():
    with _state_lock:
        active_scan = _live_state["active_scan"]
        progress = _live_state["scan_progress"].get(active_scan, {}) if active_scan else {}
        devices = _live_state["connected_devices"]
    return jsonify({
        "connected_devices": devices,
        "active_scan": active_scan,
        "progress": progress,
    })


@app.route("/api/scan/<scan_id>/findings")
def api_scan_findings(scan_id: str):
    with _state_lock:
        live = _live_state["recent_findings"].get(scan_id)
    if live is not None:
        return jsonify({"source": "live", "findings": live})
    return jsonify({"source": "database", "findings": database.list_files_for_scan(scan_id)})


@app.route("/api/scan/<scan_id>")
def api_scan_detail(scan_id: str):
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404
    return jsonify(scan)


# ---------------------------------------------------------------------------
# Routes - API: history
# ---------------------------------------------------------------------------
@app.route("/api/history")
def api_history():
    return jsonify(database.list_scans())


# ---------------------------------------------------------------------------
# Routes - API: quarantine
# ---------------------------------------------------------------------------
@app.route("/api/quarantine")
def api_quarantine_list():
    return jsonify(database.list_quarantine())


@app.route("/api/quarantine/<int:item_id>/restore", methods=["POST"])
def api_quarantine_restore(item_id: int):
    try:
        path = quarantine.restore_file(item_id)
        return jsonify({"status": "restored", "path": path})
    except quarantine.QuarantineError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/quarantine/<int:item_id>/delete", methods=["POST"])
def api_quarantine_delete(item_id: int):
    try:
        quarantine.delete_permanently(item_id)
        return jsonify({"status": "deleted"})
    except quarantine.QuarantineError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/quarantine/<int:item_id>/export", methods=["POST"])
def api_quarantine_export(item_id: int):
    try:
        export_dir = config.REPORTS_DIR / "exported_samples"
        path = quarantine.export_sample(item_id, export_dir)
        return jsonify({"status": "exported", "path": path})
    except quarantine.QuarantineError as exc:
        return jsonify({"error": str(exc)}), 400


# ---------------------------------------------------------------------------
# Routes - API: Level 4 sandbox
# ---------------------------------------------------------------------------
@app.route("/api/sandbox/available")
def api_sandbox_available():
    return jsonify(sandbox_manager.detect_available_sandboxes())


@app.route("/api/quarantine/<int:item_id>/sandbox", methods=["POST"])
def api_quarantine_sandbox(item_id: int):
    payload = request.get_json(force=True, silent=True) or {}
    sandbox_choice = payload.get("sandbox_type", "windows_sandbox")
    vm_name = payload.get("vm_name")

    item = database.get_quarantine_item(item_id)
    if not item:
        return jsonify({"error": "quarantine item not found"}), 404

    try:
        file_path = quarantine.get_sandbox_candidate_path(item_id)
    except quarantine.QuarantineError as exc:
        return jsonify({"error": str(exc)}), 400

    result = sandbox_manager.run_analysis(
        file_path=file_path, scan_id=item["scan_id"],
        sandbox_choice=sandbox_choice, vm_name=vm_name,
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# Routes - API: Settings / Start with Windows
# ---------------------------------------------------------------------------
@app.route("/api/settings/startup")
def api_startup_status():
    """
    Read-only status check used to sync the Settings checkbox on page load.
    Reports the real current registry state - never assumes or caches it.
    """
    return jsonify(startup_manager.get_status())


@app.route("/api/settings/startup", methods=["POST"])
def api_startup_apply():
    """
    Apply the user's chosen startup preference. This is the ONLY code path
    that ever writes or deletes the HKCU Run value, and it only runs in
    direct response to this explicit request from the Settings page's
    Apply Changes button - never automatically and never on app launch.
    """
    payload = request.get_json(force=True, silent=True) or {}
    enabled = bool(payload.get("enabled", False))

    try:
        result = startup_manager.enable() if enabled else startup_manager.disable()
    except Exception as exc:  # noqa: BLE001 - this endpoint must never crash the app
        logger.exception("Unexpected error applying startup setting: %s", exc)
        return jsonify({"success": False, "message": f"Unexpected error: {exc}"}), 500

    status_code = 200 if result.get("success") else 400
    response = {**result, "status": startup_manager.get_status()}
    return jsonify(response), status_code


_AUTO_DOWNLOAD_SETTING_KEY = "auto_download_report"


@app.route("/api/settings/preferences")
def api_preferences_get():
    """Read-only status check used to sync the Auto-Download toggle on page load."""
    return jsonify({
        "auto_download_report": database.get_bool_setting(_AUTO_DOWNLOAD_SETTING_KEY, default=False),
    })


@app.route("/api/settings/preferences", methods=["POST"])
def api_preferences_apply():
    """Persist simple user preferences (currently just Auto-Download Report)."""
    payload = request.get_json(force=True, silent=True) or {}
    if "auto_download_report" in payload:
        database.set_bool_setting(_AUTO_DOWNLOAD_SETTING_KEY, bool(payload["auto_download_report"]))
    return jsonify({
        "success": True,
        "auto_download_report": database.get_bool_setting(_AUTO_DOWNLOAD_SETTING_KEY, default=False),
    })


# ---------------------------------------------------------------------------
# Routes - API: PDF report
# ---------------------------------------------------------------------------
@app.route("/api/scan/<scan_id>/report", methods=["POST"])
def api_generate_report(scan_id: str):
    try:
        path = generate_report(scan_id)
        scan = database.get_scan(scan_id)
        database.finish_scan(
            scan_id, scan["files_scanned"], scan["suspicious_files"],
            scan["highest_risk"], scan["sandbox_used"], path,
        )
        return jsonify({"status": "generated", "path": path})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@app.route("/api/report/<scan_id>/download")
def api_download_report(scan_id: str):
    scan = database.get_scan(scan_id)
    if not scan or not scan.get("report_path"):
        return jsonify({"error": "report not generated yet"}), 404
    return send_file(scan["report_path"], as_attachment=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    database.init_db()
    usb_monitor.start()
    logger.info("USB Threat Analyzer starting on http://%s:%d", config.FLASK_HOST, config.FLASK_PORT)
    try:
        app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG,
                 use_reloader=False, threaded=True)
    finally:
        usb_monitor.stop()


if __name__ == "__main__":
    main()
