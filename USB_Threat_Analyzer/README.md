# USB Threat Analyzer

Automatic USB detection, multi-level static analysis (file/zip/script/PE),
an intelligent 0-100 risk engine, quarantine management, Level 4 sandbox
dynamic analysis (Windows Sandbox / VMware / VirtualBox), SQLite scan
history, and professional PDF forensic reports — behind a single-page
Glassmorphism dashboard.

## Requirements

- Windows 10/11 (Level 0 USB detection, Windows attribute/registry checks,
  and Windows Sandbox all require Windows; the rest of the pipeline degrades
  gracefully on other platforms for development).
- Python 3.12+
- For MIME detection: `libmagic`. On Windows, `python-magic-bin` (in
  requirements.txt) bundles it; on Linux/macOS install `libmagic` via your
  package manager and use `python-magic`.
- For Level 4 dynamic analysis: Windows Sandbox (Windows optional feature
  "Containers-DisposableClientVM"), and/or VMware Workstation/Player with
  `vmrun` on PATH, and/or VirtualBox with `VBoxManage` on PATH. VMware and
  VirtualBox analysis further require a pre-built analysis VM with a
  snapshot named `clean_baseline` and guest tools/guest additions installed.

## Setup

### Standalone Windows app (`.exe`)

Build once on a Windows PC with Python 3.12+:

```bat
build_exe.bat
```

This produces `dist\USBThreatAnalyzer.exe` and, if [Inno Setup](https://jrsoftware.org/isdl.php)
is installed, **`installer\USBThreatAnalyzer_Setup.exe`**. Run the setup once: it installs the
app (no admin rights needed) and puts the **USB Threat Analyzer icon on your desktop** and in the
Start Menu. Double-click the icon to open the app.

`dist\USBThreatAnalyzer.exe` is a single file that opens its own
window; there is no server to start and no browser involved. Copy it to any
Windows 10/11 PC and double-click. Insert a USB drive and the scan starts
automatically. Closing the window exits the app.

- Needs the Microsoft Edge WebView2 Runtime (preinstalled on Windows 11 and
  current Windows 10; the app offers the download link if it is missing).
- User data (scan history, quarantine, reports, log) is stored in
  `%LOCALAPPDATA%\USBThreatAnalyzer\`, so it survives restarts.
- `build_exe.bat` finishes by running `USBThreatAnalyzer.exe --selftest`, which
  checks that the packaged build contains every dependency
  (`%LOCALAPPDATA%\USBThreatAnalyzer\history\selftest.log`).
- "Start with Windows" launches the app minimized to the taskbar.

### Run from source (development)

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
python desktop.py               # same native window as the EXE
python app.py                   # or: plain web server at http://127.0.0.1:5000
```

Running from source keeps data in the project folder, as before.

## Why was this file flagged?

Every flagged file carries a structured explanation. In **Scan Results** (and in
**Quarantine**) click *Why flagged?* to see, for each indicator that fired:

- the **kind of check** — *Signature match* (content signature or known-pattern
  list), *Heuristic* (statistical/structural rule), or *Behavior indicator*
  (code capable of risky behavior),
- **what was found in this file** (e.g. the exact archive entry using `../`,
  the imported APIs, the matched command patterns, the section entropy),
- **why it matters**, and the **points** it contributed to the 0–100 score.

The explanations are produced in `scanners/risk_engine.py` (`FLAG_CATALOG` holds
the titles and wording) and stored with each scan in the `explanations_json`
column, which is added automatically to existing databases.

## Project layout

See the module docstrings at the top of each file (`app.py`, `config.py`,
`database.py`, `report_generator.py`, `scanners/*.py`, `sandbox/*.py`,
`utils/*.py`) for what each component owns.

## Safety model

- The host process never executes a suspicious file directly — Level 4
  execution always happens inside an isolated sandbox/VM guest.
- Level 2 zip analysis reads the central directory table only; nothing is
  extracted until zip-bomb, zip-slip, and nesting-depth checks all clear,
  and extraction is confined to an isolated `%TEMP%\USB_Sandbox\<scan_id>\`
  directory — never a user-facing folder like Downloads.
- High-risk files are quarantined (moved, never deleted) automatically;
  permanent deletion always requires an explicit user action.
- Every risk score is explainable: each contributing flag and its point
  weight is recorded and shown, and findings are phrased as behavior
  indicators, never a definitive malware verdict.
