# USB Tray Watcher

A small WinForms (.NET 8) tray application:

- Starts automatically at login (opt-in, via a tray menu checkbox).
- Runs minimized to the system tray - the tray icon is always visible; the
  window itself is not shown until you open it.
- Automatically pops its window to the front whenever a USB/removable drive
  is connected.
- Closing the window (the X button) minimizes it back to the tray instead of
  quitting; use the tray icon's right-click **Exit** to actually stop it.

This is intentionally **not** a hidden/silent background process: the tray
icon is the always-present, user-visible indicator that the app is running,
and it's the control point for turning "start with Windows" on/off and for
quitting.

## Requirements

- Windows 10/11
- .NET 8 SDK to build: https://dotnet.microsoft.com/download/dotnet/8.0
- No Administrator rights are required to run it or to enable "Start with
  Windows" - the startup entry is written to
  `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`, which
  only affects the currently logged-in user and needs no elevation.

## Build

From a Command Prompt / PowerShell in this folder:

```
dotnet build -c Release
```

Run it straight from source:

```
dotnet run
```

## Publish a standalone .exe

```
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

The .exe is written to:

```
bin\Release\net8.0-windows\win-x64\publish\UsbTrayWatcher.exe
```

This build embeds the .NET runtime, so it runs on a PC with no .NET
installed. Copy that one .exe wherever you like (e.g.
`%LOCALAPPDATA%\UsbTrayWatcher\UsbTrayWatcher.exe`) - once it's enabled to
start with Windows, the registry entry points at wherever you placed it, so
move it *before* checking that box.

## First run

1. Double-click `UsbTrayWatcher.exe`. A window explaining what it does
   appears once; close it and the icon stays in the tray (bottom-right,
   near the clock - click the `^` arrow if it's hidden there).
2. Right-click the tray icon → check **Start with Windows** if you want it
   to launch automatically at login.
3. Plug in a USB drive. The window should pop to the front with a tray
   balloon notification.
4. Right-click the tray icon → **Exit** to fully stop it, or uncheck
   **Start with Windows** first if you also want it to stop launching at
   login.

## How the pieces fit together

| File                         | Responsibility                                             |
|-------------------------------|-------------------------------------------------------------|
| `Program.cs`                  | Entry point; single-instance guard via a named mutex.       |
| `TrayApplicationContext.cs`   | Owns the always-visible `NotifyIcon` and its menu.          |
| `MainForm.cs` / `.Designer.cs`| The window; handles `WM_DEVICECHANGE` for USB arrival.      |
| `StartupManager.cs`           | Reads/writes the one HKCU `Run` registry value it owns.     |

### Note on this sandbox

I don't have a Windows machine or the .NET SDK available here, so I
reviewed this code carefully but could not compile or run it myself.
Build it with `dotnet build` on a Windows PC as a first check before relying
on it, and treat this as a working starting point rather than a
compiled-and-tested binary.
