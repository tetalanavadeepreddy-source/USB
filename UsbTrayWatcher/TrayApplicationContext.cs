using System;
using System.Drawing;
using System.Windows.Forms;

namespace UsbTrayWatcher
{
    /// <summary>
    /// Owns the tray icon for the lifetime of the process. The icon is visible from the
    /// moment the app starts (including when launched automatically at login) until the
    /// user picks "Exit" - there is no state in which the app runs with no visible sign
    /// of itself in the UI. That icon and its right-click menu are the user's control
    /// point: it always shows the "Start with Windows" checkbox state, and quitting from
    /// there fully stops the process.
    /// </summary>
    public sealed class TrayApplicationContext : ApplicationContext
    {
        public static TrayApplicationContext? Instance { get; private set; }

        private readonly NotifyIcon _trayIcon;
        private readonly MainForm _mainForm;
        private readonly ToolStripMenuItem _startupMenuItem;

        public TrayApplicationContext()
        {
            Instance = this;
            _mainForm = new MainForm();

            var menu = new ContextMenuStrip();

            var openItem = new ToolStripMenuItem("Open", null, (_, _) => _mainForm.RestoreAndActivate());
            menu.Items.Add(openItem);

            _startupMenuItem = new ToolStripMenuItem("Start with Windows", null, ToggleStartup)
            {
                Checked = StartupManager.IsEnabled(),
                CheckOnClick = false, // we set Checked manually after confirming the registry write succeeded
            };
            menu.Items.Add(_startupMenuItem);

            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(new ToolStripMenuItem("Exit", null, (_, _) => ExitApplication()));

            _trayIcon = new NotifyIcon
            {
                Icon = LoadTrayIcon(),
                Text = "USB Tray Watcher - running",
                Visible = true,
                ContextMenuStrip = menu,
            };
            // Left double-click is the conventional "open" gesture for tray apps.
            _trayIcon.DoubleClick += (_, _) => _mainForm.RestoreAndActivate();

            // Launch minimized to the tray - the window itself is not shown on startup,
            // but the tray icon (the user-visible indicator that the app is running) is
            // shown immediately, and one click/double-click opens the window.
            _mainForm.MinimizeToTray();
        }

        private void ToggleStartup(object? sender, EventArgs e)
        {
            bool wantEnabled = !_startupMenuItem.Checked;
            try
            {
                if (wantEnabled) StartupManager.Enable();
                else StartupManager.Disable();
                _startupMenuItem.Checked = wantEnabled;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Could not update the Windows startup setting:\n\n{ex.Message}",
                    "USB Tray Watcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public void ShowBalloon(string title, string text) =>
            _trayIcon.ShowBalloonTip(4000, title, text, ToolTipIcon.Info);

        private void ExitApplication()
        {
            _trayIcon.Visible = false; // remove immediately; otherwise it can linger until moused-over
            _trayIcon.Dispose();
            _mainForm.Dispose();
            Application.Exit();
        }

        private static Icon LoadTrayIcon()
        {
            // Falls back to a built-in system icon if app.ico isn't found, so the
            // project still runs before you've supplied your own branded .ico file.
            try { return new Icon("app.ico"); }
            catch { return SystemIcons.Application; }
        }
    }
}
