using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace UsbTrayWatcher
{
    /// <summary>
    /// The application's visible window. It is never truly hidden from the user:
    /// - A tray icon (owned by TrayApplicationContext) is shown at all times the app runs.
    /// - "Minimize to tray" hides the taskbar window but the tray icon remains, and a
    ///   single click on the tray icon or a USB insertion brings the window straight back.
    /// This mirrors how OneDrive, Slack, Dropbox, etc. behave - never a fully hidden process.
    /// </summary>
    public partial class MainForm : Form
    {
        // --- Win32 interop for USB (device) change notifications -----------------
        // Windows delivers WM_DEVICECHANGE to every top-level window automatically for
        // volume arrival/removal - no RegisterDeviceNotification call is required for
        // DBT_DEVTYP_VOLUME events, which is what we need for "a drive appeared".
        private const int WM_DEVICECHANGE = 0x0219;
        private const int DBT_DEVICEARRIVAL = 0x8000;      // a device has been inserted
        private const int DBT_DEVTYP_VOLUME = 0x0002;      // the device is a logical volume (drive)
        private const int DBTF_MEDIA = 0x0001;              // (unused here, kept for reference)

        [StructLayout(LayoutKind.Sequential)]
        private struct DEV_BROADCAST_VOLUME
        {
            public int dbcv_size;
            public int dbcv_devicetype;
            public int dbcv_reserved;
            public int dbcv_unitmask; // bit N set => drive letter (N + 'A') was affected
            public short dbcv_flags;
        }

        public MainForm()
        {
            InitializeComponent();

            // Closing the window (the X button) just minimizes to tray instead of exiting -
            // the app keeps watching for USB devices. Real exit is via the tray menu's "Exit".
            FormClosing += MainForm_FormClosing;
        }

        private void MainForm_FormClosing(object? sender, FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                MinimizeToTray();
            }
        }

        public void MinimizeToTray()
        {
            Hide();               // removes it from the taskbar; the tray icon is still visible
            ShowInTaskbar = false;
        }

        /// <summary>Brings the window to the front, restoring it if it was minimized to tray.</summary>
        public void RestoreAndActivate()
        {
            ShowInTaskbar = true;
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
            TopMost = true;   // brief nudge so Windows lets it steal focus...
            TopMost = false;  // ...then release it so it behaves like a normal window afterward.
        }

        /// <summary>
        /// Intercepts Windows messages sent to this window. WM_DEVICECHANGE with
        /// DBT_DEVICEARRIVAL + DBT_DEVTYP_VOLUME fires when a USB drive (or any
        /// removable/fixed volume) is mounted - which is exactly "a USB drive was inserted"
        /// for the vast majority of real-world cases.
        /// </summary>
        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m); // let WinForms handle everything as normal first

            if (m.Msg != WM_DEVICECHANGE || m.WParam.ToInt32() != DBT_DEVICEARRIVAL)
                return;

            var volume = Marshal.PtrToStructure<DEV_BROADCAST_VOLUME>(m.LParam);
            if (volume.dbcv_devicetype != DBT_DEVTYP_VOLUME)
                return;

            // Work out which drive letter(s) just appeared, purely for the tray notification text.
            string letters = DriveLettersFromMask(volume.dbcv_unitmask);

            BeginInvoke(() =>
            {
                RestoreAndActivate();
                TrayApplicationContext.Instance?.ShowBalloon(
                    "USB device connected",
                    string.IsNullOrEmpty(letters) ? "A drive was connected." : $"Drive {letters} was connected.");
            });
        }

        private static string DriveLettersFromMask(int unitMask)
        {
            var letters = new System.Collections.Generic.List<string>();
            for (int bit = 0; bit < 26; bit++)
            {
                if ((unitMask & (1 << bit)) != 0)
                    letters.Add(((char)('A' + bit)).ToString());
            }
            return string.Join(", ", letters);
        }
    }
}
