using System;
using System.Threading;
using System.Windows.Forms;

namespace UsbTrayWatcher
{
    internal static class Program
    {
        // Named mutex so a second launch (e.g. the user double-clicks the EXE again,
        // or Windows starts it while it's already running from a previous login)
        // doesn't spawn a duplicate tray icon.
        private const string SingleInstanceMutexName = "Local\\UsbTrayWatcher.SingleInstance";

        [STAThread]
        private static void Main()
        {
            using var mutex = new Mutex(initiallyOwned: true, SingleInstanceMutexName, out bool createdNew);
            if (!createdNew)
            {
                // Already running - just exit quietly. (A future enhancement could send
                // a message to the existing instance asking it to show its window.)
                return;
            }

            ApplicationConfiguration.Initialize();
            Application.Run(new TrayApplicationContext());
        }
    }
}
