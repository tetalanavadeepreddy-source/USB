using System;
using Microsoft.Win32;

namespace UsbTrayWatcher
{
    /// <summary>
    /// Reads and writes the single "run at login" registry value this app owns.
    /// Uses HKEY_CURRENT_USER, so no Administrator rights are required - it only
    /// affects the currently logged-in user, matching how most legitimate
    /// "Start with Windows" checkboxes work (Discord, Slack, Dropbox, etc.).
    /// This is the ONLY code path that writes or deletes this value, and it only
    /// runs when the user explicitly checks/unchecks the tray menu item - never
    /// automatically and never silently on launch.
    /// </summary>
    internal static class StartupManager
    {
        private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string ValueName = "UsbTrayWatcher";

        public static bool IsEnabled()
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
            return key?.GetValue(ValueName) is string existing
                   && string.Equals(existing.Trim('"'), ExecutablePath(), StringComparison.OrdinalIgnoreCase);
        }

        public static void Enable()
        {
            using RegistryKey key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true)
                ?? throw new InvalidOperationException("Could not open HKCU Run key.");
            // Quote the path in case the install location contains spaces.
            key.SetValue(ValueName, $"\"{ExecutablePath()}\"", RegistryValueKind.String);
        }

        public static void Disable()
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            key?.DeleteValue(ValueName, throwOnMissingValue: false);
        }

        private static string ExecutablePath() =>
            Environment.ProcessPath ?? Application_ExecutablePathFallback();

        // Environment.ProcessPath is null only in unusual hosting scenarios; this
        // keeps the method safe without pulling in System.Windows.Forms here.
        private static string Application_ExecutablePathFallback() =>
            System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
            ?? throw new InvalidOperationException("Could not determine the executable's path.");
    }
}
