namespace UsbTrayWatcher
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;
        private Label statusLabel;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            statusLabel = new Label();
            SuspendLayout();

            // statusLabel
            statusLabel.Dock = DockStyle.Fill;
            statusLabel.TextAlign = ContentAlignment.MiddleCenter;
            statusLabel.Font = new Font("Segoe UI", 11F);
            statusLabel.Text = "USB Tray Watcher is running.\n\n" +
                               "It sits in the system tray (bottom-right, near the clock).\n" +
                               "This window will pop up automatically whenever a USB\n" +
                               "drive is connected. Closing this window minimizes it to\n" +
                               "the tray - it keeps watching in the background.\n\n" +
                               "Right-click the tray icon for Settings and Exit.";

            // MainForm
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(480, 260);
            Controls.Add(statusLabel);
            Text = "USB Tray Watcher";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(400, 220);
            ResumeLayout(false);
        }
    }
}
