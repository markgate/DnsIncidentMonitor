namespace DnsIncidentMonitor;

public sealed class CaptureOptionsForm : Form
{
    private readonly ComboBox _adapterBox = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly ComboBox _modeBox = new() { DropDownStyle = ComboBoxStyle.DropDownList };

    public CaptureAdapter? SelectedAdapter => _adapterBox.SelectedItem as CaptureAdapter;

    public CaptureOptionsForm(IReadOnlyList<CaptureAdapter> adapters)
    {
        Text = "Capture Options";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(520, 175);

        Label adapterLabel = new() { Text = "Capture adapter", AutoSize = true, Location = new Point(16, 20) };
        _adapterBox.Location = new Point(150, 16);
        _adapterBox.Size = new Size(345, 25);
        _adapterBox.Items.AddRange(adapters.Cast<object>().ToArray());
        if (_adapterBox.Items.Count > 0)
        {
            _adapterBox.SelectedIndex = 0;
        }

        Label modeLabel = new() { Text = "Capture mode", AutoSize = true, Location = new Point(16, 64) };
        _modeBox.Location = new Point(150, 60);
        _modeBox.Size = new Size(345, 25);
        _modeBox.Items.Add("Raw Sockets (default, IPv4 UDP/TCP 53, no driver)");
        _modeBox.SelectedIndex = 0;

        Label hint = new()
        {
            Text = "Run as Administrator is required. Raw Sockets is recommended for incident response.",
            AutoSize = true,
            Location = new Point(16, 102)
        };

        Button ok = new() { Text = "Start", DialogResult = DialogResult.OK, Location = new Point(318, 136), Size = new Size(82, 28) };
        Button cancel = new() { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(413, 136), Size = new Size(82, 28) };
        AcceptButton = ok;
        CancelButton = cancel;

        Controls.AddRange(new Control[] { adapterLabel, _adapterBox, modeLabel, _modeBox, hint, ok, cancel });
    }
}
