using System.ComponentModel;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;

namespace DnsIncidentMonitor;

public sealed class MainForm : Form
{
    private enum CaptureMode
    {
        RawSockets,
        EtwDnsClient
    }

    private static readonly Color PageBackground = Color.FromArgb(247, 247, 250);
    private static readonly Color CardBackground = Color.White;
    private static readonly Color PrimaryPurple = Color.FromArgb(111, 93, 232);
    private static readonly Color LightPurple = Color.FromArgb(235, 229, 255);
    private static readonly Color SoftPurple = Color.FromArgb(246, 243, 255);
    private static readonly Color TextPrimary = Color.FromArgb(48, 52, 65);
    private static readonly Color TextSecondary = Color.FromArgb(128, 132, 145);
    private static readonly Color BorderLight = Color.FromArgb(232, 234, 240);
    private static readonly Color HeaderGray = Color.FromArgb(248, 248, 250);
    private static readonly Font UiFont = new("Segoe UI", 9F, FontStyle.Regular);
    private static readonly Font BoldUiFont = new("Segoe UI", 9F, FontStyle.Bold);
    private static readonly Font TitleFont = new("Segoe UI", 11F, FontStyle.Bold);

    private readonly DnsCaptureService _capture = new();
    private readonly EtwDnsClientService _etwCapture = new();
    private readonly BindingList<DnsRecord> _records = new();
    private readonly BindingSource _source = new();
    private readonly Dictionary<string, DnsRecord> _pending = new();
    private readonly Panel _mainPanel = new() { Dock = DockStyle.Fill, BackColor = PageBackground };
    private readonly Panel _contentCard = new() { Dock = DockStyle.Fill, BackColor = CardBackground, Padding = new Padding(20, 14, 20, 14) };
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill,
        ReadOnly = true,
        AllowUserToAddRows = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        MultiSelect = true,
        RowHeadersVisible = false,
        ColumnHeadersVisible = true,
        ColumnHeadersHeight = 30,
        ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing
    };
    private readonly TextBox _filterBox = new() { Width = 360, PlaceholderText = "contains:malicious.com / process:chrome.exe / response:NXDOMAIN" };
    private readonly ToolStripStatusLabel _status = new("Ready");
    private Button? _rawModeButton;
    private Button? _etwModeButton;
    private CaptureMode _mode = CaptureMode.EtwDnsClient;
    private int _dnsPacketCount;
    private int _queryCount;
    private int _responseCount;
    private CaptureAdapter? _adapter;

    public MainForm()
    {
        Text = "DNS Incident Monitor";
        Width = 1420;
        Height = 720;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = PageBackground;
        Font = UiFont;

        BuildShell();
        BuildGrid();
        BuildToolbar();

        StatusStrip statusStrip = new() { Dock = DockStyle.Bottom, BackColor = CardBackground, Font = BoldUiFont, SizingGrip = false };
        statusStrip.Items.Add(_status);
        _contentCard.Controls.Add(statusStrip);

        _source.DataSource = _records;
        _grid.DataSource = _source;

        _capture.MessageCaptured += OnMessageCaptured;
        _capture.CaptureFailed += ex => BeginInvoke(() => MessageBox.Show(this, ex.Message, "Capture failed", MessageBoxButtons.OK, MessageBoxIcon.Error));
        _etwCapture.RecordCaptured += OnEtwRecordCaptured;
        _etwCapture.WatchFailed += ex => BeginInvoke(() => MessageBox.Show(this, ex.Message, "ETW DNS Client failed", MessageBoxButtons.OK, MessageBoxIcon.Error));
        Shown += (_, _) => FirstStart();
        FormClosing += (_, _) =>
        {
            _capture.Dispose();
            _etwCapture.Dispose();
        };
    }

    private void BuildShell()
    {
        Panel topBar = new()
        {
            Dock = DockStyle.Top,
            Height = 58,
            BackColor = CardBackground,
            Padding = new Padding(20, 14, 20, 12)
        };

        FlowLayoutPanel menuBar = new()
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = CardBackground
        };

        menuBar.Controls.Add(CreateMenuButton("选择捕获器", Color.FromArgb(151, 129, 246), Color.White, 104, (_, _) => ShowCaptureOptions()));
        menuBar.Controls.Add(CreateMenuButton("开始监听", Color.FromArgb(88, 188, 119), Color.White, 92, (_, _) => StartCapture()));
        menuBar.Controls.Add(CreateMenuButton("结束监听", Color.FromArgb(255, 168, 64), Color.White, 92, (_, _) => StopCapture()));

        _filterBox.Width = 250;
        _filterBox.Height = 28;
        _filterBox.Margin = new Padding(0, 0, 8, 0);
        _filterBox.BorderStyle = BorderStyle.FixedSingle;
        _filterBox.Font = UiFont;
        menuBar.Controls.Add(_filterBox);

        menuBar.Controls.Add(CreateMenuButton("搜索记录", PrimaryPurple, Color.White, 92, (_, _) => ApplyFilter()));
        menuBar.Controls.Add(CreateMenuButton("导出记录", Color.FromArgb(151, 129, 246), Color.White, 92, (_, _) => SaveSelected()));
        menuBar.Controls.Add(CreateMenuButton("清空记录", Color.FromArgb(255, 236, 236), Color.FromArgb(236, 112, 112), 92, (_, _) => ClearRecords()));
        Panel modePanel = new()
        {
            Dock = DockStyle.Right,
            Width = 260,
            BackColor = CardBackground,
            Padding = new Padding(0, 0, 12, 0)
        };
        _etwModeButton = CreateModeButton("ETW DNS Client", CaptureMode.EtwDnsClient);
        _rawModeButton = CreateModeButton("Raw Sockets", CaptureMode.RawSockets);
        modePanel.Controls.Add(_rawModeButton);
        modePanel.Controls.Add(_etwModeButton);

        topBar.Controls.Add(modePanel);
        topBar.Controls.Add(menuBar);

        Panel page = new()
        {
            Dock = DockStyle.Fill,
            BackColor = PageBackground,
            Padding = new Padding(14)
        };
        page.Controls.Add(_contentCard);

        _mainPanel.Controls.Add(page);
        _mainPanel.Controls.Add(topBar);
        Controls.Add(_mainPanel);
    }

    private void BuildToolbar()
    {
        Panel toolbar = new()
        {
            Dock = DockStyle.Top,
            Height = 82,
            BackColor = CardBackground,
            Padding = new Padding(0, 0, 0, 10)
        };

        Label note = new()
        {
            Dock = DockStyle.Bottom,
            Height = 24,
            Text = "提示：ETW DNS Client 更适合记录 Chrome/系统 DNS 行为；Raw Sockets 仅记录本机 IPv4 UDP/TCP 53 网络包。",
            Font = BoldUiFont,
            ForeColor = TextSecondary,
            TextAlign = ContentAlignment.MiddleLeft
        };

        FlowLayoutPanel actions = new()
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = CardBackground
        };

        Label tab = new()
        {
            Text = "  DNS 监控  ×  ",
            Width = 108,
            Height = 28,
            Margin = new Padding(0, 2, 10, 0),
            TextAlign = ContentAlignment.MiddleCenter,
            Font = BoldUiFont,
            ForeColor = PrimaryPurple,
            BackColor = SoftPurple
        };

        actions.Controls.Add(tab);

        _filterBox.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                ApplyFilter();
                e.SuppressKeyPress = true;
            }
        };
        toolbar.Controls.Add(actions);
        toolbar.Controls.Add(note);
        _contentCard.Controls.Add(toolbar);
    }

    private void BuildGrid()
    {
        _grid.AutoGenerateColumns = false;
        _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        _grid.EnableHeadersVisualStyles = false;
        _grid.BackgroundColor = CardBackground;
        _grid.GridColor = BorderLight;
        _grid.BorderStyle = BorderStyle.None;
        _grid.DefaultCellStyle.BackColor = CardBackground;
        _grid.DefaultCellStyle.ForeColor = TextPrimary;
        _grid.DefaultCellStyle.Font = UiFont;
        _grid.DefaultCellStyle.SelectionBackColor = LightPurple;
        _grid.DefaultCellStyle.SelectionForeColor = PrimaryPurple;
        _grid.DefaultCellStyle.Padding = new Padding(8, 0, 8, 0);
        _grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(253, 253, 255);
        _grid.AlternatingRowsDefaultCellStyle.SelectionBackColor = LightPurple;
        _grid.AlternatingRowsDefaultCellStyle.SelectionForeColor = PrimaryPurple;
        _grid.RowTemplate.Height = 34;
        _grid.ColumnHeadersDefaultCellStyle.BackColor = HeaderGray;
        _grid.ColumnHeadersDefaultCellStyle.ForeColor = TextSecondary;
        _grid.ColumnHeadersDefaultCellStyle.Font = BoldUiFont;
        _grid.ColumnHeadersDefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleLeft;
        _grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(8, 0, 8, 0);
        _grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single;
        _grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.Time), "时间", 120));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.ProcessName), "进程名称", 130));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.ProcessId), "进程ID", 80));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.HostName), "解析域名", 260));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.QueryType), "记录类型", 90));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.ResponseIp), "响应IP", 220));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.Status), "响应状态", 95));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.Source), "源地址", 145));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.SourcePort), "源端口", 80));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.Destination), "目标地址", 145));
        _grid.Columns.Add(TextColumn(nameof(DnsRecord.DestinationPort), "目的端口", 80));
        _contentCard.Controls.Add(_grid);
    }

    private static Button CreateActionButton(string text, Color backColor, Color foreColor, EventHandler onClick)
    {
        Button button = new()
        {
            Text = text,
            Width = 64,
            Height = 28,
            Margin = new Padding(0, 2, 8, 0),
            FlatStyle = FlatStyle.Flat,
            Font = BoldUiFont,
            ForeColor = foreColor,
            BackColor = backColor,
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderColor = backColor;
        button.Click += onClick;
        return button;
    }

    private static Button CreateMenuButton(string text, Color backColor, Color foreColor, int width, EventHandler onClick)
    {
        Button button = new()
        {
            Text = text,
            Width = width,
            Height = 28,
            Margin = new Padding(0, 0, 8, 0),
            FlatStyle = FlatStyle.Flat,
            Font = BoldUiFont,
            ForeColor = foreColor,
            BackColor = backColor,
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderColor = backColor;
        button.Click += onClick;
        return button;
    }

    private static Label CreateMenuLabel(string text) =>
        new()
        {
            Text = text,
            Width = 38,
            Height = 28,
            Margin = new Padding(0, 0, 6, 0),
            TextAlign = ContentAlignment.MiddleLeft,
            Font = BoldUiFont,
            ForeColor = TextPrimary,
            BackColor = CardBackground
        };

    private Button CreateModeButton(string text, CaptureMode mode)
    {
        Button button = new()
        {
            Text = text,
            Dock = DockStyle.Right,
            Width = mode == CaptureMode.EtwDnsClient ? 128 : 106,
            FlatStyle = FlatStyle.Flat,
            Font = BoldUiFont,
            Cursor = Cursors.Hand,
            Margin = Padding.Empty
        };
        button.FlatAppearance.BorderSize = 1;
        button.Click += (_, _) => SwitchMode(mode);
        return button;
    }

    private static DataGridViewTextBoxColumn TextColumn(string property, string header, int width) =>
        new() { DataPropertyName = property, HeaderText = header, Width = width, MinimumWidth = Math.Min(width, 80) };

    private void FirstStart()
    {
        if (!IsAdministrator())
        {
            MessageBox.Show(this, "Raw Sockets capture requires Administrator privileges. Please right-click and run as administrator.", "Administrator required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            _status.Text = "Administrator privileges required";
            return;
        }

        UpdateModeButtons();
        StartCapture();
    }

    private void ShowCaptureOptions()
    {
        _mode = CaptureMode.RawSockets;
        UpdateModeButtons();

        IReadOnlyList<CaptureAdapter> adapters = DnsCaptureService.GetAdapters();
        if (adapters.Count == 0)
        {
            MessageBox.Show(this, "No active IPv4 adapters were found.", "Capture Options", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        using CaptureOptionsForm form = new(adapters);
        if (form.ShowDialog(this) == DialogResult.OK && form.SelectedAdapter is not null)
        {
            _adapter = form.SelectedAdapter;
            StartCapture();
        }
    }

    private void StartCapture()
    {
        StopCurrentCapture();
        if (_mode == CaptureMode.EtwDnsClient)
        {
            try
            {
                _etwCapture.Start();
                UpdateModeButtons();
                UpdateStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "无法启动 ETW DNS Client 模式：" + ex.Message, "Capture failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            return;
        }

        if (_adapter is null)
        {
            ShowCaptureOptions();
            return;
        }

        try
        {
            _capture.Start(_adapter);
            UpdateModeButtons();
            UpdateStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Capture failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void StopCapture()
    {
        StopCurrentCapture();
        _status.Text = "Stopped";
    }

    private void ClearRecords()
    {
        _records.Clear();
        _pending.Clear();
        _dnsPacketCount = 0;
        _queryCount = 0;
        _responseCount = 0;
        ApplyFilter();
    }

    private void StopCurrentCapture()
    {
        _capture.Stop();
        _etwCapture.Stop();
    }

    private void SwitchMode(CaptureMode mode)
    {
        if (_mode == mode)
        {
            return;
        }

        _mode = mode;
        UpdateModeButtons();
        StartCapture();
    }

    private void UpdateModeButtons()
    {
        SetModeButtonState(_rawModeButton, _mode == CaptureMode.RawSockets);
        SetModeButtonState(_etwModeButton, _mode == CaptureMode.EtwDnsClient);
    }

    private static void SetModeButtonState(Button? button, bool active)
    {
        if (button is null)
        {
            return;
        }

        button.BackColor = active ? PrimaryPurple : SoftPurple;
        button.ForeColor = active ? Color.White : PrimaryPurple;
        button.FlatAppearance.BorderColor = active ? PrimaryPurple : LightPurple;
    }

    private void OnMessageCaptured(CapturedDnsMessage message)
    {
        BeginInvoke(() =>
        {
            _dnsPacketCount++;
            if (message.Packet.IsResponse)
            {
                _responseCount++;
            }
            else
            {
                _queryCount++;
            }

            string key = PendingKey(message.Packet.TransactionId, message.Packet.HostName, message.SourcePort, message.DestinationPort);
            if (!message.Packet.IsResponse)
            {
                DnsRecord record = new()
                {
                    Time = DateTime.Now,
                    ProcessName = message.Process.ProcessName,
                    ProcessId = message.Process.ProcessId,
                    HostName = message.Packet.HostName,
                    QueryType = message.Packet.QueryType,
                    Source = message.SourceAddress.ToString(),
                    Destination = message.DestinationAddress.ToString(),
                    SourcePort = message.SourcePort.ToString(),
                    DestinationPort = message.DestinationPort.ToString(),
                    TransactionId = message.Packet.TransactionId,
                    StartedAt = DateTime.Now
                };
                _records.Insert(0, record);
                _pending[key] = record;
                TrimRecords();
            }
            else
            {
                DnsRecord? record = FindPending(message);
                if (record is not null)
                {
                    record.ResponseIp = string.IsNullOrWhiteSpace(message.Packet.ResponseText) ? message.Packet.Status : message.Packet.ResponseText;
                    record.Status = message.Packet.Status;
                    record.Duration = (DateTime.Now - record.StartedAt).TotalMilliseconds.ToString("0") + " ms";
                }
                else
                {
                    AddResponseOnly(message);
                }
            }
            ApplyFilter();
        });
    }

    private void OnEtwRecordCaptured(DnsRecord record)
    {
        BeginInvoke(() =>
        {
            _dnsPacketCount++;
            _queryCount++;
            if (!string.IsNullOrWhiteSpace(record.ResponseIp) || !record.Status.Equals("Pending", StringComparison.OrdinalIgnoreCase))
            {
                _responseCount++;
            }

            _records.Insert(0, record);
            TrimRecords();
            ApplyFilter();
        });
    }

    private DnsRecord? FindPending(CapturedDnsMessage message)
    {
        string key = PendingKey(message.Packet.TransactionId, message.Packet.HostName, message.DestinationPort, message.SourcePort);
        if (_pending.Remove(key, out DnsRecord? record))
        {
            return record;
        }

        return _pending.Values.FirstOrDefault(r => r.TransactionId == message.Packet.TransactionId && r.HostName.Equals(message.Packet.HostName, StringComparison.OrdinalIgnoreCase));
    }

    private void AddResponseOnly(CapturedDnsMessage message)
    {
        DnsRecord record = new()
        {
            Time = DateTime.Now,
            ProcessName = message.Process.ProcessName,
            ProcessId = message.Process.ProcessId,
            HostName = message.Packet.HostName,
            QueryType = message.Packet.QueryType,
            ResponseIp = string.IsNullOrWhiteSpace(message.Packet.ResponseText) ? message.Packet.Status : message.Packet.ResponseText,
            Status = message.Packet.Status,
            Source = message.SourceAddress.ToString(),
            Destination = message.DestinationAddress.ToString(),
            SourcePort = message.SourcePort.ToString(),
            DestinationPort = message.DestinationPort.ToString(),
            TransactionId = message.Packet.TransactionId
        };
        _records.Insert(0, record);
        TrimRecords();
    }

    private static string PendingKey(ushort id, string host, ushort sourcePort, ushort destinationPort) =>
        $"{id}:{host.ToLowerInvariant()}:{sourcePort}:{destinationPort}";

    private void TrimRecords()
    {
        while (_records.Count > 10000)
        {
            _records.RemoveAt(_records.Count - 1);
        }
    }

    private void ApplyFilter()
    {
        string filter = _filterBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(filter))
        {
            _source.DataSource = _records;
            UpdateStatus();
            return;
        }

        IEnumerable<DnsRecord> filtered = _records.Where(r => Matches(r, filter));
        _source.DataSource = new BindingList<DnsRecord>(filtered.ToList());
        _status.Text = $"Filtered: {_source.Count} / {_records.Count} | DNS packets: {_dnsPacketCount}, queries: {_queryCount}, responses: {_responseCount}";
    }

    private void UpdateStatus()
    {
        string modeText = _mode == CaptureMode.EtwDnsClient
            ? "Mode: ETW DNS Client"
            : "Mode: Raw Sockets";
        string sourceText = _mode == CaptureMode.RawSockets
            ? (_adapter is null ? "No adapter selected" : $"Capturing on {_adapter}")
            : "Listening Microsoft-Windows-DNS-Client/Operational";
        _status.Text = $"{modeText} | {sourceText} | Records: {_records.Count} | DNS events: {_dnsPacketCount}, queries: {_queryCount}, responses: {_responseCount}";
    }

    private static bool Matches(DnsRecord record, string filter)
    {
        if (filter.StartsWith("contains:", StringComparison.OrdinalIgnoreCase))
        {
            string value = filter["contains:".Length..];
            return Contains(record.HostName, value) || Contains(record.ResponseIp, value);
        }
        if (filter.StartsWith("process:", StringComparison.OrdinalIgnoreCase))
        {
            return Contains(record.ProcessName, filter["process:".Length..]);
        }
        if (filter.StartsWith("response:", StringComparison.OrdinalIgnoreCase))
        {
            string value = filter["response:".Length..];
            return Contains(record.Status, value) || Contains(record.ResponseIp, value);
        }

        return Contains(record.ProcessName, filter) ||
               Contains(record.HostName, filter) ||
               Contains(record.ResponseIp, filter) ||
               Contains(record.Status, filter);
    }

    private static bool Contains(string text, string value) =>
        text.Contains(value, StringComparison.OrdinalIgnoreCase);

    private void SaveSelected()
    {
        List<DnsRecord> selected = _grid.SelectedRows
            .Cast<DataGridViewRow>()
            .Select(r => r.DataBoundItem as DnsRecord)
            .Where(r => r is not null)
            .Cast<DnsRecord>()
            .ToList();

        if (selected.Count == 0)
        {
            MessageBox.Show(this, "Select one or more records first.", "Save Selected Items", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using SaveFileDialog dialog = new()
        {
            Filter = "CSV Files (*.csv)|*.csv|XML Files (*.xml)|*.xml",
            FileName = "dns-evidence-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".csv"
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        if (Path.GetExtension(dialog.FileName).Equals(".xml", StringComparison.OrdinalIgnoreCase))
        {
            SaveXml(dialog.FileName, selected);
        }
        else
        {
            SaveCsv(dialog.FileName, selected);
        }
        _status.Text = "Saved " + selected.Count + " records";
    }

    private static void SaveCsv(string path, IReadOnlyList<DnsRecord> records)
    {
        StringBuilder builder = new();
        builder.AppendLine("Time,Process Name,Process ID,Host Name,Query Type,Response IP,Duration,Response,Source,Source Port,Destination,Destination Port");
        foreach (DnsRecord r in records)
        {
            builder.AppendLine(string.Join(",", Csv(r.Time.ToString("O")), Csv(r.ProcessName), r.ProcessId, Csv(r.HostName), Csv(r.QueryType), Csv(r.ResponseIp), Csv(r.Duration), Csv(r.Status), Csv(r.Source), Csv(r.SourcePort), Csv(r.Destination), Csv(r.DestinationPort)));
        }
        File.WriteAllText(path, builder.ToString(), new UTF8Encoding(true));
    }

    private static string Csv(string value) => "\"" + value.Replace("\"", "\"\"") + "\"";

    private static void SaveXml(string path, IReadOnlyList<DnsRecord> records)
    {
        XElement root = new("DnsEvidence",
            records.Select(r => new XElement("Record",
                new XElement("Time", r.Time.ToString("O")),
                new XElement("ProcessName", r.ProcessName),
                new XElement("ProcessId", r.ProcessId),
                new XElement("HostName", r.HostName),
                new XElement("QueryType", r.QueryType),
                new XElement("ResponseIp", r.ResponseIp),
                new XElement("Duration", r.Duration),
                new XElement("Response", r.Status),
                new XElement("Source", r.Source),
                new XElement("SourcePort", r.SourcePort),
                new XElement("Destination", r.Destination),
                new XElement("DestinationPort", r.DestinationPort))));
        root.Save(path);
    }

    private static bool IsAdministrator()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
