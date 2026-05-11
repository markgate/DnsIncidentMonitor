using System.ComponentModel;

namespace DnsIncidentMonitor;

public sealed class DnsRecord : INotifyPropertyChanged
{
    private string _responseIp = "";
    private string _duration = "";
    private string _status = "Pending";

    public DateTime Time { get; init; } = DateTime.Now;
    public string ProcessName { get; init; } = "";
    public int ProcessId { get; init; }
    public string HostName { get; init; } = "";
    public string QueryType { get; init; } = "";
    public string ResponseIp
    {
        get => _responseIp;
        set { _responseIp = value; OnChanged(nameof(ResponseIp)); }
    }
    public string Duration
    {
        get => _duration;
        set { _duration = value; OnChanged(nameof(Duration)); }
    }
    public string Status
    {
        get => _status;
        set { _status = value; OnChanged(nameof(Status)); }
    }
    public string Source { get; init; } = "";
    public string Destination { get; init; } = "";
    public string SourcePort { get; init; } = "";
    public string DestinationPort { get; init; } = "";
    public ushort TransactionId { get; init; }
    public DateTime StartedAt { get; init; } = DateTime.Now;

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
