using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace DnsIncidentMonitor;

public sealed class EtwDnsClientService : IDisposable
{
    private const string ChannelName = "Microsoft-Windows-DNS-Client/Operational";
    private EventLogWatcher? _watcher;

    public event Action<DnsRecord>? RecordCaptured;
    public event Action<Exception>? WatchFailed;

    public void Start()
    {
        Stop();
        EnableChannel();

        EventLogQuery query = new(ChannelName, PathType.LogName, "*[System[Provider[@Name='Microsoft-Windows-DNS-Client']]]")
        {
            ReverseDirection = false
        };
        _watcher = new EventLogWatcher(query);
        _watcher.EventRecordWritten += OnEventRecordWritten;
        _watcher.Enabled = true;
    }

    public void Stop()
    {
        if (_watcher is not null)
        {
            _watcher.Enabled = false;
            _watcher.EventRecordWritten -= OnEventRecordWritten;
            _watcher.Dispose();
            _watcher = null;
        }
    }

    private static void EnableChannel()
    {
        using EventLogConfiguration configuration = new(ChannelName);
        if (!configuration.IsEnabled)
        {
            configuration.IsEnabled = true;
            configuration.SaveChanges();
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventException is not null)
            {
                WatchFailed?.Invoke(e.EventException);
                return;
            }

            using EventRecord? eventRecord = e.EventRecord;
            if (eventRecord is null)
            {
                return;
            }

            DnsRecord? record = ParseRecord(eventRecord);
            if (record is not null)
            {
                RecordCaptured?.Invoke(record);
            }
        }
        catch (Exception ex)
        {
            WatchFailed?.Invoke(ex);
        }
    }

    private static DnsRecord? ParseRecord(EventRecord eventRecord)
    {
        XDocument document = XDocument.Parse(eventRecord.ToXml());
        XNamespace ns = document.Root?.Name.Namespace ?? XNamespace.None;

        Dictionary<string, string> data = document
            .Descendants(ns + "Data")
            .Select((node, index) => new
            {
                Name = (string?)node.Attribute("Name") ?? "Field" + index,
                Value = node.Value
            })
            .Where(item => !string.IsNullOrWhiteSpace(item.Value))
            .GroupBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().Value, StringComparer.OrdinalIgnoreCase);

        foreach (XElement element in document.Descendants())
        {
            if (!element.HasElements && !string.IsNullOrWhiteSpace(element.Value))
            {
                data.TryAdd(element.Name.LocalName, element.Value);
            }

            foreach (XAttribute attribute in element.Attributes())
            {
                if (!string.IsNullOrWhiteSpace(attribute.Value))
                {
                    data.TryAdd(attribute.Name.LocalName, attribute.Value);
                    data.TryAdd(element.Name.LocalName + "." + attribute.Name.LocalName, attribute.Value);
                }
            }
        }

        string host = FirstValue(data, "QueryName", "Name", "HostName", "FQDN", "QuestionName");
        if (string.IsNullOrWhiteSpace(host))
        {
            host = GuessHost(data.Values);
        }

        if (string.IsNullOrWhiteSpace(host))
        {
            return null;
        }

        int pid = ParseInt(FirstValue(data, "ProcessId", "PID", "ClientProcessId", "ClientPID"));
        ProcessInfo process = ProcessResolver.ResolvePid(pid);

        string status = FirstValue(data, "Status", "QueryStatus", "Result", "ResultCode", "ErrorCode");
        if (string.IsNullOrWhiteSpace(status))
        {
            status = eventRecord.Id.ToString();
        }

        string response = FirstValue(data, "QueryResults", "Results", "Answers", "Response", "Address", "IPAddresses");
        string queryType = NormalizeQueryType(FirstValue(data, "QueryType", "Type", "RecordType", "QType"));
        string duration = FirstValue(data, "QueryDuration", "Duration", "ElapsedTime");
        string sourceIp = FirstIp(FirstValue(data, "SourceAddress", "SourceIp", "SourceIP", "ClientAddress", "ClientIp", "ClientIP", "LocalAddress", "LocalIp", "LocalIP"));
        string destinationIp = FirstIp(FirstValue(data, "DestinationAddress", "DestinationIp", "DestinationIP", "ServerAddress", "ServerIp", "ServerIP", "DnsServer", "DnsServerIp", "DnsServerIP", "RemoteAddress", "RemoteIp", "RemoteIP"));

        DateTime eventTime = eventRecord.TimeCreated ?? DateTime.Now;

        return new DnsRecord
        {
            Time = eventTime,
            ProcessName = process.ProcessName,
            ProcessId = process.ProcessId,
            HostName = host.TrimEnd('.'),
            QueryType = queryType,
            ResponseIp = response,
            Duration = NormalizeDuration(duration),
            Status = NormalizeStatus(status),
            Source = sourceIp,
            Destination = destinationIp,
            StartedAt = eventTime
        };
    }

    private static string FirstValue(Dictionary<string, string> data, params string[] names)
    {
        foreach (string name in names)
        {
            if (data.TryGetValue(name, out string? value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return "";
    }

    private static string GuessHost(IEnumerable<string> values)
    {
        foreach (string value in values)
        {
            string candidate = value.Trim().TrimEnd('.');
            if (candidate.Contains('.') &&
                !candidate.Contains(' ') &&
                !candidate.Contains(':') &&
                candidate.Any(char.IsLetter))
            {
                return candidate;
            }
        }

        return "";
    }

    private static int ParseInt(string value) =>
        int.TryParse(value, out int result) ? result : 0;

    private static string NormalizeQueryType(string value) =>
        value switch
        {
            "1" => "A",
            "5" => "CNAME",
            "12" => "PTR",
            "15" => "MX",
            "16" => "TXT",
            "28" => "AAAA",
            "33" => "SRV",
            "65" => "HTTPS",
            _ => value
        };

    private static string NormalizeStatus(string value) =>
        value switch
        {
            "0" => "NOERROR",
            "9003" => "NXDOMAIN",
            _ => value
        };

    private static string NormalizeDuration(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        return value.EndsWith("ms", StringComparison.OrdinalIgnoreCase) ? value : value + " ms";
    }

    private static string FirstIp(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        string[] parts = value.Split(new[] { ';', ',', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string part in parts)
        {
            string candidate = part.Trim('[', ']', '(', ')');
            if (System.Net.IPAddress.TryParse(candidate, out System.Net.IPAddress? address))
            {
                return address.ToString();
            }
        }

        return "";
    }

    public void Dispose() => Stop();
}
