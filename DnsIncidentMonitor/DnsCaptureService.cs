using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace DnsIncidentMonitor;

public sealed record CaptureAdapter(string Name, IPAddress Address)
{
    public override string ToString() => $"{Name} ({Address})";
}

public sealed record CapturedDnsMessage(
    DnsPacket Packet,
    IPAddress SourceAddress,
    ushort SourcePort,
    IPAddress DestinationAddress,
    ushort DestinationPort,
    ProtocolType Protocol,
    ProcessInfo Process);

public sealed class DnsCaptureService : IDisposable
{
    private const int SioRcvAll = unchecked((int)0x98000001);
    private Socket? _socket;
    private CancellationTokenSource? _cts;

    public event Action<CapturedDnsMessage>? MessageCaptured;
    public event Action<Exception>? CaptureFailed;

    public static IReadOnlyList<CaptureAdapter> GetAdapters()
    {
        List<CaptureAdapter> adapters = new();
        foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up ||
                ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
            {
                if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    adapters.Add(new CaptureAdapter(ni.Name, ip.Address));
                }
            }
        }

        return adapters;
    }

    public void Start(CaptureAdapter adapter)
    {
        Stop();
        _cts = new CancellationTokenSource();
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        _socket.Bind(new IPEndPoint(adapter.Address, 0));
        _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        _socket.IOControl(SioRcvAll, BitConverter.GetBytes(1), new byte[4]);
        _ = Task.Run(() => CaptureLoop(_socket, _cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        try
        {
            _socket?.IOControl(SioRcvAll, BitConverter.GetBytes(0), new byte[4]);
        }
        catch
        {
        }
        _socket?.Dispose();
        _socket = null;
        _cts?.Dispose();
        _cts = null;
    }

    private async Task CaptureLoop(Socket socket, CancellationToken token)
    {
        byte[] buffer = new byte[65535];
        try
        {
            while (!token.IsCancellationRequested)
            {
                int received = await socket.ReceiveAsync(buffer, SocketFlags.None, token);
                try
                {
                    ParseIpPacket(buffer.AsSpan(0, received));
                }
                catch
                {
                    // Ignore malformed or unsupported packets. Capture must continue during incident response.
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            CaptureFailed?.Invoke(ex);
        }
    }

    private void ParseIpPacket(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20)
        {
            return;
        }

        int version = packet[0] >> 4;
        int headerLength = (packet[0] & 0x0F) * 4;
        if (version != 4 || headerLength < 20 || packet.Length < headerLength)
        {
            return;
        }

        ProtocolType protocol = (ProtocolType)packet[9];
        IPAddress sourceAddress = new(packet.Slice(12, 4).ToArray());
        IPAddress destinationAddress = new(packet.Slice(16, 4).ToArray());
        ReadOnlySpan<byte> transport = packet[headerLength..];

        if (protocol == ProtocolType.Udp)
        {
            ParseUdp(transport, sourceAddress, destinationAddress);
        }
        else if (protocol == ProtocolType.Tcp)
        {
            ParseTcp(transport, sourceAddress, destinationAddress);
        }
    }

    private void ParseUdp(ReadOnlySpan<byte> udp, IPAddress sourceAddress, IPAddress destinationAddress)
    {
        if (udp.Length < 8)
        {
            return;
        }

        ushort sourcePort = ReadUInt16(udp, 0);
        ushort destinationPort = ReadUInt16(udp, 2);
        if (sourcePort != 53 && destinationPort != 53)
        {
            return;
        }

        if (!DnsPacketParser.TryParse(udp[8..], out DnsPacket dns))
        {
            return;
        }

        ushort localPort = destinationPort == 53 ? sourcePort : destinationPort;
        IPAddress localAddress = destinationPort == 53 ? sourceAddress : destinationAddress;
        ProcessInfo process = ProcessResolver.ResolveUdp(localAddress, localPort);
        MessageCaptured?.Invoke(new CapturedDnsMessage(dns, sourceAddress, sourcePort, destinationAddress, destinationPort, ProtocolType.Udp, process));
    }

    private void ParseTcp(ReadOnlySpan<byte> tcp, IPAddress sourceAddress, IPAddress destinationAddress)
    {
        if (tcp.Length < 20)
        {
            return;
        }

        ushort sourcePort = ReadUInt16(tcp, 0);
        ushort destinationPort = ReadUInt16(tcp, 2);
        if (sourcePort != 53 && destinationPort != 53)
        {
            return;
        }

        int dataOffset = (tcp[12] >> 4) * 4;
        if (tcp.Length < dataOffset + 2)
        {
            return;
        }

        int dnsLength = ReadUInt16(tcp, dataOffset);
        if (dnsLength <= 0 || tcp.Length < dataOffset + 2 + dnsLength)
        {
            return;
        }

        if (!DnsPacketParser.TryParse(tcp.Slice(dataOffset + 2, dnsLength), out DnsPacket dns))
        {
            return;
        }

        ushort localPort = destinationPort == 53 ? sourcePort : destinationPort;
        IPAddress localAddress = destinationPort == 53 ? sourceAddress : destinationAddress;
        IPAddress remoteAddress = destinationPort == 53 ? destinationAddress : sourceAddress;
        ushort remotePort = destinationPort == 53 ? destinationPort : sourcePort;
        ProcessInfo process = ProcessResolver.ResolveTcp(localAddress, localPort, remoteAddress, remotePort);
        MessageCaptured?.Invoke(new CapturedDnsMessage(dns, sourceAddress, sourcePort, destinationAddress, destinationPort, ProtocolType.Tcp, process));
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> buffer, int offset) =>
        (ushort)((buffer[offset] << 8) | buffer[offset + 1]);

    public void Dispose() => Stop();
}
