using System.Net;
using System.Text;

namespace DnsIncidentMonitor;

public sealed record DnsPacket(
    ushort TransactionId,
    bool IsResponse,
    string HostName,
    string QueryType,
    string ResponseText,
    string Status);

public static class DnsPacketParser
{
    private static readonly Dictionary<ushort, string> Types = new()
    {
        [1] = "A",
        [2] = "NS",
        [5] = "CNAME",
        [12] = "PTR",
        [15] = "MX",
        [16] = "TXT",
        [28] = "AAAA",
        [33] = "SRV",
        [65] = "HTTPS"
    };

    public static bool TryParse(ReadOnlySpan<byte> dns, out DnsPacket packet)
    {
        packet = new DnsPacket(0, false, "", "", "", "Invalid");
        if (dns.Length < 12)
        {
            return false;
        }

        ushort id = ReadUInt16(dns, 0);
        ushort flags = ReadUInt16(dns, 2);
        bool isResponse = (flags & 0x8000) != 0;
        ushort qdCount = ReadUInt16(dns, 4);
        ushort anCount = ReadUInt16(dns, 6);
        int rcode = flags & 0x000F;
        string status = rcode switch
        {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => $"RCODE {rcode}"
        };

        int offset = 12;
        string host = "";
        string queryType = "";

        if (qdCount > 0)
        {
            if (!ReadName(dns, ref offset, out host) || offset + 4 > dns.Length)
            {
                return false;
            }

            ushort type = ReadUInt16(dns, offset);
            queryType = Types.GetValueOrDefault(type, type.ToString());
            offset += 4;
        }

        List<string> answers = new();
        if (isResponse)
        {
            for (int i = 0; i < anCount && offset + 12 <= dns.Length; i++)
            {
                if (!ReadName(dns, ref offset, out _))
                {
                    break;
                }

                if (offset + 10 > dns.Length)
                {
                    break;
                }

                ushort type = ReadUInt16(dns, offset);
                offset += 2;
                offset += 2;
                offset += 4;
                ushort rdLength = ReadUInt16(dns, offset);
                offset += 2;

                if (offset + rdLength > dns.Length)
                {
                    break;
                }

                if (type == 1 && rdLength == 4)
                {
                    answers.Add(new IPAddress(dns.Slice(offset, 4).ToArray()).ToString());
                }
                else if (type == 28 && rdLength == 16)
                {
                    answers.Add(new IPAddress(dns.Slice(offset, 16).ToArray()).ToString());
                }
                else if (type == 5)
                {
                    int nameOffset = offset;
                    if (ReadName(dns, ref nameOffset, out string cname))
                    {
                        answers.Add("CNAME " + cname);
                    }
                }

                offset += rdLength;
            }
        }

        packet = new DnsPacket(id, isResponse, host, queryType, string.Join("; ", answers), status);
        return !string.IsNullOrWhiteSpace(host);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> buffer, int offset) =>
        (ushort)((buffer[offset] << 8) | buffer[offset + 1]);

    private static bool ReadName(ReadOnlySpan<byte> buffer, ref int offset, out string name)
    {
        name = "";
        StringBuilder builder = new();
        int cursor = offset;
        int jumps = 0;
        bool jumped = false;

        while (cursor < buffer.Length)
        {
            byte length = buffer[cursor++];
            if (length == 0)
            {
                if (!jumped)
                {
                    offset = cursor;
                }
                name = builder.ToString().TrimEnd('.');
                return true;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (cursor >= buffer.Length || ++jumps > 16)
                {
                    return false;
                }

                int pointer = ((length & 0x3F) << 8) | buffer[cursor++];
                if (!jumped)
                {
                    offset = cursor;
                }
                cursor = pointer;
                jumped = true;
                continue;
            }

            if ((length & 0xC0) != 0 || cursor + length > buffer.Length)
            {
                return false;
            }

            builder.Append(Encoding.ASCII.GetString(buffer.Slice(cursor, length))).Append('.');
            cursor += length;
        }

        return false;
    }
}
