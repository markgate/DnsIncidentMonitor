using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace DnsIncidentMonitor;

public sealed record ProcessInfo(int ProcessId, string ProcessName);

public static class ProcessResolver
{
    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;

    public static ProcessInfo ResolveUdp(IPAddress localAddress, ushort localPort)
    {
        int pid = FindUdpPid(localAddress, localPort);
        return ToProcessInfo(pid);
    }

    public static ProcessInfo ResolveTcp(IPAddress localAddress, ushort localPort, IPAddress remoteAddress, ushort remotePort)
    {
        int pid = FindTcpPid(localAddress, localPort, remoteAddress, remotePort);
        return ToProcessInfo(pid);
    }

    public static ProcessInfo ResolvePid(int pid) => ToProcessInfo(pid);

    private static ProcessInfo ToProcessInfo(int pid)
    {
        if (pid <= 0)
        {
            return new ProcessInfo(0, "Unknown");
        }

        try
        {
            using Process process = Process.GetProcessById(pid);
            return new ProcessInfo(pid, process.ProcessName + ".exe");
        }
        catch
        {
            return new ProcessInfo(pid, "PID " + pid);
        }
    }

    private static int FindUdpPid(IPAddress address, ushort port)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, AfInet, UdpTableOwnerPid, 0);
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buffer, ref size, true, AfInet, UdpTableOwnerPid, 0) != 0)
            {
                return 0;
            }

            int count = Marshal.ReadInt32(buffer);
            IntPtr row = IntPtr.Add(buffer, 4);
            uint local = ToLittleEndianUInt(address);
            int rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                MibUdpRowOwnerPid entry = Marshal.PtrToStructure<MibUdpRowOwnerPid>(row);
                ushort entryPort = NetworkToHostPort(entry.LocalPort);
                if (entryPort == port && (entry.LocalAddr == local || entry.LocalAddr == 0))
                {
                    return (int)entry.OwningPid;
                }
                row = IntPtr.Add(row, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return 0;
    }

    private static int FindTcpPid(IPAddress localAddress, ushort localPort, IPAddress remoteAddress, ushort remotePort)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableOwnerPidAll, 0) != 0)
            {
                return 0;
            }

            int count = Marshal.ReadInt32(buffer);
            IntPtr row = IntPtr.Add(buffer, 4);
            uint local = ToLittleEndianUInt(localAddress);
            uint remote = ToLittleEndianUInt(remoteAddress);
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                MibTcpRowOwnerPid entry = Marshal.PtrToStructure<MibTcpRowOwnerPid>(row);
                if (entry.LocalAddr == local &&
                    entry.RemoteAddr == remote &&
                    NetworkToHostPort(entry.LocalPort) == localPort &&
                    NetworkToHostPort(entry.RemotePort) == remotePort)
                {
                    return (int)entry.OwningPid;
                }
                row = IntPtr.Add(row, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return 0;
    }

    private static uint ToLittleEndianUInt(IPAddress address) =>
        BitConverter.ToUInt32(address.GetAddressBytes(), 0);

    private static ushort NetworkToHostPort(uint value) =>
        (ushort)IPAddress.NetworkToHostOrder((short)(value & 0xFFFF));

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }
}
