# DNS Incident Monitor

DNS Incident Monitor is a Windows DNS monitoring tool for emergency response.
DNS事件监控器是一款适用于应急响应场景的Windows域名系统监控工具。用于解决应急响应中，通过持续监控恶意域名请求，定位恶意进程。

## Features

- ETW DNS Client mode for Windows DNS Client events.
- 支持通过ETW DNS Client mode抓取windows DNS 客户端事件中的域名解析记录。
- Raw Sockets capture mode, no packet driver required.
- 支持通过Raw Sockets capture模式，直接选择网卡抓包
- Capture selector for choosing Wi-Fi or Ethernet IPv4 adapter in Raw Sockets mode.
- DNS table with process name, PID, hostname, query type, response IP, source IP, source port, destination IP, destination port, and DNS response code.
- Process attribution through Windows TCP/UDP owner PID tables.
- Quick filters:
  - `contains:malicious.com`
  - `process:chrome.exe`
  - `response:NXDOMAIN`
- CSV/XML evidence export for selected records.

## Run

Build or publish the app, then right-click `DnsIncidentMonitor.exe` and choose **Run as administrator**.

Administrator privileges are required for Raw Sockets capture and for enabling the DNS Client operational event channel.

## Build

```powershell
dotnet build .\DnsIncidentMonitor.csproj -c Release
```

Output:

```text
bin\Release\net10.0-windows\DnsIncidentMonitor.exe
```

## Publish Portable Folder

```powershell
dotnet publish .\DnsIncidentMonitor.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
```

The published executable is framework-dependent and requires .NET Desktop Runtime 10 on the target host.

## Capture Notes

ETW DNS Client mode is recommended for normal Windows application monitoring because it records DNS Client events and often sees queries that Raw Sockets cannot attribute cleanly.

Raw Sockets mode focuses on local IPv4 DNS traffic on UDP/TCP port 53. It is intended as a no-driver emergency mode. It does not capture DoH/DoT traffic or IPv6 DNS traffic; Npcap support can be added later if driver-level capture is required.
