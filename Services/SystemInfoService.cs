using Microsoft.Win32;
using SecurityShield.Models;
using SecurityShield.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Windows;

namespace SecurityShield.Services
{
    public class SystemInfoService : ISystemInfoService
    {
        private PerformanceCounter? _cpuCounter;
        private readonly Dictionary<int, (TimeSpan TotalProcessorTime, DateTime Time)> _prevProcessTimes = new();

        public SystemInfoService()
        {
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _cpuCounter.NextValue();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"PerformanceCounter: {ex.Message}");
            }
        }

        public SystemInfo GetDetailedSystemInfo()
        {
            var info = new SystemInfo();
            try
            {
                info.OSVersion = Environment.OSVersion.VersionString;
                info.Build = Environment.OSVersion.Version.Build.ToString();
                info.ComputerName = Environment.MachineName;
                info.UserName = Environment.UserName;
                info.Domain = Environment.UserDomainName;

                using (var s = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                    foreach (ManagementObject o in s.Get())
                    { info.Processor = $"{o["Name"]} ({o["NumberOfCores"]} ядер)"; break; }

                using (var s = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                    foreach (ManagementObject o in s.Get())
                    { info.TotalRAM = $"{Convert.ToUInt64(o["TotalPhysicalMemory"]) / 1024.0 / 1024.0 / 1024.0:F1} GB"; break; }

                using (var s = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard"))
                    foreach (ManagementObject o in s.Get())
                    { info.Motherboard = $"{o["Manufacturer"]} {o["Product"]}"; break; }

                using (var s = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                    foreach (ManagementObject o in s.Get())
                    { info.BIOS = $"{o["Manufacturer"]} {o["SMBIOSBIOSVersion"]}"; break; }

                foreach (var a in NetworkInterface.GetAllNetworkInterfaces().Where(a => a.OperationalStatus == OperationalStatus.Up))
                    info.NetworkAdapters.Add($"{a.Name} ({a.NetworkInterfaceType})");

                info.UpdateStatus = GetVersionStatus();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SystemInfo: {ex.Message}");
            }
            return info;
        }

        private string GetVersionStatus()
        {
            try
            {
                int build = Environment.OSVersion.Version.Build;
                using var s = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem");
                foreach (ManagementObject o in s.Get())
                {
                    string caption = o["Caption"]?.ToString() ?? "";
                    bool isWin11 = caption.Contains("Windows 11") || build >= 22000;
                    if (isWin11)
                    {
                        if (build >= 22631) return "Последняя версия (Win 11 23H2)";
                        if (build >= 22621) return "Актуальная (Win 11 22H2)";
                        return "Требуется обновление (Win 11)";
                    }
                    if (build >= 19045) return "Последняя версия (Win 10 22H2)";
                    if (build >= 19044) return "Устарела (Win 10 21H2)";
                    return "Критически устарела";
                }
            }
            catch { }
            return "Не определено";
        }

        public List<DriveInfoModel> GetDriveInfo()
        {
            var drives = new List<DriveInfoModel>();
            try
            {
                foreach (var d in DriveInfo.GetDrives().Where(d => d.IsReady))
                {
                    drives.Add(new DriveInfoModel
                    {
                        Name = d.Name,
                        TotalSpace = d.TotalSize,
                        FreeSpace = d.TotalFreeSpace,
                        DriveType = d.DriveType.ToString(),
                        DriveFormat = d.DriveFormat
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"DriveInfo: {ex.Message}");
            }
            return drives;
        }

        public List<ProcessInfo> GetRunningProcesses()
        {
            var processes = new List<ProcessInfo>();
            var current = Process.GetProcesses();
            var now = DateTime.Now;

            foreach (var proc in current)
            {
                try
                {
                    double cpuUsage = 0;
                    try
                    {
                        if (_prevProcessTimes.TryGetValue(proc.Id, out var prev))
                        {
                            var curTime = proc.TotalProcessorTime;
                            var elapsed = (now - prev.Time).TotalMilliseconds;
                            if (elapsed > 0)
                                cpuUsage = (curTime - prev.TotalProcessorTime).TotalMilliseconds / (elapsed * Environment.ProcessorCount) * 100;
                            _prevProcessTimes[proc.Id] = (curTime, now);
                        }
                        else
                        {
                            _prevProcessTimes[proc.Id] = (proc.TotalProcessorTime, now);
                        }
                    }
                    catch { }

                    var p = new ProcessInfo
                    {
                        Name = proc.ProcessName,
                        Id = proc.Id,
                        Cpu = Math.Round(cpuUsage, 1),
                        ProcessPath = GetProcessPath(proc)
                    };

                    try { p.MemoryMB = proc.WorkingSet64 / 1024.0 / 1024.0; } catch { }
                    p.IsUserProcess = p.CheckIsUserProcess();
                    processes.Add(p);
                }
                catch
                {
                    continue;
                }
            }

            var currentIds = new HashSet<int>(current.Select(p => p.Id));
            foreach (var key in _prevProcessTimes.Keys.Where(k => !currentIds.Contains(k)).ToList())
                _prevProcessTimes.Remove(key);

            return processes.OrderByDescending(p => p.MemoryMB).ToList();
        }

        private string GetProcessPath(Process proc)
        {
            try { return proc.MainModule?.FileName ?? "Системный"; }
            catch { return "Нет доступа"; }
        }

        public double GetCurrentCpuUsage()
        {
            try
            {
                if (_cpuCounter != null)
                    return Math.Round(_cpuCounter.NextValue(), 1);
            }
            catch { }
            return 0;
        }

        public bool KillProcess(int processId)
        {
            if (processId == Environment.ProcessId)
            {
                var answer = MessageBox.Show(
                    "Вы пытаетесь завершить процесс этой программы.\nЗакрыть приложение?",
                    "Закрытие программы",
                    MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (answer == MessageBoxResult.Yes)
                {
                    Application.Current.Dispatcher.Invoke(() => Application.Current.Shutdown());
                    return true;
                }
                return false;
            }

            try
            {
                using var proc = Process.GetProcessById(processId);
                var name = proc.ProcessName.ToLower();

                var critical = new[]
                {
            "csrss", "winlogon", "services", "lsass", "smss",
            "system", "wininit", "fontdrvhost", "audiodg", "dwm",
            "svchost", "registry", "memory compression"
        };
                if (critical.Any(c => name.Equals(c)))
                {
                    MessageBox.Show(
                        $"'{proc.ProcessName}' — критический системный процесс.\nЗавершение запрещено.",
                        "Запрещено", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                proc.Kill();
                return proc.WaitForExit(3000);
            }
            catch (ArgumentException) { return false; }
            catch (InvalidOperationException) { return true; }
            catch (System.ComponentModel.Win32Exception ex)
            {
                MessageBox.Show($"Недостаточно прав: {ex.Message}",
                    "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }
        public List<SoftwareInfo> GetInstalledSoftware()
        {
            var list = new List<SoftwareInfo>();
            var paths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            foreach (var path in paths)
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key == null) continue;
                foreach (var sub in key.GetSubKeyNames())
                {
                    using var sk = key.OpenSubKey(sub);
                    var name = sk?.GetValue("DisplayName")?.ToString();
                    if (string.IsNullOrEmpty(name)) continue;
                    list.Add(new SoftwareInfo
                    {
                        DisplayName = name,
                        DisplayVersion = sk?.GetValue("DisplayVersion")?.ToString() ?? "N/A",
                        Publisher = sk?.GetValue("Publisher")?.ToString() ?? "N/A",
                        InstallDate = sk?.GetValue("InstallDate")?.ToString() ?? "N/A"
                    });
                }
            }
            return list.OrderBy(s => s.DisplayName).ToList();
        }

        public List<StartupProgram> GetStartupPrograms()
        {
            var list = new List<StartupProgram>();
            void ReadKey(RegistryKey? key, string loc, string user)
            {
                if (key == null) return;
                foreach (var name in key.GetValueNames())
                    list.Add(new StartupProgram { Name = name, Command = key.GetValue(name)?.ToString() ?? "", Location = loc, User = user });
            }

            ReadKey(Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"), "HKCU\\Run", "Текущий");
            ReadKey(Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"), "HKLM\\Run", "Все");
            ReadKey(Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"), "HKCU\\RunOnce", "Текущий");
            ReadKey(Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"), "HKLM\\RunOnce", "Все");

            var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (Directory.Exists(startupFolder))
                foreach (var file in Directory.GetFiles(startupFolder, "*.*"))
                    list.Add(new StartupProgram { Name = Path.GetFileName(file), Command = file, Location = "Папка автозагрузки", User = "Текущий" });

            return list.OrderBy(s => s.Name).ToList();
        }

        public List<NetworkConnectionInfo> GetActiveNetworkConnections()
        {
            var connections = new List<NetworkConnectionInfo>();
            try
            {
                foreach (var tcp in GetAllTcpConnections())
                {
                    if (IPAddress.IsLoopback(tcp.LocalAddress) && IPAddress.IsLoopback(tcp.RemoteAddress))
                        continue;

                    string processName = "N/A";
                    try { if (tcp.OwningPid > 0) processName = Process.GetProcessById((int)tcp.OwningPid).ProcessName; } catch { }

                    var (portName, portPurpose) = PortDescriptionService.GetPortDescription(tcp.RemotePort);

                    connections.Add(new NetworkConnectionInfo
                    {
                        LocalAddress = tcp.LocalAddress.ToString(),
                        LocalPort = tcp.LocalPort,
                        RemoteAddress = tcp.RemoteAddress.ToString(),
                        RemotePort = tcp.RemotePort,
                        State = tcp.State.ToString(),
                        ProcessId = (int)tcp.OwningPid,
                        ProcessName = processName,
                        RemotePortDescription = $"{tcp.RemotePort} ({portName})",
                        ConnectionPurpose = portPurpose
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Network: {ex.Message}");
            }
            return connections;
        }

        private List<TcpConnectionInfo> GetAllTcpConnections()
        {
            var table = new List<TcpConnectionInfo>();
            int afInet = 2;
            int buffSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, afInet, (int)TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr buff = Marshal.AllocHGlobal(buffSize);
            try
            {
                uint ret = GetExtendedTcpTable(buff, ref buffSize, true, afInet, (int)TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return table;

                int count = Marshal.ReadInt32(buff);
                IntPtr rowPtr = buff + 4;

                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    table.Add(new TcpConnectionInfo
                    {
                        LocalAddress = new IPAddress(BitConverter.GetBytes(row.dwLocalAddr)),
                        LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort),
                        RemoteAddress = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)),
                        RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwRemotePort),
                        State = (TcpState)row.dwState,
                        OwningPid = row.dwOwningPid
                    });
                    rowPtr += Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buff);
            }
            return table;
        }

        private class TcpConnectionInfo
        {
            public IPAddress LocalAddress { get; set; } = IPAddress.None;
            public ushort LocalPort { get; set; }
            public IPAddress RemoteAddress { get; set; } = IPAddress.None;
            public ushort RemotePort { get; set; }
            public TcpState State { get; set; }
            public uint OwningPid { get; set; }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int TableClass, uint Reserved);

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL
        }
    }
}