using Microsoft.Win32;
using SecurityShield.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Threading.Tasks;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Windows;

namespace SecurityShield.Services
{
    public class SystemInfoService : ISystemInfoService
    {
        private PerformanceCounter? _cpuCounter;
        private List<string> _systemProcesses;
        private List<string> _allowedUserProcesses;

       
        private readonly Dictionary<int, (TimeSpan TotalProcessorTime, DateTime Time)> _prevProcessTimes
            = new Dictionary<int, (TimeSpan, DateTime)>();

        public SystemInfoService()
        {
            InitializeCpuCounter();
            InitializeProcessLists();
        }


        private void InitializeCpuCounter()
        {
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _cpuCounter.NextValue(); 
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка PerformanceCounter: {ex.Message}");
            }
        }

        public SystemInfo GetDetailedSystemInfo()
        {
            var info = new SystemInfo
            {
                OSVersion = Environment.OSVersion.VersionString,
                ComputerName = Environment.MachineName,
                UserName = Environment.UserName,
                Domain = Environment.UserDomainName
            };

            try
            {
                // Используем быстрые запросы WMI
                using var searcherProc = new ManagementObjectSearcher("SELECT Name, NumberOfCores FROM Win32_Processor");
                foreach (ManagementObject obj in searcherProc.Get())
                {
                    info.Processor = $"{obj["Name"]} ({obj["NumberOfCores"]} ядер)";
                    break;
                }

                using var searcherMem = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcherMem.Get())
                {
                    if (ulong.TryParse(obj["TotalPhysicalMemory"]?.ToString(), out ulong totalBytes))
                        info.TotalRAM = $"{(totalBytes / 1024.0 / 1024.0 / 1024.0):F1} GB";
                    break;
                }

                // Инфо о версии
                info.Build = Environment.OSVersion.Version.Build.ToString();
                info.UpdateStatus = CheckWindowsVersionStatus();

                // Сетевые адаптеры
                foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces().Where(a => a.OperationalStatus == OperationalStatus.Up))
                {
                    info.NetworkAdapters.Add($"{adapter.Name} ({adapter.NetworkInterfaceType})");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка SystemInfo: {ex.Message}");
            }
            return info;
        }
        private string CheckWindowsVersionStatus()
        {
            try
            {
                var osVersion = Environment.OSVersion;
                var currentBuild = osVersion.Version.Build;

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string version = obj["Version"]?.ToString() ?? "";
                        string caption = obj["Caption"]?.ToString() ?? "";

                        // Анализируем версию системы
                        return AnalyzeWindowsVersion(version, caption, currentBuild);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки версии Windows: {ex.Message}");
            }

            return "Не удалось определить статус версии";
        }
        
        private string AnalyzeWindowsVersion(string version, string caption, int currentBuild)
        {
            // Определяем базовую версию Windows
            if (version.StartsWith("10.0"))
            {
                return AnalyzeWindows10And11(currentBuild, caption);
            }
            else if (version.StartsWith("6.3"))
            {
                return "Обновите версию, она устарела (Windows 8.1)";
            }
            else if (version.StartsWith("6.2"))
            {
                return "Обновите версию, она устарела (Windows 8)";
            }
            else if (version.StartsWith("6.1"))
            {
                return "Обновите версию, она устарела (Windows 7)";
            }
            else if (version.StartsWith("6.0"))
            {
                return "Обновите версию, она устарела (Windows Vista)";
            }
            else if (version.StartsWith("5."))
            {
                return "Обновите версию, она устарела (Windows XP или старше)";
            }

            return "Можете обновить вашу версию системы";
        }

        private string AnalyzeWindows10And11(int currentBuild, string caption)
        {
            bool isWindows11 = caption.Contains("Windows 11") || currentBuild >= 22000;

            if (isWindows11)
            {
                // Анализ Windows 11
                if (currentBuild >= 22631) return "Последняя версия (Windows 11 23H2)";
                if (currentBuild >= 22621) return "Актуальная версия (Windows 11 22H2)";
                if (currentBuild >= 22000) return "Требуется обновление (Windows 11 21H2)";

                // Если сборка ниже 22000, но определилась как Win11 (например, Insider)
                return "Актуальная версия (Windows 11)";
            }
            else
            {
                // Анализ Windows 10
                if (currentBuild >= 19045) return "Последняя версия (Windows 10 22H2)";
                if (currentBuild >= 19044) return "Версия устарела (Windows 10 21H2). Поддержка прекращена.";
                if (currentBuild >= 19043) return "Версия устарела (Windows 10 21H1). Поддержка прекращена.";
                if (currentBuild > 0) return "Версия критически устарела. Поддержка прекращена.";
            }

            return "Не удалось определить статус версии";
        }
        public List<DriveInfoModel> GetDriveInfo()
        {
            var drives = new List<DriveInfoModel>();
            try
            {
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady))
                {
                    var driveModel = new DriveInfoModel
                    {
                        Name = drive.Name,
                        TotalSpace = drive.TotalSize,
                        FreeSpace = drive.TotalFreeSpace,
                        DriveType = drive.DriveType.ToString(),
                        DriveFormat = drive.DriveFormat
                    };
                    driveModel.UpdateDriveSeries();
                    drives.Add(driveModel);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения информации о дисках: {ex.Message}");
            }
            return drives;
        }

        public List<ProcessInfo> GetRunningProcesses()
        {
            var processes = new List<ProcessInfo>();
            var currentProcesses = Process.GetProcesses();
            var now = DateTime.Now;

            foreach (var process in currentProcesses)
            {
                try
                {
                    double cpuUsage = 0;

                  
                    if (_prevProcessTimes.TryGetValue(process.Id, out var prevData))
                    {
                        var curTotalProcTime = process.TotalProcessorTime;
                        var timeDiff = (now - prevData.Time).TotalMilliseconds;

                        if (timeDiff > 0)
                        {
                            var cpuTimeDiff = (curTotalProcTime - prevData.TotalProcessorTime).TotalMilliseconds;
                          
                            cpuUsage = (cpuTimeDiff / (timeDiff * Environment.ProcessorCount)) * 100;
                        }

                        _prevProcessTimes[process.Id] = (curTotalProcTime, now);
                    }
                    else
                    {
                       
                        _prevProcessTimes[process.Id] = (process.TotalProcessorTime, now);
                    }

               
                    var pInfo = new ProcessInfo
                    {
                        Name = process.ProcessName,
                        Id = process.Id,
                      
                        MemoryMB = 0,
                        Cpu = Math.Round(cpuUsage, 1),
                        ProcessPath = GetProcessPathSafe(process),
                        WindowTitle = process.MainWindowTitle
                    };

                    try { pInfo.MemoryMB = process.WorkingSet64 / 1024.0 / 1024.0; } catch { }

                    pInfo.IsUserProcess = pInfo.CheckIsUserProcess();
                    processes.Add(pInfo);
                }
                catch (Exception)
                {
                    continue;
                }
            }

      
            var currentIds = new HashSet<int>(currentProcesses.Select(p => p.Id));
            var keysToRemove = _prevProcessTimes.Keys.Where(k => !currentIds.Contains(k)).ToList();
            foreach (var key in keysToRemove) _prevProcessTimes.Remove(key);

            return processes.OrderByDescending(p => p.MemoryMB).ToList();
        }

        private string GetProcessPathSafe(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "Системный/Защищенный";
            }
            catch
            {
                return "Нет доступа";
            }
        }

        public List<ProcessInfo> GetUserProcesses()
        {
            var allProcesses = GetRunningProcesses();
            return allProcesses.Where(p => p.IsUserProcess).ToList();
        }

        public bool KillProcess(int processId)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                if (!CanKillProcess(process.ProcessName))
                {
                    Debug.WriteLine($"Попытка завершить системный процесс: {process.ProcessName}");
                    MessageBox.Show($"Процесс '{process.ProcessName}' является системным и не может быть завершен.",
                        "Ошибка безопасности", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                var warningProcesses = new[] { "explorer", "winlogon" };
                if (warningProcesses.Any(p => process.ProcessName.ToLower().Contains(p)))
                {
                    var result = MessageBox.Show(
                        $"Завершение процесса '{process.ProcessName}' может привести к нестабильной работе системы. Продолжить?",
                        "Предупреждение безопасности",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);
                    if (result != MessageBoxResult.Yes)
                        return false;
                }

                process.Kill();
                if (!process.WaitForExit(3000))
                {
                    Debug.WriteLine($"Процесс {process.ProcessName} не завершился в течение 3 секунд");
                    return false;
                }
                return true;
            }
            catch (ArgumentException ex)
            {
                Debug.WriteLine($"Процесс с ID {processId} не найден: {ex.Message}");
                return false;
            }
            catch (InvalidOperationException ex)
            {
                Debug.WriteLine($"Процесс уже завершен: {ex.Message}");
                return true;
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                Debug.WriteLine($"Ошибка доступа при завершении процесса {processId}: {ex.Message}");
                MessageBox.Show($"Недостаточно прав для завершения процесса. Запустите программу от имени администратора.",
                    "Ошибка доступа", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка завершения процесса {processId}: {ex.Message}");
                MessageBox.Show($"Ошибка при завершении процесса: {ex.Message}",
                    "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private bool CanKillProcess(string processName)
        {
            if (string.IsNullOrEmpty(processName))
                return false;

            var lowerName = processName.ToLower();
            var criticalSystemProcesses = new[]
            {
                "csrss", "winlogon", "services", "lsass", "smss",
                "system", "wininit", "fontdrvhost", "audiodg"
            };

            if (criticalSystemProcesses.Any(critical => lowerName.Contains(critical)))
                return false;

            return true;
        }

        private void InitializeProcessLists()
        {
            _systemProcesses = new List<string>
            {
                "csrss", "winlogon", "services", "lsass", "svchost",
                "system", "smss", "taskhost", "dwm", "explorer",
                "wininit", "spoolsv", "taskeng", "conhost", "runtimebroker",
                "ctfmon", "searchindexer", "searchui", "sihost", "fontdrvhost"
            };

            _allowedUserProcesses = new List<string>
            {
                "chrome", "firefox", "msedge", "opera", "vivaldi",
                "notepad", "calc", "winword", "excel", "powerpnt",
                "SecurityShield", "devenv", "code", "steam", "epicgameslauncher",
                "spotify", "discord", "telegram", "whatsapp", "skype",
                "vlc", "winamp", "audacity", "photoshop", "paint.net",
                "acrobat", "foxitreader", "teamviewer", "anydesk"
            };
        }

      
        public double GetCurrentCpuUsage()
        {
            try
            {
                if (_cpuCounter != null)
                {
                    return Math.Round(_cpuCounter.NextValue(), 1);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения загрузки ЦП: {ex.Message}");
            }
            return 0;
        }


        public List<string> GetRunningUserProcessNames()
        {
            var userProcesses = GetUserProcesses();
            return userProcesses.Select(p => p.Name).Distinct().ToList();
        }



     
    
        public List<SoftwareInfo> GetInstalledSoftware()
        {
            var softwareList = new List<SoftwareInfo>();
            // Проверяем 64-bit и 32-bit ветки реестра
            var registryKeys = new[]
            {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    };

            foreach (var keyPath in registryKeys)
            {
                using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key == null) continue;
                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        using (var subKey = key.OpenSubKey(subKeyName))
                        {
                            var displayName = subKey?.GetValue("DisplayName")?.ToString();
                            if (string.IsNullOrEmpty(displayName)) continue;

                            softwareList.Add(new SoftwareInfo
                            {
                                DisplayName = displayName,
                                DisplayVersion = subKey?.GetValue("DisplayVersion")?.ToString() ?? "N/A",
                                Publisher = subKey?.GetValue("Publisher")?.ToString() ?? "N/A",
                                InstallDate = subKey?.GetValue("InstallDate")?.ToString() ?? "N/A",
                                InstallLocation = subKey?.GetValue("InstallLocation")?.ToString() ?? "N/A"
                            });
                        }
                    }
                }
            }
            return softwareList.OrderBy(s => s.DisplayName).ToList();
        }

        public List<StartupProgram> GetStartupPrograms()
        {
            var startupList = new List<StartupProgram>();

           
            using (var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
            {
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        startupList.Add(new StartupProgram
                        {
                            Name = valueName,
                            Command = key.GetValue(valueName)?.ToString() ?? "",
                            Location = "HKCU\\...\\Run",
                            User = "Current User"
                        });
                    }
                }
            }

      
            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
            {
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        startupList.Add(new StartupProgram
                        {
                            Name = valueName,
                            Command = key.GetValue(valueName)?.ToString() ?? "",
                            Location = "HKLM\\...\\Run",
                            User = "All Users"
                        });
                    }
                }
            }

            using (var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"))
            {
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        startupList.Add(new StartupProgram
                        {
                            Name = valueName,
                            Command = key.GetValue(valueName)?.ToString() ?? "",
                            Location = "HKCU\\...\\RunOnce",
                            User = "Current User (Once)"
                        });
                    }
                }
            }

            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"))
            {
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        startupList.Add(new StartupProgram
                        {
                            Name = valueName,
                            Command = key.GetValue(valueName)?.ToString() ?? "",
                            Location = "HKLM\\...\\RunOnce",
                            User = "All Users (Once)"
                        });
                    }
                }
            }

            
            var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (Directory.Exists(startupFolder))
            {
                foreach (var file in Directory.GetFiles(startupFolder, "*.*")) 
                {
                    startupList.Add(new StartupProgram
                    {
                        Name = Path.GetFileName(file),
                        Command = file,
                        Location = "Startup Folder",
                        User = "Current User"
                    });
                }
            }
            return startupList.OrderBy(s => s.Name).ToList();
        }

        public List<NetworkConnectionInfo> GetActiveNetworkConnections()
        {
            var connections = new List<NetworkConnectionInfo>();
            try
            {
                // Получаем список соединений через WinAPI (функция ниже)
                var tcpConnections = GetAllTcpConnections();

                foreach (var tcp in tcpConnections)
                {
               
                    if (IPAddress.IsLoopback(tcp.LocalAddress) && IPAddress.IsLoopback(tcp.RemoteAddress))
                        continue;

                    string processName = "N/A";
                    try
                    {
                        if (tcp.OwningPid > 0)
                        {
                            processName = Process.GetProcessById((int)tcp.OwningPid).ProcessName;
                        }
                    }
                    catch { }

                    var (portName, portPurpose) = PortDescriptionService.GetPortDescription(tcp.RemotePort);

                    connections.Add(new NetworkConnectionInfo
                    {
                        _localAddress = tcp.LocalAddress.ToString(),
                        _localPort = tcp.LocalPort,
                        _remoteAddress = tcp.RemoteAddress.ToString(),
                        _remotePort = tcp.RemotePort,
                        _state = tcp.State.ToString(),
                        _processId = (int)tcp.OwningPid,
                        _processName = processName,
                        _remotePortDescription = $"{tcp.RemotePort} ({portName})",
                        _connectionPurpose = portPurpose,
                        _localPortDescription = PortDescriptionService.GetLocalPortDescription(tcp.LocalPort)
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения сетевых подключений: {ex.Message}");
            }
            return connections;
        }

        private List<TcpConnectionInfo> GetAllTcpConnections()
        {
            var table = new List<TcpConnectionInfo>();
            int afInet = 2; // IPv4
            int buffSize = 0;

            // 1. Узнаем необходимый размер буфера
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, afInet, (int)TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);
            try
            {
                // 2. Получаем данные
                ret = GetExtendedTcpTable(buffTable, ref buffSize, true, afInet, (int)TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return table;

                // 3. Читаем количество записей (первые 4 байта)
                int tabNumEntries = Marshal.ReadInt32(buffTable);
                IntPtr rowPtr = (IntPtr)((long)buffTable + 4);

                for (int i = 0; i < tabNumEntries; i++)
                {
                    // Маршалинг структуры
                    MIB_TCPROW_OWNER_PID tcpRow = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                    table.Add(new TcpConnectionInfo
                    {
                        LocalAddress = new IPAddress(BitConverter.GetBytes(tcpRow.dwLocalAddr)),
                        LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.dwLocalPort),
                        RemoteAddress = new IPAddress(BitConverter.GetBytes(tcpRow.dwRemoteAddr)),
                        RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.dwRemotePort),
                        State = (TcpState)tcpRow.dwState,
                        OwningPid = tcpRow.dwOwningPid
                    });

                    // Сдвигаем указатель на размер структуры
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffTable);
            }
            return table;
        }
        private class TcpConnectionInfo
        {
            public IPAddress LocalAddress { get; set; }
            public ushort LocalPort { get; set; }
            public IPAddress RemoteAddress { get; set; }
            public ushort RemotePort { get; set; }
            public TcpState State { get; set; }
            public uint OwningPid { get; set; }
        }
        #region Network P/Invoke Structs


        private const int AF_INET = 2; // IPv4

  

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
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
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }
        #endregion

    }
}