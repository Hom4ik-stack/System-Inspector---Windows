using Microsoft.Win32;
using SecurityShield.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
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

        public SystemInfoService()
        {
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _cpuCounter.NextValue();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка инициализации PerformanceCounter: {ex.Message}");
            }
            InitializeProcessLists();
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

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.Processor = $"{obj["Name"]} ({obj["NumberOfCores"]} ядер)";
                        break;
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var totalBytes = Convert.ToUInt64(obj["TotalPhysicalMemory"]);
                        info.TotalRAM = $"{(totalBytes / 1024.0 / 1024.0 / 1024.0):F1} GB";
                        break;
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.Motherboard = $"{obj["Manufacturer"]} {obj["Product"]}";
                        break;
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.BIOS = $"{obj["Manufacturer"]} {obj["SMBIOSBIOSVersion"]}";
                        break;
                    }
                }

                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var adapter in adapters.Where(a => a.OperationalStatus == OperationalStatus.Up))
                {
                    info.NetworkAdapters.Add($"{adapter.Name} ({adapter.NetworkInterfaceType})");
                }

                info.UpdateStatus = CheckWindowsVersionStatus();

            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения системной информации: {ex.Message}");
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
            try
            {
                var allProcesses = Process.GetProcesses();
                foreach (var process in allProcesses)
                {
                    try
                    {
                        var processInfo = new ProcessInfo
                        {
                            Name = process.ProcessName,
                            Id = process.Id,
                            MemoryMB = process.WorkingSet64 / 1024.0 / 1024.0,
                            Cpu = GetProcessCpuUsage(process),
                            ProcessPath = GetProcessPathSafe(process),
                            WindowTitle = process.MainWindowTitle ?? string.Empty
                        };
                        processInfo.IsUserProcess = processInfo.CheckIsUserProcess();
                        processes.Add(processInfo);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Не удалось получить информацию о процессе {process.ProcessName}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения процессов: {ex.Message}");
            }
            return processes.OrderByDescending(p => p.MemoryMB).ToList();
        }

        private double GetProcessCpuUsage(Process process)
        {
            try
            {
                var startTime = DateTime.Now;
                var startCpuUsage = process.TotalProcessorTime;
                System.Threading.Thread.Sleep(100);
                var endTime = DateTime.Now;
                var endCpuUsage = process.TotalProcessorTime;
                var cpuUsedMs = (endCpuUsage - startCpuUsage).TotalMilliseconds;
                var totalMsPassed = (endTime - startTime).TotalMilliseconds;
                var cpuUsage = cpuUsedMs / (Environment.ProcessorCount * totalMsPassed) * 100;
                return Math.Round(cpuUsage, 1);
            }
            catch
            {
                return 0;
            }
        }

        private string GetProcessPathSafe(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "Нет доступа";
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return "Требуются права администратора";
            }
            catch (Exception ex)
            {
                return $"Ошибка доступа: {ex.Message}";
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
            var processCache = new Dictionary<int, string>();

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netstat", "-ano -p TCP")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(psi))
                {
                    if (process == null) return connections;

                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                
                    var regex = new Regex(@"^\s*TCP\s+([\d\.:\[\]]+):(\d+)\s+([\d\.:\[\]]+):(\d+)\s+ESTABLISHED\s+(\d+)\s*$", RegexOptions.Multiline);

                    foreach (Match match in regex.Matches(output))
                    {
                        string localAddress = match.Groups[1].Value;
                        int localPort = int.Parse(match.Groups[2].Value);
                        string remoteAddress = match.Groups[3].Value;
                        int remotePort = int.Parse(match.Groups[4].Value);
                        int pid = int.Parse(match.Groups[5].Value);

                    
                        if (IPAddress.TryParse(remoteAddress.Replace("[", "").Replace("]", ""), out IPAddress ip) && IPAddress.IsLoopback(ip))
                        {
                            continue;
                        }

                        string processName = "N/A";
                        if (pid > 0)
                        {
                            if (processCache.ContainsKey(pid))
                            {
                                processName = processCache[pid];
                            }
                            else
                            {
                                try
                                {
                                    processName = Process.GetProcessById(pid).ProcessName;
                                    processCache[pid] = processName;
                                }
                                catch { 
                                
                                }
                            }
                        }

               
                        var (portName, portPurpose) = PortDescriptionService.GetPortDescription(remotePort);

                        connections.Add(new NetworkConnectionInfo
                        {
                            
                           _localAddress = localAddress,
                            _localPort = localPort,
                            _remoteAddress = remoteAddress,
                            _remotePort = remotePort,
                            _state = "ESTABLISHED",
                            _processId = pid,
                            _processName = processName,
                            _remotePortDescription = $"{remotePort} ({portName})",
                            _connectionPurpose = portPurpose,
                            _localPortDescription = PortDescriptionService.GetLocalPortDescription(localPort)
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения сетевых подключений (netstat): {ex.Message}");
            }
            return connections;
        }

        #region Network P/Invoke Structs

        // Структуры для вызова GetExtendedTcpTable
        private const int AF_INET = 2; // IPv4

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

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
            public MIB_TCPROW_OWNER_PID[] table;
        }

        // Импорт функции API
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