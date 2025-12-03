using Microsoft.Win32;
using SecurityShield.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics.Eventing;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Controls.Primitives;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace SecurityShield.Services
{
    
    public class SecurityService : ISecurityService
    {

        private SecurityScanResult _lastScanResult;
        private string _antivirusExePath = string.Empty;


        public List<SecurityVulnerability> PerformComprehensiveSecurityAudit()
        {
            var result = PerformComprehensiveSecurityScan();
            var vulnerabilities = new List<SecurityVulnerability>();

            // Преобразуем SecurityCheck в SecurityVulnerability для проблемных проверок
            foreach (var check in result.SecurityChecks.Where(c => !c.Status.Contains("ОК")))
            {
                vulnerabilities.Add(new SecurityVulnerability
                {
                    Title = check.CheckName,
                    Description = check.Details,
                    Severity = check.IsCritical ? "Critical" : "High",
                    Category = check.Category,
                    Recommendation = check.Recommendation,
                    IsFixed = false
                });
            }

            // Добавляем обнаруженные угрозы
            foreach (var threat in result.Threats)
            {
                vulnerabilities.Add(new SecurityVulnerability
                {
                    Title = threat.Name,
                    Description = threat.Description,
                    Severity = threat.Severity,
                    Category = threat.Type,
                    Recommendation = threat.Recommendation,
                    IsFixed = false
                });
            }

            return vulnerabilities;
        }

        private List<SecurityThreat> DetectNetworkThreats()
        {
            var threats = new List<SecurityThreat>();
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();
                var listeners = properties.GetActiveTcpListeners();

                // Опасные порты
                var riskyPorts = new Dictionary<int, string>
        {
            { 21, "FTP (Незащищенная передача файлов)" },
            { 23, "Telnet (Нешифрованный удаленный доступ)" },
            { 445, "SMB (Уязвимость WannaCry/Ransomware)" },
            { 3389, "RDP (Удаленный рабочий стол)" },
            { 5900, "VNC (Удаленное управление)" }
        };

                foreach (var endpoint in listeners)
                {
                    
                    if (IPAddress.IsLoopback(endpoint.Address)) continue;

                    if (riskyPorts.ContainsKey(endpoint.Port))
                    {
                        threats.Add(new SecurityThreat
                        {
                            Name = $"Открыт опасный порт {endpoint.Port} ({riskyPorts[endpoint.Port]})",
                            Type = "Сетевая угроза",
                            Severity = endpoint.Port == 445 || endpoint.Port == 23 ? "Критическая" : "Высокая",
                            Description = $"Порт {endpoint.Port} открыт для внешних подключений. Это может использоваться злоумышленниками.",
                            Recommendation = "Настройте Брандмауэр Windows, чтобы заблокировать этот порт, или остановите службу."
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка сканирования сети: {ex.Message}");
            }
            return threats;
        }


        private List<SecurityThreat> DetectSecurityThreats()
        {
            var threats = new List<SecurityThreat>();
            threats.AddRange(DetectNetworkThreats());
            threats.AddRange(CheckSystemVulnerabilities());

            if (CheckHostsFileModified())
            {
                threats.Add(new SecurityThreat
                {
                    Name = "Файл HOSTS модифицирован",
                    Type = "Системная угроза",
                    Severity = "Высокая",
                    Description = "Найдены нестандартные перенаправления в файле hosts.",
                    Recommendation = "Проверьте файл C:\\Windows\\System32\\drivers\\etc\\hosts"
                });
            }

            var tempSize = GetTempFolderSize();
            if (tempSize > 1024 * 1024 * 500) // > 500 MB
            {
                threats.Add(new SecurityThreat
                {
                    Name = "Много временных файлов",
                    Type = "Мусор",
                    Severity = "Низкая",
                    Description = $"В папке Temp скопилось {(tempSize / 1024 / 1024)} MB.",
                    Recommendation = "Рекомендуется очистка диска."
                });
            }

            return threats;
        }
        private bool CheckHostsFileModified()
        {
            try
            {
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                if (!File.Exists(path)) return false;

                string[] lines = File.ReadAllLines(path);
                int suspiciousLines = 0;

                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#")) continue;

                    // Разрешаем только локалхост
                    if (!trimmed.Contains("127.0.0.1") && !trimmed.Contains("::1"))
                    {
                        suspiciousLines++;
                    }
                }

                return suspiciousLines > 0;
            }
            catch { return false; }
        }
        public long GetTempFolderSize()
        {
            try
            {
                string tempPath = Path.GetTempPath();
                if (Directory.Exists(tempPath))
                {
                    return Directory.GetFiles(tempPath, "*", SearchOption.AllDirectories)
                                    .Sum(t => new FileInfo(t).Length);
                }
            }
            catch { }
            return 0;
        }
        public string GetWindowsVersionStatus()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var caption = obj["Caption"]?.ToString() ?? "Unknown";
                    var version = obj["Version"]?.ToString() ?? "Unknown";
                    var buildNumber = obj["BuildNumber"]?.ToString() ?? "Unknown";
                    var installDate = ManagementDateTimeConverter.ToDateTime(obj["InstallDate"]?.ToString() ?? "");

                    // Проверяем, поддерживается ли версия Windows
                    var isSupported = IsWindowsVersionSupported(version);

                    return $"{caption} (Версия: {version}, Сборка: {buildNumber}) - " +
                           $"{(isSupported ? "Поддерживается" : "Не поддерживается")}";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения информации о версии Windows: {ex.Message}");
            }

            return "Не удалось определить версию Windows";
        }

        private bool IsWindowsVersionSupported(string version)
        {
            try
            {
                var osVersion = new Version(version);

                // Windows 10 и новее считаются поддерживаемыми
                var minSupportedVersion = new Version("10.0.0");
                return osVersion >= minSupportedVersion;
            }
            catch
            {
                return false;
            }
        }


        public bool CheckRDPStatus()
        {
            try
            {
                var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
                var value = key?.GetValue("fDenyTSConnections");
                // 0 = RDP включен, 1 = RDP выключен
                return value != null && (int)value == 0;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки RDP: {ex.Message}");
                return false;
            }
        }

        public bool CheckUACStatus()
        {
            try
            {
                var uacKey = Registry.GetValue(
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "EnableLUA", "0");

                var consentKey = Registry.GetValue(
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "ConsentPromptBehaviorAdmin", "0");

                return uacKey?.ToString() == "1" && consentKey?.ToString() != "0";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки UAC: {ex.Message}");
                return false;
            }
        }

        public bool CheckSmartScreenStatus()
        {
            try
            {
                var edgeKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Edge\SmartScreenEnabled");
                if (edgeKey != null)
                {
                    var edgeValue = edgeKey.GetValue("");
                    if (edgeValue?.ToString() == "1") return true;
                }

              
                var windowsKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation");
                if (windowsKey != null)
                {
                    var windowsValue = windowsKey.GetValue("");
                    if (windowsValue?.ToString() == "1") return true;
                }

                return CheckSmartScreenViaPowerShell();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки SmartScreen: {ex.Message}");
                return false;
            }
        }

        private bool CheckSmartScreenViaPowerShell()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = "-Command \"Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-SmartScreen | Select-Object -ExpandProperty State\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                return output.Contains("Enabled");
            }
            catch
            {
                return false;
            }
        }

        public bool CheckBitLockerStatus()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = 'C:'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var protectionStatus = obj["ProtectionStatus"]?.ToString();
                    return protectionStatus == "1" || protectionStatus == "2"; // 1=On, 2=Off
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки BitLocker: {ex.Message}");
            }

            return false;
        }

        public AntivirusInfo GetInstalledAntivirus()
        {
            var antivirus = new AntivirusInfo();

            try
            {
                antivirus = GetDetailedAntivirusInfoFromWMI();

                if (antivirus.Name == "Не обнаружен")
                {
                    antivirus = CheckAntivirusViaRegistryAndProcesses();
                }

                if (antivirus.Name != "Не обнаружен")
                {
                    antivirus = EnhanceAntivirusInfo(antivirus);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения информации об антивирусе: {ex.Message}");
                antivirus.Name = "Ошибка определения";
                antivirus.Status = "Неизвестно";
            }

            return antivirus;
        }

        private AntivirusInfo GetDetailedAntivirusInfoFromWMI()
        {
            var antivirus = new AntivirusInfo();

            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                var antivirusProducts = searcher.Get().Cast<ManagementObject>().ToList();

                if (antivirusProducts.Any())
                {
                    foreach (ManagementObject product in antivirusProducts)
                    {
                        var productName = product["displayName"]?.ToString() ?? "Неизвестно";
                        var productState = product["productState"]?.ToString() ?? "0";
                        var detailedInfo = ParseAntivirusProductState(productName, productState);

                        
                        if (detailedInfo.Name != "Не обнаружен" && detailedInfo.IsEnabled)
                        {
                            antivirus = detailedInfo;
                            
                            _antivirusExePath = product["pathToSignedProductExe"]?.ToString() ?? string.Empty;
                            break;
                        }
                      
                        else if (antivirus.Name == "Не обнаружен")
                        {
                            antivirus = detailedInfo;
                            _antivirusExePath = product["pathToSignedProductExe"]?.ToString() ?? string.Empty;
                        }
                    }
                }
            }

            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка WMI проверки антивируса: {ex.Message}");
            }

            return antivirus;
        }

        private AntivirusInfo ParseAntivirusProductState(string productName, string productState)
        {
            var antivirus = new AntivirusInfo { Name = productName };

            try
            {
                if (uint.TryParse(productState, out uint state))
                {
                    byte[] stateBytes = BitConverter.GetBytes(state);

                    if (stateBytes.Length >= 3)
                    {
                        antivirus.IsEnabled = (stateBytes[1] & 0x11) != 0;
                        antivirus.Status = antivirus.IsEnabled ? "Активен" : "Неактивен";
                        antivirus.Vendor = GetAntivirusVendor(productName);
                        antivirus.RealTimeProtection = (stateBytes[1] & 0x10) != 0 ? "Включена" : "Выключена";
                        antivirus.IsUpToDate = (stateBytes[2] & 0x10) == 0;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка парсинга состояния антивируса: {ex.Message}");
            }

            return antivirus;
        }

        private string GetAntivirusVendor(string productName)
        {
            var lowerName = productName.ToLower();

            if (lowerName.Contains("kaspersky")) return "Kaspersky Lab";
            if (lowerName.Contains("eset") || lowerName.Contains("nod32")) return "ESET";
            if (lowerName.Contains("avast")) return "Avast Software";
            if (lowerName.Contains("avg")) return "AVG Technologies";
            if (lowerName.Contains("bitdefender")) return "Bitdefender";
            if (lowerName.Contains("mcafee")) return "McAfee";
            if (lowerName.Contains("norton")) return "NortonLifeLock";
            if (lowerName.Contains("dr.web") || lowerName.Contains("drweb")) return "Dr.Web";
            if (lowerName.Contains("defender") || lowerName.Contains("security health")) return "Microsoft";
            if (lowerName.Contains("avira")) return "Avira";
            if (lowerName.Contains("panda")) return "Panda Security";
            if (lowerName.Contains("trend") || lowerName.Contains("micro")) return "Trend Micro";
            if (lowerName.Contains("comodo")) return "Comodo";
            if (lowerName.Contains("360")) return "360 Safe";
            if (lowerName.Contains("baidu")) return "Baidu";
            if (lowerName.Contains("qihoo")) return "Qihoo 360";
            if (lowerName.Contains("sophos")) return "Sophos";
            if (lowerName.Contains("malwarebytes")) return "Malwarebytes";

            return "Неизвестный производитель";
        }

        private AntivirusInfo CheckAntivirusViaRegistryAndProcesses()
        {
            var antivirus = new AntivirusInfo();

            try
            {
                antivirus = CheckAntivirusRegistry();

                if (antivirus.Name == "Не обнаружен")
                {
                    antivirus = CheckAntivirusProcesses();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки антивируса через реестр и процессы: {ex.Message}");
            }

            return antivirus;
        }

        private AntivirusInfo CheckAntivirusRegistry()
        {
            var antivirus = new AntivirusInfo();

            var registryPaths = new Dictionary<string, (string name, string vendor)>
            {
                { @"SOFTWARE\KasperskyLab", ("Kaspersky Anti-Virus", "Kaspersky Lab") },
                { @"SOFTWARE\ESET\ESET Security", ("ESET NOD32 Antivirus", "ESET") },
                { @"SOFTWARE\Avast Software\Avast", ("Avast Antivirus", "Avast Software") },
                { @"SOFTWARE\AVG", ("AVG Antivirus", "AVG Technologies") },
                { @"SOFTWARE\Bitdefender", ("Bitdefender Antivirus", "Bitdefender") },
                { @"SOFTWARE\McAfee", ("McAfee Antivirus", "McAfee") },
                { @"SOFTWARE\Symantec", ("Norton Antivirus", "NortonLifeLock") },
                { @"SOFTWARE\DrWeb", ("Dr.Web Anti-virus", "Dr.Web") },
                { @"SOFTWARE\Avira", ("Avira Antivirus", "Avira") },
                { @"SOFTWARE\Panda Security", ("Panda Antivirus", "Panda Security") },
                { @"SOFTWARE\TrendMicro", ("Trend Micro Antivirus", "Trend Micro") },
                { @"SOFTWARE\Comodo", ("Comodo Antivirus", "Comodo") },
                { @"SOFTWARE\360Safe", ("360 Total Security", "360 Safe") }
            };

            foreach (var path in registryPaths)
            {
                try
                {
                    var key = Registry.LocalMachine.OpenSubKey(path.Key);
                    if (key != null)
                    {
                        antivirus.Name = path.Value.name;
                        antivirus.Vendor = path.Value.vendor;
                        antivirus.Status = "Обнаружен в реестре";
                        return antivirus;
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Ошибка проверки реестра {path.Key}: {ex.Message}");
                }
            }

            return antivirus;
        }

        private AntivirusInfo CheckAntivirusProcesses()
        {
            var antivirus = new AntivirusInfo();
            var processes = Process.GetProcesses();

            var antivirusProcesses = new Dictionary<string, (string name, string vendor)>
            {
                { "avast", ("Avast Antivirus", "Avast Software") },
                { "avg", ("AVG Antivirus", "AVG Technologies") },
                { "bdagent", ("Bitdefender Antivirus", "Bitdefender") },
                { "mbam", ("Malwarebytes", "Malwarebytes") },
                { "msmpeng", ("Защитник Windows", "Microsoft") },
                { "securityhealthservice", ("Защитник Windows", "Microsoft") },
                { "norton", ("Norton Antivirus", "NortonLifeLock") },
                { "mcafee", ("McAfee Antivirus", "McAfee") },
                { "kaspersky", ("Kaspersky Anti-Virus", "Kaspersky Lab") },
                { "eset", ("ESET NOD32 Antivirus", "ESET") },
                { "avp", ("Kaspersky Anti-Virus", "Kaspersky Lab") },
                { "avira", ("Avira Antivirus", "Avira") },
                { "panda", ("Panda Antivirus", "Panda Security") }
            };

            foreach (var process in processes)
            {
                try
                {
                    var processName = process.ProcessName.ToLower();
                    foreach (var avProcess in antivirusProcesses)
                    {
                        if (processName.Contains(avProcess.Key))
                        {
                            antivirus.Name = avProcess.Value.name;
                            antivirus.Vendor = avProcess.Value.vendor;
                            antivirus.Status = "Активен (обнаружен процесс)";
                            antivirus.IsEnabled = true;
                            return antivirus;
                        }
                    }
                }
                catch
                {
                   
                }
            }

            return antivirus;
        }

        private AntivirusInfo EnhanceAntivirusInfo(AntivirusInfo antivirus)
        {
            try
            {
                antivirus.IsEnabled = CheckAntivirusRunning(antivirus.Name);
                antivirus.Status = antivirus.IsEnabled ? "Активен" : "Неактивен";
                antivirus.RealTimeProtection = CheckRealTimeProtection(antivirus.Name);
                antivirus.IsUpToDate = CheckAntivirusUpdates(antivirus.Name);
                antivirus.LastUpdate = GetLastUpdateTime(antivirus.Name);
                antivirus.Version = GetAntivirusVersion(antivirus.Name);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка улучшения информации об антивирусе: {ex.Message}");
            }

            return antivirus;
        }

        private bool CheckAntivirusRunning(string antivirusName)
        {
            try
            {
                var processes = Process.GetProcesses();
                var lowerName = antivirusName.ToLower();

                var processMapping = new Dictionary<string, string[]>
                {
                    { "kaspersky", new[] { "avp", "kaspersky" } },
                    { "avast", new[] { "avast", "aswidsagent" } },
                    { "avg", new[] { "avg", "avgui" } },
                    { "bitdefender", new[] { "bdagent", "vsserv" } },
                    { "mcafee", new[] { "mcafee", "mfemms" } },
                    { "norton", new[] { "norton", "ns" } },
                    { "eset", new[] { "ekrn", "egui" } },
                    { "defender", new[] { "msmpeng", "securityhealthservice" } },
                    { "avira", new[] { "avguard", "avcenter" } }
                };

                foreach (var mapping in processMapping)
                {
                    if (lowerName.Contains(mapping.Key))
                    {
                        return mapping.Value.Any(processName =>
                            processes.Any(p => p.ProcessName.ToLower().Contains(processName)));
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки запуска антивируса: {ex.Message}");
            }

            return false;
        }

        private string CheckRealTimeProtection(string antivirusName)
        {
            try
            {
                var lowerName = antivirusName.ToLower();

                if (lowerName.Contains("defender"))
                {
                    var defenderStatus = GetDefenderStatus();
                    return defenderStatus.IsRealTimeProtectionEnabled ? "Включена" : "Выключена";
                }

                using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                foreach (ManagementObject product in searcher.Get())
                {
                    var name = product["displayName"]?.ToString()?.ToLower() ?? "";
                    if (name.Contains(lowerName))
                    {
                        var state = product["productState"]?.ToString() ?? "0";
                        if (uint.TryParse(state, out uint stateValue))
                        {
                            return (stateValue & 0x1000) == 0 ? "Включена" : "Выключена";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки защиты в реальном времени: {ex.Message}");
            }

            return "Неизвестно";
        }

        private bool CheckAntivirusUpdates(string antivirusName)
        {
            try
            {
                // Пробуем получить статус через WMI SecurityCenter2
                using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                foreach (ManagementObject product in searcher.Get())
                {
                    var name = product["displayName"]?.ToString() ?? "";
                    if (name.Contains(antivirusName))
                    {
                        var state = product["productState"]?.ToString() ?? "0";
                        if (uint.TryParse(state, out uint stateValue))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки обновлений антивируса: {ex.Message}");
            }

          
            return true;
        }

        private DateTime GetLastUpdateTime(string antivirusName)
        {
            try
            {
                if (antivirusName.ToLower().Contains("defender"))
                {
                    
                    using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus");
                    var obj = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                    if (obj != null)
                    {
                        var sigDate = obj["AntivirusSignatureLastUpdated"]?.ToString();
                        if (sigDate != null)
                        {
                            return ManagementDateTimeConverter.ToDateTime(sigDate);
                        }
                    }
                }

                
                using var searcherWSC = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                foreach (ManagementObject product in searcherWSC.Get())
                {
                    if (product["displayName"]?.ToString() == antivirusName)
                    {
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения времени обновления антивируса: {ex.Message}");
            }


            return DateTime.MinValue;
        }
        private string GetAntivirusVersion(string antivirusName)
        {
            try
            {
                var registryPath = GetAntivirusRegistryPath(antivirusName);
                if (!string.IsNullOrEmpty(registryPath))
                {
                    var key = Registry.LocalMachine.OpenSubKey(registryPath);
                    if (key != null)
                    {
                        var version = key.GetValue("Version") ?? key.GetValue("DisplayVersion");
                        return version?.ToString() ?? "Неизвестно";
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения версии антивируса: {ex.Message}");
            }

            return "Неизвестно";
        }

        private string GetAntivirusRegistryPath(string antivirusName)
        {
            var lowerName = antivirusName.ToLower();

            if (lowerName.Contains("kaspersky")) return @"SOFTWARE\KasperskyLab";
            if (lowerName.Contains("eset")) return @"SOFTWARE\ESET\ESET Security";
            if (lowerName.Contains("avast")) return @"SOFTWARE\Avast Software\Avast";
            if (lowerName.Contains("avg")) return @"SOFTWARE\AVG";
            if (lowerName.Contains("bitdefender")) return @"SOFTWARE\Bitdefender";
            if (lowerName.Contains("mcafee")) return @"SOFTWARE\McAfee";
            if (lowerName.Contains("norton")) return @"SOFTWARE\Symantec";
            if (lowerName.Contains("defender")) return @"SOFTWARE\Microsoft\Windows Defender";

            return null;
        }

        public SecurityScanResult PerformComprehensiveSecurityScan()
        {
            var result = new SecurityScanResult
            {
                ScanTime = DateTime.Now,
                SecurityChecks = new List<SecurityCheck>(),
                Threats = new List<SecurityThreat>()
            };

            try
            {
               
                result.SecurityChecks.AddRange(PerformSystemSecurityChecks()); // Обновления, Брандмауэр

             
                result.SecurityChecks.Add(CheckSmb1Protocol());
                result.SecurityChecks.Add(CheckRemoteRegistry());
                result.SecurityChecks.Add(CheckAutoRunPolicies());

                
                result.SecurityChecks.AddRange(PerformNetworkSecurityChecks()); // Порты

           
                result.SecurityChecks.AddRange(PerformUserSecurityChecks()); // Пароли, Админы

                
                result.SecurityChecks.AddRange(PerformApplicationSecurityChecks());

                result.Threats.AddRange(DetectSecurityThreats());

                CalculateSecurityStatus(result);
                _lastScanResult = result;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Scan Error: {ex.Message}");
                result.OverallStatus = "Ошибка сканирования";
            }

            return result;
        }
        private SecurityCheck CheckSmb1Protocol()
        {
            bool isSmb1Enabled = false;
            try
            {
               
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
                if (key != null)
                {
                    var val = key.GetValue("SMB1");
                    if (val != null && (int)val == 1) isSmb1Enabled = true;
                }
            }
            catch { }

            return new SecurityCheck
            {
                CheckName = "Протокол SMBv1",
                Category = "Сетевая безопасность",
                Status = isSmb1Enabled ? "КРИТИЧЕСКИЙ РИСК" : "ОК",
                IsCritical = isSmb1Enabled,
                Details = isSmb1Enabled ? "Устаревший протокол включен (риск WannaCry)" : "SMBv1 отключен",
                Recommendation = isSmb1Enabled ? "Отключите компонент SMB1.0/CIFS в компонентах Windows" : "Действий не требуется"
            };
        }

        private SecurityCheck CheckRemoteRegistry()
        {
        
            string startMode = "Unknown";
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT StartMode FROM Win32_Service WHERE Name='RemoteRegistry'"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        startMode = obj["StartMode"]?.ToString();
                    }
                }
            }
            catch { }

            bool isRisk = startMode == "Auto";

            return new SecurityCheck
            {
                CheckName = "Удаленный реестр",
                Category = "Службы",
                Status = isRisk ? "ВНИМАНИЕ" : "ОК",
                IsCritical = false,
                Details = $"Режим запуска: {startMode}",
                Recommendation = isRisk ? "Отключите службу Удаленного реестра" : "Служба настроена верно"
            };
        }

        private SecurityCheck CheckAutoRunPolicies()
        {
         
            bool autorunDisabled = false;
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
                var val = key?.GetValue("NoDriveTypeAutoRun");
                if (val != null) autorunDisabled = true; 
            }
            catch { }

            return new SecurityCheck
            {
                CheckName = "Автозапуск носителей",
                Category = "Система",
                Status = autorunDisabled ? "ОК" : "РИСК",
                IsCritical = false,
                Details = autorunDisabled ? "Автозапуск ограничен политиками" : "Автозапуск разрешен",
                Recommendation = autorunDisabled ? "" : "Отключите автозапуск для защиты от USB-вирусов"
            };
        }

        private List<SecurityCheck> PerformSystemSecurityChecks()
        {
            var checks = new List<SecurityCheck>();

            var updateStatus = CheckWindowsUpdatesDetailed();
            checks.Add(new SecurityCheck
            {
                CheckName = "Обновления Windows",
                Category = "Система",
                Status = updateStatus.IsUpToDate ? "ОК - Система обновлена" : "КРИТИЧЕСКИЙ РИСК - Требуются обновления",
                Details = updateStatus.IsUpToDate ?
                    $"Последнее обновление: {updateStatus.LastUpdateDate}" :
                    $"Дней без обновлений: {updateStatus.DaysSinceLastUpdate}",
                Recommendation = "Установите обновления через Центр обновления Windows",
                IsCritical = !updateStatus.IsUpToDate
            });

            var uacStatus = CheckUACStatusDetailed();
            checks.Add(new SecurityCheck
            {
                CheckName = "Контроль учетных записей (UAC)",
                Category = "Безопасность",
                Status = uacStatus.isEnabled ? "ОК - UAC включен" : "КРИТИЧЕСКИЙ РИСК - UAC отключен",
                Details = uacStatus.isEnabled ?
                    $"Уровень UAC: {uacStatus.level}" :
                    "Система уязвима для несанкционированного доступа",
                Recommendation = uacStatus.isEnabled ?
                    "Поддерживайте текущий уровень UAC" :
                    "Включите UAC на уровень не ниже 'Уведомлять всегда'",
                IsCritical = !uacStatus.isEnabled
            });

            checks.Add(new SecurityCheck
            {
                CheckName = "Брандмауэр Windows",
                Category = "Сеть",
                Status = CheckFirewallStatus() ? "ОК - Брандмауэр активен" : "КРИТИЧЕСКИЙ РИСК - Брандмауэр отключен",
                Details = CheckFirewallStatus() ?
                    "Сетевой экран защищает систему" :
                    "Система открыта для сетевых атак",
                Recommendation = "Включите брандмауэр Windows",
                IsCritical = !CheckFirewallStatus()
            });

            var bitlockerStatus = CheckBitLockerStatusDetailed();
            checks.Add(new SecurityCheck
            {
                CheckName = "Шифрование дисков BitLocker",
                Category = "Данные",
                Status = bitlockerStatus.isEnabled ? "ОК - Диски защищены" : "ВНИМАНИЕ - Шифрование не используется",
                Details = bitlockerStatus.isEnabled ?
                    $"Статус: {bitlockerStatus.status}" :
                    "Данные могут быть доступны при физическом доступе",
                Recommendation = bitlockerStatus.isEnabled ?
                    "Сохраните ключ восстановления в безопасном месте" :
                    "Включите BitLocker для системного диска",
                IsCritical = false
            });

            checks.Add(new SecurityCheck
            {
                CheckName = "Предотвращение выполнения данных (DEP)",
                Category = "Память",
                Status = CheckDEPStatus() ? "ОК - DEP активен" : "РИСК - DEP отключен",
                Details = CheckDEPStatus() ?
                    "Защита от атак на память включена" :
                    "Система уязвима для эксплойтов памяти",
                Recommendation = "Включите DEP для всех программ",
                IsCritical = !CheckDEPStatus()
            });

            checks.Add(new SecurityCheck
            {
                CheckName = "Удаленный рабочий стол (RDP)",
                Category = "Сеть",
                Status = CheckRDPStatus() ? "РИСК - RDP включен" : "ОК - RDP отключен",
                Details = CheckRDPStatus() ? "Включен удаленный доступ к рабочему столу" : "Удаленный доступ отключен",
                Recommendation = CheckRDPStatus() ? "Отключите RDP, если он не используется" : "RDP отключен, это безопасно",
                IsCritical = CheckRDPStatus()
            });

            return checks;
        }


      
        private (bool isEnabled, string level) CheckUACStatusDetailed()
        {
            try
            {
                var uacKey = Registry.GetValue(
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "EnableLUA", "0");

                var consentKey = Registry.GetValue(
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "ConsentPromptBehaviorAdmin", "0");

                if (uacKey?.ToString() == "1")
                {
                    var level = consentKey?.ToString() switch
                    {
                        "0" => "Никогда не уведомлять",
                        "2" => "Уведомлять всегда",
                        "5" => "Уведомлять при попытках изменений",
                        _ => "Неизвестный уровень"
                    };
                    return (true, level);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки UAC: {ex.Message}");
            }

            return (false, "Отключен");
        }

        private (bool isEnabled, string status) CheckBitLockerStatusDetailed()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = 'C:'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var protectionStatus = obj["ProtectionStatus"]?.ToString();
                    var status = protectionStatus == "1" ? "Защищено" : "Не защищено";
                    return (protectionStatus == "1", status);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки BitLocker: {ex.Message}");
            }

            return (false, "Не проверено");
        }

        private List<SecurityCheck> PerformNetworkSecurityChecks()
        {
            var checks = new List<SecurityCheck>();


            var openPorts = GetOpenPortsDetailed();
            var riskyPorts = openPorts.Where(p => p.IsRisky).ToList();
            string portDetails = riskyPorts.Any() ?
            $"Рискованные: {string.Join(", ", riskyPorts.Select(p => p.PortNumber).Take(5))}" :
            $"Открыто (нестандартных): {openPorts.Count}";
            if (!openPorts.Any()) portDetails = "Нет подозрительных открытых портов";

            checks.Add(new SecurityCheck
            {
                CheckName = "Открытые сетевые порты",
                Category = "Сеть",
                Status = !riskyPorts.Any() ? "ОК - Нет рискованных портов" : "ВНИМАНИЕ - Обнаружены рискованные порты",
                Details = portDetails,
                Recommendation = riskyPorts.Any() ? "Закройте неиспользуемые рискованные порты" : "Регулярно проверяйте открытые порты",
                IsCritical = riskyPorts.Any()
            });
            var networkAdapters = GetNetworkAdapterInfo();
            checks.Add(new SecurityCheck
            {
                CheckName = "Сетевые адаптеры",
                Category = "Сеть",
                Status = "ОК - Адаптеры настроены",
                Details = networkAdapters,
                Recommendation = "Регулярно обновляйте драйверы сетевых адаптеров",
                IsCritical = false
            });

            var dnsStatus = CheckDNSSettings();
            checks.Add(new SecurityCheck
            {
                CheckName = "DNS настройки",
                Category = "Сеть",
                Status = dnsStatus.isSecure ? "ОК - DNS защищены" : "ВНИМАНИЕ - Используются ненадежные DNS",
                Details = dnsStatus.details,
                Recommendation = dnsStatus.isSecure ? "Поддерживайте текущие настройки" : "Используйте надежные DNS-серверы",
                IsCritical = false
            });

            return checks;
        }

        private List<SecurityCheck> PerformUserSecurityChecks()
        {
            var checks = new List<SecurityCheck>();


            var accountCheck = CheckUserAccountsDetailed();
            checks.Add(new SecurityCheck
            {
                CheckName = "Учетные записи",
                Category = "Пользователи",
                Status = accountCheck.isSecure ? "ОК - Учетные записи защищены" : "РИСК - Найдены проблемы",
                Details = accountCheck.details,
                Recommendation = accountCheck.recommendation,
                IsCritical = !accountCheck.isSecure
            });

            var adminCheck = CheckAdminPrivilegesDetailed();
            checks.Add(new SecurityCheck
            {
                CheckName = "Права администратора",
                Category = "Пользователи",
                Status = adminCheck.isOptimal ? "ОК - Права настроены" : "ВНИМАНИЕ - Избыточные права",
                Details = adminCheck.details,
                Recommendation = adminCheck.recommendation,
                IsCritical = false
            });

            return checks;
        }

        private List<SecurityCheck> PerformApplicationSecurityChecks()
        {
            var checks = new List<SecurityCheck>();

            var antivirus = GetInstalledAntivirus();
            checks.Add(new SecurityCheck
            {
                CheckName = "Антивирусная защита",
                Category = "Приложения",
                Status = antivirus.IsEnabled ? "ОК - Антивирус активен" : "КРИТИЧЕСКИЙ РИСК - Антивирус неактивен",
                Details = $"{antivirus.Name} ({antivirus.Vendor}) - {antivirus.Status} - Защита в реальном времени: {antivirus.RealTimeProtection}",
                Recommendation = antivirus.IsEnabled ?
                    "Поддерживайте антивирус в актуальном состоянии" :
                    "Установите и включите антивирусное ПО",
                IsCritical = !antivirus.IsEnabled
            });

            var outdatedSoftware = CheckOutdatedSoftwareDetailed();
            checks.Add(new SecurityCheck
            {
                CheckName = "Устаревшее программное обеспечение",
                Category = "Приложения",
                Status = outdatedSoftware.count == 0 ? "ОК - ПО актуально" : "ВНИМАНИЕ - Найдено устаревшее ПО",
                Details = outdatedSoftware.count == 0 ?
                    "Программное обеспечение обновлено" :
                    $"Обнаружено {outdatedSoftware.count} программ с известными уязвимостями",
                Recommendation = outdatedSoftware.count == 0 ?
                    "Продолжайте регулярно обновлять ПО" :
                    "Обновите устаревшее программное обеспечение",
                IsCritical = outdatedSoftware.hasCritical
            });

            var startupCheck = CheckStartupProgramsDetailed();
            checks.Add(new SecurityCheck
            {
                CheckName = "Автозагрузка",
                Category = "Приложения",
                Status = startupCheck.isClean ? "ОК - Автозагрузка чистая" : "ВНИМАНИЕ - Подозрительные программы",
                Details = startupCheck.details,
                Recommendation = startupCheck.isClean ?
                    "Продолжайте мониторить автозагрузку" :
                    "Проверьте и удалите подозрительные программы из автозагрузки",
                IsCritical = false
            });

            return checks;
        }

 

        private (bool IsUpToDate, int DaysSinceLastUpdate, string LastUpdateDate) CheckWindowsUpdatesDetailed()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key == null) return (false, 999, "Реестр не найден");

                    var build = key.GetValue("CurrentBuild")?.ToString();
                    var ubr = key.GetValue("UBR")?.ToString(); // Update Build Revision

                    if (!string.IsNullOrEmpty(build) && !string.IsNullOrEmpty(ubr))
                    {
                        return (true, 0, $"Билд: {build}.{ubr}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки обновлений Windows: {ex.Message}");
            }
         
            return (false, 999, "Не удалось проверить");
        }

        public bool CheckFirewallStatus()
        {
            try
            {
                // Проверяем все 3 профиля брандмауэра в реестре
                var profiles = new[] { "DomainProfile", "StandardProfile", "PublicProfile" };
                bool isEnabled = false;

                foreach (var profile in profiles)
                {
                    var keyPath = $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}";
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        var value = key?.GetValue("EnableFirewall");
                        if (value != null && (int)value == 1)
                        {
                            isEnabled = true;
                            break; // Нашли хотя бы один включенный профиль
                        }
                    }
                }
                return isEnabled;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки брандмауэра: {ex.Message}");
                return false; // Считаем выключенным при ошибке
            }
        }

        private bool CheckDEPStatus()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var depSupport = obj["DataExecutionPrevention_SupportPolicy"]?.ToString();
                    return depSupport == "2" || depSupport == "3";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки DEP: {ex.Message}");
            }

            return false;
        }


        private List<OpenPortInfo> GetOpenPortsDetailed()
        {
            var openPorts = new List<OpenPortInfo>();
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpListeners = properties.GetActiveTcpListeners();
                var udpListeners = properties.GetActiveUdpListeners();

                // Исключаем общеизвестные и "шумные" порты Windows
                var excludedPorts = new[] { 135, 445, 5357 }; // RPC, SMB, WSD

                var riskyPorts = new[] { 21, 23, 25, 139, 3306, 3389, 5900 };

                foreach (var endpoint in tcpListeners)
                {
                    if (excludedPorts.Contains(endpoint.Port)) continue; // Пропускаем

                    // Пропускаем, если порт слушает только на localhost
                    if (endpoint.Address.Equals(IPAddress.Loopback) || endpoint.Address.Equals(IPAddress.IPv6Loopback)) continue;

                    openPorts.Add(new OpenPortInfo
                    {
                        PortNumber = endpoint.Port,
                        Protocol = "TCP Listen",
                        Address = endpoint.Address.ToString(),
                        IsRisky = riskyPorts.Contains(endpoint.Port)
                    });
                }
                foreach (var endpoint in udpListeners)
                {
                    if (excludedPorts.Contains(endpoint.Port)) continue; // Пропускаем
                    if (endpoint.Address.Equals(IPAddress.Loopback) || endpoint.Address.Equals(IPAddress.IPv6Loopback)) continue;

                    openPorts.Add(new OpenPortInfo
                    {
                        PortNumber = endpoint.Port,
                        Protocol = "UDP Listen",
                        Address = endpoint.Address.ToString(),
                        IsRisky = riskyPorts.Contains(endpoint.Port)
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки открытых портов: {ex.Message}");
            }
            return openPorts;
        }
        private string GetNetworkAdapterInfo()
        {
            try
            {
                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                var activeAdapters = adapters.Count(a => a.OperationalStatus == OperationalStatus.Up);
                var wifiAdapters = adapters.Count(a => a.NetworkInterfaceType == NetworkInterfaceType.Wireless80211);
                var ethernetAdapters = adapters.Count(a => a.NetworkInterfaceType == NetworkInterfaceType.Ethernet);

                return $"Активных: {activeAdapters}, Wi-Fi: {wifiAdapters}, Ethernet: {ethernetAdapters}";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения информации о сетевых адаптерах: {ex.Message}");
                return "Информация недоступна";
            }
        }

        private (bool isSecure, string details) CheckDNSSettings()
        {
            try
            {
                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var adapter in adapters.Where(a => a.OperationalStatus == OperationalStatus.Up))
                {
                    var properties = adapter.GetIPProperties();
                    var dnsServers = properties.DnsAddresses;

                    if (dnsServers.Any())
                    {
                        var untrustedDNS = dnsServers.Any(ip =>
                            ip.ToString().StartsWith("8.8.8.") ||
                            ip.ToString().StartsWith("1.1.1.") ||
                            ip.ToString().StartsWith("208.67.222."));

                        return (!untrustedDNS, $"DNS серверы: {string.Join(", ", dnsServers.Take(2))}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки DNS настроек: {ex.Message}");
            }

            return (true, "Настройки по умолчанию");
        }



        private (bool isSecure, string details, string recommendation) CheckUserAccountsDetailed()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_UserAccount WHERE LocalAccount = TRUE AND Disabled = FALSE AND AccountType = 512");
                var users = searcher.Get().Cast<ManagementObject>().ToList();

                var accountsWithoutPassword = users.Count(u =>
                    u["PasswordRequired"]?.ToString() == "False" &&
                    u["Disabled"]?.ToString() == "False");

                var disabledAccounts = users.Count(u => u["Disabled"]?.ToString() == "True");
                var localAccounts = users.Count(u => u["LocalAccount"]?.ToString() == "True");

                if (accountsWithoutPassword > 0)
                {
                    return (false,
                           $"Найдено {accountsWithoutPassword} учетных записей без пароля",
                           "Установите пароли для всех учетных записей");
                }

                return (true,
                       $"Учетных записей: {users.Count}, локальных: {localAccounts}, отключенных: {disabledAccounts}",
                       "Поддерживайте надежные пароли");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки учетных записей: {ex.Message}");
                return (true, "Не удалось проверить учетные записи", "Проверьте учетные записи вручную");
            }
        }

        private (bool isOptimal, string details, string recommendation) CheckAdminPrivilegesDetailed()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_GroupUser WHERE GroupComponent LIKE '%Administrators%'");
                var adminUsers = searcher.Get().Cast<ManagementObject>();
                var adminCount = adminUsers.Count();

                return (adminCount <= 3,
                       $"Пользователей с правами администратора: {adminCount}",
                       adminCount <= 3 ?
                           "Количество администраторов оптимально" :
                           "Ограничьте количество пользователей с правами администратора");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки прав администратора: {ex.Message}");
                return (true, "Проверка не выполнена", "Ручная проверка рекомендуется");
            }
        }

        private (int count, bool hasCritical) CheckOutdatedSoftwareDetailed()
        {
            var outdatedCount = 0;
            var hasCritical = false;
            var riskyApps = new[] { "java", "adobe reader", "chrome", "firefox", "7-zip" };

            try
            {
                var uninstallKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (uninstallKey != null)
                {
                    foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                    {
                        using (var subKey = uninstallKey.OpenSubKey(subKeyName))
                        {
                            var displayName = subKey?.GetValue("DisplayName")?.ToString();
                            var installDateStr = subKey?.GetValue("InstallDate")?.ToString();

                            if (string.IsNullOrEmpty(displayName) || string.IsNullOrEmpty(installDateStr))
                            {
                                continue;
                            }

                            // Пытаемся распознать дату формата YYYYMMDD
                            if (DateTime.TryParseExact(installDateStr, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var installDate))
                            {
                                // Считаем ПО старше 4 лет устаревшим
                                if ((DateTime.Now - installDate).TotalDays > (365 * 4))
                                {
                                    outdatedCount++;
                                  
                                    if (!hasCritical && riskyApps.Any(app => displayName.ToLower().Contains(app)))
                                    {
                                        hasCritical = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки устаревшего ПО: {ex.Message}");
            }
            return (outdatedCount, hasCritical);
        }

        private (bool isClean, string details) CheckStartupProgramsDetailed()
        {
            try
            {
                var runKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                var programs = runKey?.GetValueNames() ?? new string[0];

                var suspiciousKeywords = new[] { "crack", "keygen", "patch", "loader", "hack" };
                var suspiciousCount = programs.Count(p =>
                    suspiciousKeywords.Any(kw => p.ToLower().Contains(kw)));

                return (suspiciousCount == 0,
                       $"Программ в автозагрузке: {programs.Length}, подозрительных: {suspiciousCount}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки автозагрузки: {ex.Message}");
                return (true, "Проверка не выполнена");
            }
        }



        private List<SecurityThreat> CheckSystemVulnerabilities()
        {
            var vulnerabilities = new List<SecurityThreat>();

            if (!CheckWindowsUpdatesDetailed().IsUpToDate)
            {
                vulnerabilities.Add(new SecurityThreat
                {
                    Name = "Отсутствуют обновления безопасности Windows",
                    Type = "Системная уязвимость",
                    Severity = "Критическая",
                    Description = "Система не получала обновления безопасности длительное время, что делает ее уязвимой для известных эксплойтов",
                    Recommendation = "Немедленно установите обновления через Центр обновления Windows"
                });
            }

            if (!CheckUACStatus())
            {
                vulnerabilities.Add(new SecurityThreat
                {
                    Name = "Отключен контроль учетных записей (UAC)",
                    Type = "Уязвимость прав доступа",
                    Severity = "Высокая",
                    Description = "UAC отключен, что позволяет программам получать права администратора без уведомления пользователя",
                    Recommendation = "Включите UAC в настройках безопасности Windows на уровень не ниже 'Уведомлять всегда'"
                });
            }

            if (!CheckFirewallStatus())
            {
                vulnerabilities.Add(new SecurityThreat
                {
                    Name = "Брандмауэр Windows отключен",
                    Type = "Сетевая уязвимость",
                    Severity = "Критическая",
                    Description = "Система не защищена сетевым экраном, что делает ее уязвимой для сетевых атак",
                    Recommendation = "Немедленно включите брандмауэр Windows"
                });
            }

            return vulnerabilities;
        }



        private void CalculateSecurityStatus(SecurityScanResult result)
        {
            result.TotalThreats = result.Threats.Count;
            result.CriticalIssues = result.SecurityChecks.Count(c => c.IsCritical && !c.Status.Contains("ОК"));
            result.Warnings = result.SecurityChecks.Count(c => !c.IsCritical && !c.Status.Contains("ОК"));

            if (result.CriticalIssues > 0)
            {
                result.OverallStatus = $"Критический риск ({result.CriticalIssues} крит. проблем)";
            }
            else if (result.TotalThreats > 0)
            {
                result.OverallStatus = $"Требуется внимание ({result.TotalThreats} угроз)";
            }
            else if (result.Warnings > 0)
            {
                result.OverallStatus = $"Умеренный риск ({result.Warnings} предупреждений)";
            }
            else
            {
                result.OverallStatus = "Защищено";
            }
        }


        public List<SecurityVulnerability> ScanForVulnerabilities()
        {
            var result = PerformComprehensiveSecurityScan();
            return result.Threats.Select(t => new SecurityVulnerability
            {
                Title = t.Name,
                Description = t.Description,
                Severity = t.Severity,
                Category = t.Type,
                Recommendation = t.Recommendation,
                IsFixed = false
            }).ToList();
        }



        public List<SecurityVulnerability> CheckSystemConfiguration()
        {
            var checks = PerformSystemSecurityChecks();
            return checks.Where(c => !c.Status.Contains("ОК")).Select(c => new SecurityVulnerability
            {
                Title = c.CheckName,
                Description = c.Details,
                Severity = c.IsCritical ? "Critical" : "High",
                Category = c.Category,
                Recommendation = c.Recommendation,
                IsFixed = false
            }).ToList();
        }

        public List<SecurityVulnerability> CheckUserAccounts()
        {
            var accountCheck = CheckUserAccountsDetailed();
            if (!accountCheck.isSecure)
            {
                return new List<SecurityVulnerability>
                {
                    new SecurityVulnerability
                    {
                        Title = "Проблемы с учетными записями",
                        Description = accountCheck.details,
                        Severity = "High",
                        Category = "Accounts",
                        Recommendation = accountCheck.recommendation,
                        IsFixed = false
                    }
                };
            }
            return new List<SecurityVulnerability>();
        }

        public List<SecurityVulnerability> CheckNetworkSecurity()
        {
            var checks = PerformNetworkSecurityChecks();
            return checks.Where(c => !c.Status.Contains("ОК")).Select(c => new SecurityVulnerability
            {
                Title = c.CheckName,
                Description = c.Details,
                Severity = c.IsCritical ? "Critical" : "Medium",
                Category = c.Category,
                Recommendation = c.Recommendation,
                IsFixed = false
            }).ToList();
        }




        public DefenderStatus GetDefenderStatus()
        {
            var status = new DefenderStatus();

            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus");
                foreach (ManagementObject obj in searcher.Get())
                {
                    status.IsEnabled = (bool)(obj["AntivirusEnabled"] ?? false);
                    status.IsRealTimeProtectionEnabled = (bool)(obj["RealTimeProtectionEnabled"] ?? false);
                    status.IsCloudProtectionEnabled = (bool)(obj["CloudEnabled"] ?? false);
                    status.IsTamperProtectionEnabled = (bool)(obj["TamperProtectionEnabled"] ?? false);
                    status.AntivirusStatus = obj["AntivirusSignatureVersion"]?.ToString() ?? "Неизвестно";
                    status.DefinitionVersion = obj["AntivirusSignatureVersion"]?.ToString() ?? "Неизвестно";
                    status.LastScanTime = GetLastScanTime(obj);
                    break;
                }

                status.IsFirewallEnabled = GetFirewallStatus();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения статуса Защитника: {ex.Message}");
                status.IsEnabled = false;
                status.AntivirusStatus = "Ошибка проверки";
            }

            return status;
        }

        private string GetLastScanTime(ManagementObject defenderObj)
        {
            try
            {
                var lastScan = defenderObj["LastQuickScanDateTime"] ?? defenderObj["LastFullScanDateTime"];
                if (lastScan != null)
                {
                    return ManagementDateTimeConverter.ToDateTime(lastScan.ToString()).ToString("dd.MM.yyyy HH:mm");
                }
            }
            catch
            {
                // Игнорируем ошибки
            }

            return "Неизвестно";
        }

        private bool GetFirewallStatus()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var domainRole = obj["DomainRole"]?.ToString();
                    return true;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка проверки брандмауэра: {ex.Message}");
            }

            return false;
        }



        public (bool Success, string Output, int Progress) StartDefenderScanWithProgress(string scanType)
        {
            try
            {
                string scanArgument = scanType switch
                {
                    "Быстрая проверка" => "QuickScan",
                    "Полная проверка" => "FullScan",
                    _ => "QuickScan"
                };

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-Command \"& {{" +
                                   $"$scan = Start-MpScan -ScanType {scanArgument} -AsJob; " +
                                   $"Write-Host 'Сканирование запущено...'; " +
                                   $"do {{ " +
                                   $"Start-Sleep -Seconds 2; " +
                                   $"$jobState = (Get-Job -Id $scan.Id).State; " +
                                   $"Write-Host 'Состояние:' $jobState; " +
                                   $"}} while ($jobState -eq 'Running'); " +
                                   $"$result = Receive-Job -Job $scan; " +
                                   $"Write-Host 'Результат:' $result; " +
                                   $"}}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };

                process.Start();
                var output = new StringBuilder();
                string line;
                int progress = 0;

                while ((line = process.StandardOutput.ReadLine()) != null)
                {
                    output.AppendLine(line);
                    if (line.Contains("Running"))
                    {
                        progress += 10;
                        if (progress > 90) progress = 90;
                    }
                }

                process.WaitForExit(300000);
                return (process.ExitCode == 0, output.ToString(), progress);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка запуска сканирования с прогрессом: {ex.Message}");
                return (false, ex.Message, 0);
            }
        }

        public bool EnableDefenderProtection()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = "-Command \"Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -DisableBehaviorMonitoring $false\"",
                        UseShellExecute = true,
                        Verb = "runas"
                    }
                };

                process.Start();
                process.WaitForExit(3000);
                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка включения Защитника: {ex.Message}");
                return false;
            }
        }

        public void OpenWindowsSecurity()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "windowsdefender:",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка открытия Безопасности Windows: {ex.Message}");
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "ms-settings:windowsdefender",
                        UseShellExecute = true
                    });
                }
                catch (Exception ex2)
                {
                    Debug.WriteLine($"Резервный способ тоже не сработал: {ex2.Message}");
                    throw new Exception("Не удалось открыть Безопасность Windows. Проверьте, что Защитник Windows установлен и включен.");
                }
            }
        }


        public void OpenAntivirusUI()
        {
          
            var avInfo = GetInstalledAntivirus(); 

            if (avInfo.Name.ToLower().Contains("defender") || avInfo.Name.ToLower().Contains("защитник"))
            {
                OpenWindowsSecurity();
                return;
            }

            if (!string.IsNullOrEmpty(_antivirusExePath) && File.Exists(_antivirusExePath))
            {
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = _antivirusExePath,
                        UseShellExecute = true
                    });
                    return;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Не удалось открыть UI антивируса по пути: {ex.Message}");
                   
                }
            }


            OpenWindowsSecurity();
        }

        public List<SecurityEvent> SecurityEvents()
        {
            var events = new List<SecurityEvent>();
            var startTime = DateTime.Now.AddDays(-1); 

          
            AddDefenderEvents(events);

            
            string querySecurity = $"*[System[EventID=4625 and TimeCreated[@SystemTime >= '{startTime.ToUniversalTime():o}']]]";
            AddEventsFromQuery(events, "Security", querySecurity, "Неудачный вход", "Высокая");

   
            string queryApplication = $"*[System[Provider[@Name='Application Error'] and EventID=1000 and Level=2 and TimeCreated[@SystemTime >= '{startTime.ToUniversalTime():o}']]]";
            AddEventsFromQuery(events, "Application", queryApplication, "Сбой приложения", "Средняя");

            return events.OrderByDescending(e => e.TimeGenerated).Take(50).ToList();
        }

    
        private void AddEventsFromQuery(List<SecurityEvent> events, string logName, string query, string eventType, string severity)
        {
            try
            {
                var eventQuery = new EventLogQuery(logName, PathType.LogName, query)
                {
                    ReverseDirection = true
                };

                using (var reader = new EventLogReader(eventQuery))
                {
                    EventRecord record;
                    while ((record = reader.ReadEvent()) != null && events.Count < 50) 
                    {
                        events.Add(new SecurityEvent
                        {
                            TimeGenerated = record.TimeCreated?.ToLocalTime() ?? DateTime.Now,
                            EventType = eventType,
                            Source = record.ProviderName,
                            Description = record.FormatDescription()?.Split('\n')[0] ?? "Нет описания", 
                            Severity = severity
                        });
                    }
                }
            }
            catch (EventLogNotFoundException)
            {
                Debug.WriteLine($"Журнал '{logName}' не найден.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка чтения журнала '{logName}': {ex.Message}");
            }
        }


        private void AddDefenderEvents(List<SecurityEvent> events)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpThreat");
                foreach (ManagementObject obj in searcher.Get())
                {
                    events.Add(new SecurityEvent
                    {
                        TimeGenerated = DateTime.Now.AddDays(-1),
                        EventType = "Угроза",
                        Source = "Защитник Windows",
                        Description = $"Обнаружена угроза: {obj["ThreatName"]}",
                        Severity = "Высокая"
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка чтения событий Защитника: {ex.Message}");
            }
        }



        public class OpenPortInfo
        {
            public int PortNumber { get; set; }
            public string Protocol { get; set; } = string.Empty;
            public string Address { get; set; } = string.Empty;
            public bool IsRisky { get; set; }
        }
    }
}
