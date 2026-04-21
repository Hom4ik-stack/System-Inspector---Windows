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
using System.Text;

namespace SecurityShield.Services
{
    public class SecurityService : ISecurityService
    {
        private string _antivirusExePath = string.Empty;

        public SecurityScanResult PerformComprehensiveSecurityScan()
        {
            var result = new SecurityScanResult { ScanTime = DateTime.Now };
            try
            {
                result.SecurityChecks.AddRange(SystemChecks());
                result.SecurityChecks.AddRange(NetworkChecks());
                result.SecurityChecks.AddRange(ServiceChecks());
                result.SecurityChecks.AddRange(AppChecks());
                result.SecurityChecks.AddRange(AccountChecks());
                result.SecurityChecks.AddRange(FileSystemChecks());

                result.Threats.AddRange(BuildThreatsFromChecks(result.SecurityChecks));
                result.Threats = result.Threats.GroupBy(t => t.Name).Select(g => g.First()).ToList();
                CalcStatus(result);
            }
            catch (Exception ex) { Debug.WriteLine(ex.Message); }
            return result;
        }

        public DefenderStatus GetDefenderStatus()
        {
            var status = new DefenderStatus();
            try
            {
                using var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus");
                foreach (ManagementObject o in s.Get())
                {
                    status.RealTimeProtection = (bool)(o["RealTimeProtectionEnabled"] ?? false);
                    status.CloudProtection = (bool)(o["CloudEnabled"] ?? false);
                    status.TamperProtection = (bool)(o["TamperProtectionEnabled"] ?? false);
                    status.SignatureVersion = o["AntivirusSignatureVersion"]?.ToString() ?? "Неизвестно";
                    try
                    {
                        var scan = o["LastQuickScanDateTime"] ?? o["LastFullScanDateTime"];
                        if (scan?.ToString() is string scanStr)
                            status.LastScanTime = ManagementDateTimeConverter.ToDateTime(scanStr).ToString("dd.MM.yyyy HH:mm");
                    }
                    catch { }
                    break;
                }
                status.FirewallEnabled = IsFirewallEnabled();
            }
            catch (Exception ex) { Debug.WriteLine($"Defender: {ex.Message}"); }
            return status;
        }

        public AntivirusInfo GetInstalledAntivirus()
        {
            var av = new AntivirusInfo();
            try
            {
                av = GetAvFromWMI();
                if (av.Name == "Не обнаружен") av = GetAvFromProcesses();
                if (av.Name != "Не обнаружен") EnhanceAv(av);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                av.Name = "Ошибка определения";
            }
            return av;
        }

        public bool EnableDefenderProtection()
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -Command \"Set-MpPreference -DisableRealtimeMonitoring $false\"",
                    UseShellExecute = true,
                    Verb = "runas"
                });
                p?.WaitForExit(10000);
                return p?.ExitCode == 0;
            }
            catch { return false; }
        }

        public void OpenWindowsSecurity()
        {
            try { Process.Start(new ProcessStartInfo { FileName = "windowsdefender:", UseShellExecute = true }); }
            catch
            {
                try { Process.Start(new ProcessStartInfo { FileName = "ms-settings:windowsdefender", UseShellExecute = true }); }
                catch (Exception ex) { throw new Exception($"Не удалось открыть: {ex.Message}"); }
            }
        }

        public void OpenAntivirusUI()
        {
            var av = GetInstalledAntivirus();
            if (av.Name.ToLower().Contains("defender") || av.Name.ToLower().Contains("защитник"))
            { OpenWindowsSecurity(); return; }
            if (!string.IsNullOrEmpty(_antivirusExePath) && File.Exists(_antivirusExePath))
            { try { Process.Start(new ProcessStartInfo { FileName = _antivirusExePath, UseShellExecute = true }); return; } catch { } }
            OpenWindowsSecurity();
        }

        private List<SecurityCheck> SystemChecks()
        {
            var list = new List<SecurityCheck>();

            var upd = CheckUpdates();
            list.Add(new SecurityCheck
            {
                CheckName = "Обновления Windows",
                Category = "Система",
                Status = upd.ok ? "OK" : "КРИТИЧЕСКИЙ РИСК",
                Details = upd.ok ? $"Последнее обновление: {upd.info}" : $"Дней без обновлений: {upd.days}",
                Recommendation = upd.ok ? "" : "Установите обновления Windows Update",
                IsCritical = !upd.ok
            });

            var uac = CheckUAC();
            list.Add(new SecurityCheck
            {
                CheckName = "UAC",
                Category = "Безопасность",
                Status = uac.on ? "OK" : "КРИТИЧЕСКИЙ РИСК",
                Details = uac.on ? $"Уровень: {uac.level}" : "UAC отключён",
                Recommendation = uac.on ? "" : "Включите UAC через Панель управления",
                IsCritical = !uac.on
            });

            bool fw = IsFirewallEnabled();
            list.Add(new SecurityCheck
            {
                CheckName = "Брандмауэр",
                Category = "Сеть",
                Status = fw ? "OK" : "КРИТИЧЕСКИЙ РИСК",
                Details = fw ? "Активен" : "Отключён",
                Recommendation = fw ? "" : "Включите брандмауэр Windows",
                IsCritical = !fw
            });

            bool dep = CheckDEP();
            list.Add(new SecurityCheck
            {
                CheckName = "DEP",
                Category = "Память",
                Status = dep ? "OK" : "РИСК",
                Details = dep ? "Включён" : "Отключён",
                Recommendation = dep ? "" : "Включите DEP для всех программ",
                IsCritical = !dep
            });

            bool rdp = IsRDPEnabled();
            list.Add(new SecurityCheck
            {
                CheckName = "RDP",
                Category = "Сеть",
                Status = rdp ? "ВНИМАНИЕ" : "OK",
                Details = rdp ? "Удалённый рабочий стол включён" : "RDP отключён",
                Recommendation = rdp ? "Отключите RDP если не используется" : ""
            });

            list.Add(CheckSMB1());
            list.Add(CheckAutoRun());
            list.Add(CheckPowerShellPolicy());
            list.Add(CheckHostsFile());

            return list;
        }

        private List<SecurityCheck> NetworkChecks()
        {
            var list = new List<SecurityCheck>();
            var riskyOpen = FindExternalRiskyPorts();
            if (riskyOpen.Any())
            {
                list.Add(new SecurityCheck
                {
                    CheckName = "Опасные открытые порты",
                    Category = "Сеть",
                    Status = "ВНИМАНИЕ",
                    Details = $"Слушают на 0.0.0.0: {string.Join(", ", riskyOpen.Select(p => $"{p.port} ({p.name})"))}",
                    Recommendation = "Заблокируйте неиспользуемые порты в брандмауэре",
                    IsCritical = riskyOpen.Any(p => p.port == 445 || p.port == 23 || p.port == 135)
                });
            }
            else
            {
                list.Add(new SecurityCheck
                {
                    CheckName = "Открытые порты",
                    Category = "Сеть",
                    Status = "OK",
                    Details = "Опасных портов, слушающих на всех интерфейсах, нет"
                });
            }

            list.Add(new SecurityCheck
            {
                CheckName = "DNS серверы",
                Category = "Сеть",
                Status = "OK",
                Details = GetDnsInfo()
            });

            return list;
        }

        private List<SecurityCheck> ServiceChecks()
        {
            var list = new List<SecurityCheck>();
            list.Add(CheckService("RemoteRegistry", "Удалённый реестр",
                "Позволяет удалённо изменять реестр Windows",
                "Остановите и отключите службу RemoteRegistry"));
            list.Add(CheckService("WinRM", "WinRM",
                "Позволяет удалённо управлять системой через PowerShell",
                "Остановите WinRM если удалённое управление не требуется"));
            list.Add(CheckService("TlntSvr", "Telnet Server",
                "Нешифрованный удалённый доступ",
                "Удалите компонент Telnet Server"));
            list.Add(CheckService("SSDPSRV", "SSDP Discovery",
                "UPnP обнаружение устройств — потенциальный вектор атаки",
                "Отключите если UPnP не используется"));
            return list;
        }

        private SecurityCheck CheckService(string serviceName, string displayName, string riskDescription, string recommendation)
        {
            bool isRunning = false;
            string startType = "Неизвестно";
            try
            {
                using var sc = new System.ServiceProcess.ServiceController(serviceName);
                isRunning = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                using var s = new ManagementObjectSearcher($"SELECT StartMode FROM Win32_Service WHERE Name='{serviceName}'");
                foreach (ManagementObject o in s.Get())
                    startType = o["StartMode"]?.ToString() ?? "Неизвестно";
            }
            catch (InvalidOperationException)
            {
                return new SecurityCheck
                {
                    CheckName = displayName,
                    Category = "Службы",
                    Status = "OK",
                    Details = "Служба не установлена"
                };
            }
            catch { }

            bool isRisk = isRunning || startType == "Auto";
            return new SecurityCheck
            {
                CheckName = displayName,
                Category = "Службы",
                Status = isRisk ? "ВНИМАНИЕ" : "OK",
                Details = isRisk ? $"Состояние: {(isRunning ? "Запущена" : "Остановлена")}, Автозапуск: {startType}. {riskDescription}" : $"Остановлена, запуск: {startType}",
                Recommendation = isRisk ? recommendation : ""
            };
        }

        private List<SecurityCheck> AppChecks()
        {
            var list = new List<SecurityCheck>();
            var av = GetInstalledAntivirus();
            list.Add(new SecurityCheck
            {
                CheckName = "Антивирус",
                Category = "Приложения",
                Status = av.IsEnabled ? "OK" : "КРИТИЧЕСКИЙ РИСК",
                Details = $"{av.Name} ({av.Vendor}) — {av.Status}. Защита: {av.RealTimeProtection}",
                Recommendation = av.IsEnabled ? "" : "Установите и активируйте антивирус",
                IsCritical = !av.IsEnabled
            });

            var def = GetDefenderStatus();
            string defDetails = $"Real-time: {(def.RealTimeProtection ? "Вкл" : "Выкл")}, " +
                                $"Cloud: {(def.CloudProtection ? "Вкл" : "Выкл")}, " +
                                $"Tamper: {(def.TamperProtection ? "Вкл" : "Выкл")}, " +
                                $"Сигнатуры: {def.SignatureVersion}";
            if (def.LastScanTime != "Неизвестно")
                defDetails += $", Последнее сканирование: {def.LastScanTime}";

            list.Add(new SecurityCheck
            {
                CheckName = "Защитник Windows",
                Category = "Приложения",
                Status = def.RealTimeProtection ? "OK" : "ВНИМАНИЕ",
                Details = defDetails,
                Recommendation = def.RealTimeProtection ? "" : "Включите защиту в реальном времени"
            });

            return list;
        }

        private List<SecurityCheck> AccountChecks()
        {
            var list = new List<SecurityCheck>();
            try
            {
                bool guestEnabled = false;
                string guestName = "";
                int totalActive = 0;
                int adminCount = 0;

                using (var s = new ManagementObjectSearcher("SELECT Name, Disabled FROM Win32_UserAccount WHERE LocalAccount=TRUE"))
                {
                    foreach (ManagementObject o in s.Get())
                    {
                        string name = o["Name"]?.ToString() ?? "";
                        bool disabled = (bool)(o["Disabled"] ?? false);
                        if (!disabled) totalActive++;
                        if (!disabled && (name.Equals("Guest", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("Гость", StringComparison.OrdinalIgnoreCase)))
                        {
                            guestEnabled = true;
                            guestName = name;
                        }
                    }
                }

                try
                {
                    using var s = new ManagementObjectSearcher(
                        "SELECT * FROM Win32_GroupUser WHERE GroupComponent LIKE '%Administrators%' OR GroupComponent LIKE '%Администраторы%'");
                    adminCount = s.Get().Count;
                }
                catch { }

                if (guestEnabled)
                {
                    list.Add(new SecurityCheck
                    {
                        CheckName = "Гостевая учётная запись",
                        Category = "Пользователи",
                        Status = "РИСК",
                        Details = $"Учётная запись '{guestName}' активна — любой может войти без пароля",
                        Recommendation = "Отключите гостевую учётную запись: net user Guest /active:no",
                        IsCritical = true
                    });
                }
                else
                {
                    list.Add(new SecurityCheck
                    {
                        CheckName = "Гостевая учётная запись",
                        Category = "Пользователи",
                        Status = "OK",
                        Details = "Гостевая учётная запись отключена"
                    });
                }

                bool tooManyAdmins = adminCount > 3;
                list.Add(new SecurityCheck
                {
                    CheckName = "Администраторы",
                    Category = "Пользователи",
                    Status = tooManyAdmins ? "ВНИМАНИЕ" : "OK",
                    Details = $"Пользователей с правами администратора: {adminCount}",
                    Recommendation = tooManyAdmins ? "Сократите число администраторов до минимума" : ""
                });

                list.Add(new SecurityCheck
                {
                    CheckName = "Локальные пользователи",
                    Category = "Пользователи",
                    Status = "OK",
                    Details = $"Активных локальных учётных записей: {totalActive}"
                });
            }
            catch
            {
                list.Add(new SecurityCheck
                {
                    CheckName = "Учётные записи",
                    Category = "Пользователи",
                    Status = "OK",
                    Details = "Требуются права администратора для полной проверки"
                });
            }
            return list;
        }

        private List<SecurityCheck> FileSystemChecks()
        {
            var list = new List<SecurityCheck>();
            list.Add(CheckHostsFile());
            return list;
        }

        private List<SecurityThreat> BuildThreatsFromChecks(List<SecurityCheck> checks)
        {
            var threats = new List<SecurityThreat>();
            foreach (var c in checks)
            {
                if (c.Status.Contains("OK")) continue;

                string severity;
                if (c.Status.Contains("КРИТИЧЕСКИЙ")) severity = "Критическая";
                else if (c.IsCritical) severity = "Высокая";
                else if (c.Status.Contains("ВНИМАНИЕ")) severity = "Средняя";
                else if (c.Status.Contains("РИСК")) severity = "Средняя";
                else continue;

                if (severity == "Низкая") continue;

                threats.Add(new SecurityThreat
                {
                    Name = c.CheckName,
                    Type = c.Category,
                    Severity = severity,
                    Description = c.Details,
                    Recommendation = c.Recommendation
                });
            }
            return threats;
        }

        private List<(int port, string name)> FindExternalRiskyPorts()
        {
            var result = new List<(int port, string name)>();
            var riskyDef = new Dictionary<int, string>
            {
                {21,"FTP"},{23,"Telnet"},{135,"RPC"},{139,"NetBIOS"},
                {445,"SMB"},{1433,"MSSQL"},{3306,"MySQL"},{3389,"RDP"},
                {5432,"PostgreSQL"},{5900,"VNC"},{5985,"WinRM"}
            };

            try
            {
                var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
                foreach (var ep in listeners)
                {
                    if (!riskyDef.ContainsKey(ep.Port)) continue;
                    if (ep.Address.Equals(IPAddress.Any) || ep.Address.Equals(IPAddress.IPv6Any))
                        result.Add((ep.Port, riskyDef[ep.Port]));
                }
            }
            catch { }
            return result.DistinctBy(x => x.port).ToList();
        }

        private (bool ok, int days, string info) CheckUpdates()
        {
            try
            {
                DateTime? last = null;
                using var s = new ManagementObjectSearcher("SELECT InstalledOn FROM Win32_QuickFixEngineering");
                foreach (ManagementObject obj in s.Get())
                {
                    try
                    {
                        var str = obj["InstalledOn"]?.ToString();
                        if (DateTime.TryParse(str, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                            if (last == null || dt > last) last = dt;
                    }
                    catch { }
                }

                if (last.HasValue)
                {
                    int days = (int)(DateTime.Now - last.Value).TotalDays;
                    return (days <= 60, days, last.Value.ToString("dd.MM.yyyy"));
                }
            }
            catch { }
            return (false, 999, "Неизвестно");
        }

        private (bool on, string level) CheckUAC()
        {
            try
            {
                var lua = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "0");
                var consent = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", "0");

                if (lua?.ToString() == "1")
                {
                    string level = consent?.ToString() switch
                    {
                        "0" => "Никогда не уведомлять (небезопасно)",
                        "1" => "Без затемнения рабочего стола",
                        "2" => "Всегда уведомлять",
                        "3" => "Требовать учётные данные",
                        "5" => "При попытках изменений (рекомендуемый)",
                        _ => $"Уровень {consent}"
                    };
                    bool isWeak = consent?.ToString() == "0";
                    return (!isWeak, level);
                }
            }
            catch { }
            return (false, "Отключён");
        }

        private bool IsFirewallEnabled()
        {
            try
            {
                int enabledCount = 0;
                foreach (var p in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
                {
                    using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{p}");
                    var v = k?.GetValue("EnableFirewall");
                    if (v != null && (int)v == 1) enabledCount++;
                }
                return enabledCount >= 2;
            }
            catch { }
            return false;
        }

        private bool CheckDEP()
        {
            try
            {
                using var s = new ManagementObjectSearcher("SELECT DataExecutionPrevention_SupportPolicy FROM Win32_OperatingSystem");
                foreach (ManagementObject o in s.Get())
                { var v = o["DataExecutionPrevention_SupportPolicy"]?.ToString(); return v == "2" || v == "3"; }
            }
            catch { }
            return false;
        }

        private bool IsRDPEnabled()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
                var v = k?.GetValue("fDenyTSConnections");
                return v != null && (int)v == 0;
            }
            catch { return false; }
        }

        private SecurityCheck CheckSMB1()
        {
            bool enabled = false;
            string method = "";
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
                if (k != null)
                {
                    var v = k.GetValue("SMB1");
                    enabled = v == null || (int)v != 0;
                    method = v == null ? "Ключ SMB1 не задан (включён по умолчанию)" : $"SMB1={v}";
                }
                else
                {
                    method = "Ключ реестра отсутствует";
                }
            }
            catch { method = "Ошибка проверки"; }

            return new SecurityCheck
            {
                CheckName = "SMBv1",
                Category = "Сеть",
                Status = enabled ? "КРИТИЧЕСКИЙ РИСК" : "OK",
                Details = enabled ? $"SMBv1 включён ({method}). Уязвимость EternalBlue/WannaCry" : "SMBv1 отключён",
                Recommendation = enabled ? "Отключите: Set-SmbServerConfiguration -EnableSMB1Protocol $false" : "",
                IsCritical = enabled
            };
        }

        private SecurityCheck CheckAutoRun()
        {
            int? cuValue = null;
            int? lmValue = null;
            try
            {
                using var ck = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
                var cv = ck?.GetValue("NoDriveTypeAutoRun");
                if (cv != null) cuValue = (int)cv;
            }
            catch { }
            try
            {
                using var lk = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
                var lv = lk?.GetValue("NoDriveTypeAutoRun");
                if (lv != null) lmValue = (int)lv;
            }
            catch { }

            bool disabled = (cuValue.HasValue && cuValue.Value >= 0xFF) || (lmValue.HasValue && lmValue.Value >= 0xFF);
            return new SecurityCheck
            {
                CheckName = "Автозапуск USB",
                Category = "Система",
                Status = disabled ? "OK" : "РИСК",
                Details = disabled ? "Автозапуск отключён политикой" : "Автозапуск съёмных носителей разрешён",
                Recommendation = disabled ? "" : "Отключите: reg add HKLM\\...\\Policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255"
            };
        }

        private SecurityCheck CheckPowerShellPolicy()
        {
            string pol = "Unknown";
            try
            {
                var p = Process.Start(new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -Command \"Get-ExecutionPolicy -Scope LocalMachine\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                });
                if (p != null) { pol = p.StandardOutput.ReadToEnd().Trim(); p.WaitForExit(5000); }
            }
            catch { }

            bool risk = pol == "Unrestricted" || pol == "Bypass";
            return new SecurityCheck
            {
                CheckName = "PowerShell ExecutionPolicy",
                Category = "Система",
                Status = risk ? "РИСК" : "OK",
                Details = $"Политика LocalMachine: {pol}" + (risk ? " — любые скрипты могут выполняться" : ""),
                Recommendation = risk ? "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine" : ""
            };
        }

        private SecurityCheck CheckHostsFile()
        {
            try
            {
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                if (!File.Exists(path))
                    return new SecurityCheck { CheckName = "Файл hosts", Category = "Система", Status = "OK", Details = "Файл не найден" };

                var blocked = new[] { "microsoft.com", "windowsupdate.com", "kaspersky.com", "eset.com", "avast.com", "bitdefender.com", "malwarebytes.com" };
                var suspicious = new List<string>();

                foreach (var line in File.ReadAllLines(path))
                {
                    var t = line.Trim();
                    if (string.IsNullOrEmpty(t) || t.StartsWith("#")) continue;
                    var parts = t.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;

                    string ip = parts[0];
                    string host = parts[1].ToLower();

                    if (ip == "127.0.0.1" && host == "localhost") continue;
                    if (ip == "::1" && host == "localhost") continue;

                    if (blocked.Any(d => host.Contains(d)))
                        suspicious.Add($"{ip} → {host}");
                }

                if (suspicious.Any())
                {
                    return new SecurityCheck
                    {
                        CheckName = "Файл hosts",
                        Category = "Система",
                        Status = "КРИТИЧЕСКИЙ РИСК",
                        Details = $"Заблокированы критические домены: {string.Join("; ", suspicious.Take(5))}",
                        Recommendation = "Проверьте C:\\Windows\\System32\\drivers\\etc\\hosts на вредоносные записи",
                        IsCritical = true
                    };
                }

                return new SecurityCheck { CheckName = "Файл hosts", Category = "Система", Status = "OK", Details = "Подозрительных записей нет" };
            }
            catch
            {
                return new SecurityCheck { CheckName = "Файл hosts", Category = "Система", Status = "OK", Details = "Нет доступа для проверки" };
            }
        }

        private string GetDnsInfo()
        {
            try
            {
                foreach (var a in NetworkInterface.GetAllNetworkInterfaces().Where(a => a.OperationalStatus == OperationalStatus.Up))
                {
                    var dns = a.GetIPProperties().DnsAddresses;
                    if (dns.Any()) return $"{string.Join(", ", dns.Take(4))}";
                }
            }
            catch { }
            return "По умолчанию";
        }

        private void CalcStatus(SecurityScanResult r)
        {
            r.TotalThreats = r.Threats.Count;
            r.CriticalIssues = r.Threats.Count(t => t.Severity == "Критическая");
            r.Warnings = r.Threats.Count(t => t.Severity == "Средняя" || t.Severity == "Высокая");

            if (r.CriticalIssues > 0)
                r.OverallStatus = $"Критический риск ({r.CriticalIssues} критических)";
            else if (r.TotalThreats > 0)
                r.OverallStatus = $"Требуется внимание ({r.TotalThreats} проблем)";
            else
                r.OverallStatus = "Защищено";
        }

        private AntivirusInfo GetAvFromWMI()
        {
            var av = new AntivirusInfo();
            try
            {
                using var s = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                foreach (ManagementObject p in s.Get())
                {
                    var name = p["displayName"]?.ToString() ?? "Неизвестно";
                    var state = p["productState"]?.ToString() ?? "0";

                    if (uint.TryParse(state, out uint st))
                    {
                        var bytes = BitConverter.GetBytes(st);
                        av.Name = name;
                        av.IsEnabled = (bytes[1] & 0x10) != 0;
                        av.Status = av.IsEnabled ? "Активен" : "Неактивен";
                        av.Vendor = GetVendor(name);
                        av.RealTimeProtection = av.IsEnabled ? "Включена" : "Выключена";
                        av.IsUpToDate = (bytes[0] & 0x10) == 0;
                        _antivirusExePath = p["pathToSignedProductExe"]?.ToString() ?? "";
                        if (av.IsEnabled) break;
                    }
                }
            }
            catch { }
            return av;
        }

        private AntivirusInfo GetAvFromProcesses()
        {
            var mapping = new Dictionary<string, (string n, string v)>
            {
                {"avp",("Kaspersky","Kaspersky Lab")},{"msmpeng",("Защитник Windows","Microsoft")},
                {"avast",("Avast","Avast")},{"bdagent",("Bitdefender","Bitdefender")},
                {"ekrn",("ESET","ESET")},{"avguard",("Avira","Avira")},
                {"dwservice",("Dr.Web","Dr.Web")},{"mbam",("Malwarebytes","Malwarebytes")}
            };

            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var pn = p.ProcessName.ToLower();
                    foreach (var kv in mapping)
                        if (pn.Contains(kv.Key))
                            return new AntivirusInfo { Name = kv.Value.n, Vendor = kv.Value.v, Status = "Активен", IsEnabled = true, RealTimeProtection = "Включена" };
                }
                catch { }
            }
            return new AntivirusInfo();
        }

        private void EnhanceAv(AntivirusInfo av)
        {
            try
            {
                var mapping = new Dictionary<string, string[]>
                {
                    {"kaspersky",new[]{"avp"}},{"avast",new[]{"avast","avastsvc"}},{"eset",new[]{"ekrn"}},
                    {"defender",new[]{"msmpeng"}},{"защитник",new[]{"msmpeng"}},
                    {"bitdefender",new[]{"bdagent","vsserv"}},{"avira",new[]{"avguard"}},{"dr.web",new[]{"dwservice"}}
                };

                var ln = av.Name.ToLower();
                var procs = Process.GetProcesses();
                foreach (var kv in mapping)
                    if (ln.Contains(kv.Key))
                    { av.IsEnabled = kv.Value.Any(pn => procs.Any(p => p.ProcessName.Equals(pn, StringComparison.OrdinalIgnoreCase))); break; }

                av.Status = av.IsEnabled ? "Активен" : "Неактивен";
                av.RealTimeProtection = av.IsEnabled ? "Включена" : "Выключена";
            }
            catch { }
        }

        private string GetVendor(string name)
        {
            var n = name.ToLower();
            if (n.Contains("kaspersky")) return "Kaspersky Lab";
            if (n.Contains("eset") || n.Contains("nod32")) return "ESET";
            if (n.Contains("avast")) return "Avast";
            if (n.Contains("bitdefender")) return "Bitdefender";
            if (n.Contains("mcafee")) return "McAfee";
            if (n.Contains("norton")) return "NortonLifeLock";
            if (n.Contains("defender")) return "Microsoft";
            if (n.Contains("avira")) return "Avira";
            if (n.Contains("dr.web") || n.Contains("drweb")) return "Dr.Web";
            if (n.Contains("malwarebytes")) return "Malwarebytes";
            return "Неизвестный";
        }
    }
}