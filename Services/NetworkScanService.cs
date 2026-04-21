using SecurityShield.Helpers;
using SecurityShield.Models;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SecurityShield.Services
{
    public class NetworkScanService : INetworkScanService
    {
        private const uint HKLM = 0x80000002;
        private const int MaxConcurrentPings = 30;
        private const int PingTimeoutMs = 1500;
        private const int MaxIpRange = 1024;
        private const int WmiTimeoutSeconds = 15;

        public async Task<List<NetworkHost>> DiscoverHostsAsync(
            string startIp, string endIp, CancellationToken ct = default)
        {
            if (!SecurityHelper.IsValidIpRange(startIp, endIp))
                return new List<NetworkHost>();

            var ips = GenerateIpRange(startIp, endIp);
            if (!ips.Any())
                return new List<NetworkHost>();

            var semaphore = new SemaphoreSlim(MaxConcurrentPings);
            var tasks = ips.Select(async ip =>
            {
                await semaphore.WaitAsync(ct);
                try
                {
                    ct.ThrowIfCancellationRequested();
                    var host = new NetworkHost { IpAddress = ip };
                    try
                    {
                        using var ping = new Ping();
                        var reply = await ping.SendPingAsync(ip, PingTimeoutMs);
                        host.IsOnline = reply.Status == IPStatus.Success;
                        host.Status = host.IsOnline ? "Онлайн" : "Офлайн";
                        if (host.IsOnline)
                        {
                            try
                            {
                                var entry = await Dns.GetHostEntryAsync(ip);
                                host.HostName = entry.HostName;
                            }
                            catch { host.HostName = ip; }
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { host.Status = "Ошибка пинга"; }
                    return host;
                }
                finally { semaphore.Release(); }
            });

            var results = await Task.WhenAll(tasks);
            return results.OrderBy(h => IpToUint(h.IpAddress)).ToList();
        }

        public async Task<SecurityScanResult> RemoteAuditAsync(
            string ip, string username, string password, string domain)
        {
            if (!SecurityHelper.IsValidIpAddress(ip))
                throw new ArgumentException("Некорректный IP-адрес.");

            var sanitizedUser = SecurityHelper.SanitizeUsername(username);
            var sanitizedDomain = SecurityHelper.SanitizeDomain(domain);

            if (string.IsNullOrEmpty(sanitizedUser))
                throw new ArgumentException("Некорректное имя пользователя.");

            return await Task.Run(() =>
            {
                var result = new SecurityScanResult { ScanTime = DateTime.Now };
                try
                {
                    var options = BuildOptions(sanitizedUser, password, sanitizedDomain);
                    var cimScope = ConnectScope($"\\\\{ip}\\root\\cimv2", options);

                    result.SecurityChecks.Add(CheckRemoteOS(cimScope));
                    result.SecurityChecks.Add(CheckRemoteUpdates(cimScope));
                    result.SecurityChecks.Add(CheckRemoteServices(cimScope));

                    try
                    {
                        var regScope = ConnectScope($"\\\\{ip}\\root\\default", options);
                        result.SecurityChecks.Add(CheckRemoteFirewall(regScope));
                        result.SecurityChecks.Add(CheckRemoteUAC(regScope));
                        result.SecurityChecks.Add(CheckRemoteRDP(regScope));
                        result.SecurityChecks.Add(CheckRemoteSMB1(regScope));
                        result.SecurityChecks.Add(CheckRemoteAutoRun(regScope));
                    }
                    catch
                    {
                        result.SecurityChecks.Add(new SecurityCheck
                        {
                            CheckName = "Реестр",
                            Category = "Система",
                            Status = "ОШИБКА",
                            Details = "StdRegProv недоступен"
                        });
                    }

                    try
                    {
                        var secScope = ConnectScope($"\\\\{ip}\\root\\SecurityCenter2", options);
                        result.SecurityChecks.Add(CheckRemoteAntivirus(secScope));
                    }
                    catch
                    {
                        result.SecurityChecks.Add(new SecurityCheck
                        {
                            CheckName = "Антивирус",
                            Category = "Приложения",
                            Status = "НЕ ОПРЕДЕЛЕНО",
                            Details = "SecurityCenter2 недоступен на серверных ОС"
                        });
                    }

                    result.Threats = BuildThreats(result.SecurityChecks);
                    CalcStatus(result);
                }
                catch (UnauthorizedAccessException)
                {
                    result.OverallStatus = "Доступ запрещён";
                    result.SecurityChecks.Add(new SecurityCheck
                    {
                        CheckName = "Подключение",
                        Category = "Сеть",
                        Status = "ОШИБКА",
                        Details = "Неверные учётные данные или недостаточно прав",
                        IsCritical = true
                    });
                }
                catch (System.Runtime.InteropServices.COMException)
                {
                    result.OverallStatus = "Недоступен";
                    result.SecurityChecks.Add(new SecurityCheck
                    {
                        CheckName = "Подключение",
                        Category = "Сеть",
                        Status = "ОШИБКА",
                        Details = "RPC/WMI недоступен",
                        IsCritical = true
                    });
                }
                catch (Exception)
                {
                    result.OverallStatus = "Ошибка";
                    result.SecurityChecks.Add(new SecurityCheck
                    {
                        CheckName = "Подключение",
                        Category = "Сеть",
                        Status = "ОШИБКА",
                        Details = "Не удалось подключиться к хосту",
                        IsCritical = true
                    });
                }
                return result;
            });
        }

        public async Task<Dictionary<string, bool>> DisableSMB1Async(
            List<string> ips, string username, string password, string domain)
        {
            var validIps = ips.Where(SecurityHelper.IsValidIpAddress).ToList();
            var results = new ConcurrentDictionary<string, bool>();

            var sanitizedUser = SecurityHelper.SanitizeUsername(username);
            var sanitizedDomain = SecurityHelper.SanitizeDomain(domain);

            var tasks = validIps.Select(ip => Task.Run(() =>
            {
                try
                {
                    var options = BuildOptions(sanitizedUser, password, sanitizedDomain);
                    var scope = ConnectScope($"\\\\{ip}\\root\\default", options);
                    bool ok = WriteDword(scope,
                        @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                        "SMB1", 0);
                    results[ip] = ok;
                }
                catch { results[ip] = false; }
            }));

            await Task.WhenAll(tasks);
            return new Dictionary<string, bool>(results);
        }

        public int CalculateSecurityScore(SecurityScanResult result)
        {
            int score = 100;
            foreach (var c in result.SecurityChecks)
            {
                if (c.Status.Contains("OK") || c.Status.Contains("НЕ ОПРЕДЕЛЕНО"))
                    continue;
                if (c.Status.Contains("КРИТИЧЕСКИЙ")) score -= 20;
                else if (c.IsCritical) score -= 15;
                else if (c.Status.Contains("РИСК")) score -= 10;
                else if (c.Status.Contains("ВНИМАНИЕ")) score -= 5;
            }
            return Math.Clamp(score, 0, 100);
        }

        public (string startIp, string endIp) DetectLocalSubnet()
        {
            try
            {
                foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (iface.OperationalStatus != OperationalStatus.Up)
                        continue;
                    if (iface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    foreach (var addr in iface.GetIPProperties().UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily != AddressFamily.InterNetwork)
                            continue;

                        var ip = addr.Address.GetAddressBytes();
                        var mask = addr.IPv4Mask.GetAddressBytes();
                        var start = new byte[4];
                        var end = new byte[4];

                        for (int i = 0; i < 4; i++)
                        {
                            start[i] = (byte)(ip[i] & mask[i]);
                            end[i] = (byte)((ip[i] & mask[i]) | ~mask[i]);
                        }

                        start[3] = Math.Max(start[3], (byte)1);
                        end[3] = Math.Min(end[3], (byte)254);

                        return (
                            $"{start[0]}.{start[1]}.{start[2]}.{start[3]}",
                            $"{end[0]}.{end[1]}.{end[2]}.{end[3]}"
                        );
                    }
                }
            }
            catch { }
            return ("192.168.1.1", "192.168.1.254");
        }

        private ConnectionOptions BuildOptions(
            string username, string password, string domain)
        {
            string fullUsername = string.IsNullOrEmpty(domain)
                ? username
                : $"{domain}\\{username}";

            return new ConnectionOptions
            {
                Username = fullUsername,
                Password = password,
                Timeout = TimeSpan.FromSeconds(WmiTimeoutSeconds),
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.PacketPrivacy
            };
        }

        private ManagementScope ConnectScope(
            string path, ConnectionOptions options)
        {
            var scope = new ManagementScope(path, options);
            scope.Connect();
            return scope;
        }

        private int? ReadDword(
            ManagementScope scope, string subKey, string valueName)
        {
            if (!SecurityHelper.IsValidRegistryPath(subKey))
                return null;

            try
            {
                using var reg = new ManagementClass(scope,
                    new ManagementPath("StdRegProv"), null!);
                var p = reg.GetMethodParameters("GetDWORDValue");
                p["hDefKey"] = HKLM;
                p["sSubKeyName"] = subKey;
                p["sValueName"] = valueName;
                var r = reg.InvokeMethod("GetDWORDValue", p, null!);
                if ((uint)r["ReturnValue"] == 0 && r["uValue"] != null)
                    return Convert.ToInt32(r["uValue"]);
            }
            catch { }
            return null;
        }

        private bool WriteDword(
            ManagementScope scope, string subKey,
            string valueName, int data)
        {
            if (!SecurityHelper.IsValidRegistryPath(subKey))
                return false;

            try
            {
                using var reg = new ManagementClass(scope,
                    new ManagementPath("StdRegProv"), null!);
                var p = reg.GetMethodParameters("SetDWORDValue");
                p["hDefKey"] = HKLM;
                p["sSubKeyName"] = subKey;
                p["sValueName"] = valueName;
                p["uValue"] = (uint)data;
                var r = reg.InvokeMethod("SetDWORDValue", p, null!);
                return (uint)r["ReturnValue"] == 0;
            }
            catch { }
            return false;
        }

        private SecurityCheck CheckRemoteOS(ManagementScope scope)
        {
            try
            {
                using var s = new ManagementObjectSearcher(scope,
                    new ObjectQuery(
                        "SELECT Caption, BuildNumber FROM Win32_OperatingSystem"));
                foreach (ManagementObject o in s.Get())
                {
                    string caption = o["Caption"]?.ToString() ?? "Неизвестно";
                    string build = o["BuildNumber"]?.ToString() ?? "";
                    int.TryParse(build, out int bNum);
                    bool outdated = bNum > 0 && bNum < 19044;

                    return new SecurityCheck
                    {
                        CheckName = "Операционная система",
                        Category = "Система",
                        Status = outdated ? "ВНИМАНИЕ" : "OK",
                        Details = $"{caption} (сборка {build})",
                        Recommendation = outdated
                            ? "Обновите ОС до актуальной версии"
                            : "",
                        IsCritical = bNum > 0 && bNum < 18363
                    };
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
            return new SecurityCheck
            {
                CheckName = "ОС",
                Category = "Система",
                Status = "НЕ ОПРЕДЕЛЕНО",
                Details = "Не удалось определить"
            };
        }

        private SecurityCheck CheckRemoteUpdates(ManagementScope scope)
        {
            try
            {
                DateTime? last = null;
                using var s = new ManagementObjectSearcher(scope,
                    new ObjectQuery(
                        "SELECT InstalledOn FROM Win32_QuickFixEngineering"));
                foreach (ManagementObject o in s.Get())
                {
                    try
                    {
                        var str = o["InstalledOn"]?.ToString();
                        if (DateTime.TryParse(str, CultureInfo.InvariantCulture,
                            DateTimeStyles.None, out var dt))
                            if (last == null || dt > last) last = dt;
                    }
                    catch { }
                }

                if (last.HasValue)
                {
                    int days = (int)(DateTime.Now - last.Value).TotalDays;
                    return new SecurityCheck
                    {
                        CheckName = "Обновления Windows",
                        Category = "Система",
                        Status = days <= 60 ? "OK" : "КРИТИЧЕСКИЙ РИСК",
                        Details = $"Последнее: {last.Value:dd.MM.yyyy} ({days} дн. назад)",
                        Recommendation = days > 60 ? "Установите обновления" : "",
                        IsCritical = days > 60
                    };
                }
            }
            catch { }
            return new SecurityCheck
            {
                CheckName = "Обновления",
                Category = "Система",
                Status = "НЕ ОПРЕДЕЛЕНО",
                Details = "Не удалось проверить"
            };
        }

        private SecurityCheck CheckRemoteServices(ManagementScope scope)
        {
            var risky = new List<string>();
            var svcNames = new Dictionary<string, string>
            {
                { "RemoteRegistry", "Удалённый реестр" },
                { "TlntSvr", "Telnet" },
                { "SSDPSRV", "SSDP/UPnP" }
            };

            try
            {
                foreach (var kv in svcNames)
                {
                    if (!SecurityHelper.IsValidWmiName(kv.Key))
                        continue;

                    string safeServiceName =
                        SecurityHelper.SanitizeWmiValue(kv.Key);

                    using var s = new ManagementObjectSearcher(scope,
                        new ObjectQuery(
                            $"SELECT State FROM Win32_Service WHERE Name='{safeServiceName}'"));
                    foreach (ManagementObject o in s.Get())
                        if (o["State"]?.ToString() == "Running")
                            risky.Add(kv.Value);
                }
            }
            catch { }

            if (risky.Any())
                return new SecurityCheck
                {
                    CheckName = "Опасные службы",
                    Category = "Службы",
                    Status = "ВНИМАНИЕ",
                    Details = $"Запущены: {string.Join(", ", risky)}",
                    Recommendation = "Остановите неиспользуемые службы"
                };

            return new SecurityCheck
            {
                CheckName = "Службы",
                Category = "Службы",
                Status = "OK",
                Details = "Опасных служб не обнаружено"
            };
        }

        private SecurityCheck CheckRemoteFirewall(ManagementScope regScope)
        {
            int count = 0;
            foreach (var profile in new[]
                { "DomainProfile", "StandardProfile", "PublicProfile" })
            {
                var v = ReadDword(regScope,
                    $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}",
                    "EnableFirewall");
                if (v == 1) count++;
            }

            bool ok = count >= 2;
            return new SecurityCheck
            {
                CheckName = "Брандмауэр",
                Category = "Сеть",
                Status = ok ? "OK" : "КРИТИЧЕСКИЙ РИСК",
                Details = ok
                    ? $"Активен ({count}/3 профилей)"
                    : $"Отключён ({count}/3 профилей)",
                Recommendation = ok ? "" : "Включите брандмауэр",
                IsCritical = !ok
            };
        }

        private SecurityCheck CheckRemoteUAC(ManagementScope regScope)
        {
            var v = ReadDword(regScope,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA");
            bool on = v == 1;
            return new SecurityCheck
            {
                CheckName = "UAC",
                Category = "Безопасность",
                Status = on ? "OK" : "КРИТИЧЕСКИЙ РИСК",
                Details = on ? "Включён" : "Отключён",
                Recommendation = on ? "" : "Включите UAC",
                IsCritical = !on
            };
        }

        private SecurityCheck CheckRemoteRDP(ManagementScope regScope)
        {
            var v = ReadDword(regScope,
                @"SYSTEM\CurrentControlSet\Control\Terminal Server",
                "fDenyTSConnections");
            bool rdp = v != null && v == 0;
            return new SecurityCheck
            {
                CheckName = "RDP",
                Category = "Сеть",
                Status = rdp ? "ВНИМАНИЕ" : "OK",
                Details = rdp
                    ? "Удалённый рабочий стол включён"
                    : "RDP отключён",
                Recommendation = rdp
                    ? "Отключите RDP если не используется"
                    : ""
            };
        }

        private SecurityCheck CheckRemoteSMB1(ManagementScope regScope)
        {
            var v = ReadDword(regScope,
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "SMB1");
            bool enabled = v == null || v != 0;
            return new SecurityCheck
            {
                CheckName = "SMBv1",
                Category = "Сеть",
                Status = enabled ? "КРИТИЧЕСКИЙ РИСК" : "OK",
                Details = enabled
                    ? "SMBv1 включён — уязвимость EternalBlue/WannaCry"
                    : "SMBv1 отключён",
                Recommendation = enabled ? "Отключите SMBv1" : "",
                IsCritical = enabled
            };
        }

        private SecurityCheck CheckRemoteAutoRun(ManagementScope regScope)
        {
            var v = ReadDword(regScope,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoDriveTypeAutoRun");
            bool disabled = v.HasValue && v.Value >= 0xFF;
            return new SecurityCheck
            {
                CheckName = "Автозапуск USB",
                Category = "Система",
                Status = disabled ? "OK" : "РИСК",
                Details = disabled
                    ? "Автозапуск отключён"
                    : "Автозапуск разрешён",
                Recommendation = disabled
                    ? ""
                    : "Отключите автозапуск съёмных носителей"
            };
        }

        private SecurityCheck CheckRemoteAntivirus(ManagementScope scope)
        {
            try
            {
                using var s = new ManagementObjectSearcher(scope,
                    new ObjectQuery(
                        "SELECT displayName, productState FROM AntiVirusProduct"));
                foreach (ManagementObject o in s.Get())
                {
                    var name = o["displayName"]?.ToString() ?? "Неизвестно";
                    if (uint.TryParse(
                        o["productState"]?.ToString(), out uint st))
                    {
                        bool enabled =
                            (BitConverter.GetBytes(st)[1] & 0x10) != 0;
                        if (enabled)
                            return new SecurityCheck
                            {
                                CheckName = "Антивирус",
                                Category = "Приложения",
                                Status = "OK",
                                Details = $"{name} — активен"
                            };
                    }
                }
            }
            catch { }
            return new SecurityCheck
            {
                CheckName = "Антивирус",
                Category = "Приложения",
                Status = "КРИТИЧЕСКИЙ РИСК",
                Details = "Антивирус не обнаружен или неактивен",
                Recommendation = "Установите и активируйте антивирус",
                IsCritical = true
            };
        }

        private List<SecurityThreat> BuildThreats(List<SecurityCheck> checks)
        {
            var threats = new List<SecurityThreat>();
            foreach (var c in checks)
            {
                if (c.Status.Contains("OK")
                    || c.Status.Contains("НЕ ОПРЕДЕЛЕНО"))
                    continue;

                string severity;
                if (c.Status.Contains("КРИТИЧЕСКИЙ")) severity = "Критическая";
                else if (c.IsCritical) severity = "Высокая";
                else if (c.Status.Contains("ВНИМАНИЕ")) severity = "Средняя";
                else if (c.Status.Contains("РИСК")) severity = "Средняя";
                else continue;

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

        private void CalcStatus(SecurityScanResult r)
        {
            r.TotalThreats = r.Threats.Count;
            r.CriticalIssues = r.Threats.Count(
                t => t.Severity == "Критическая");
            r.Warnings = r.Threats.Count(
                t => t.Severity == "Средняя" || t.Severity == "Высокая");

            if (r.CriticalIssues > 0)
                r.OverallStatus =
                    $"Критический риск ({r.CriticalIssues})";
            else if (r.TotalThreats > 0)
                r.OverallStatus =
                    $"Требует внимания ({r.TotalThreats})";
            else
                r.OverallStatus = "Защищено";
        }

        private List<string> GenerateIpRange(string start, string end)
        {
            var result = new List<string>();
            uint s = IpToUint(start);
            uint e = IpToUint(end);
            if (s == 0 || e == 0 || s > e || e - s > MaxIpRange)
                return result;
            for (uint i = s; i <= e; i++)
                result.Add(
                    $"{(i >> 24) & 0xFF}.{(i >> 16) & 0xFF}" +
                    $".{(i >> 8) & 0xFF}.{i & 0xFF}");
            return result;
        }

        private static uint IpToUint(string ip)
        {
            var p = ip.Split('.');
            if (p.Length != 4) return 0;
            if (!byte.TryParse(p[0], out byte a) ||
                !byte.TryParse(p[1], out byte b) ||
                !byte.TryParse(p[2], out byte c) ||
                !byte.TryParse(p[3], out byte d))
                return 0;
            return (uint)(a << 24 | b << 16 | c << 8 | d);
        }
    }
}