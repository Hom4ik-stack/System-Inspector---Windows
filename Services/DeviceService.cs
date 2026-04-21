using SecurityShield.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;

namespace SecurityShield.Services
{
    public class DeviceService : IDeviceService, IDisposable
    {
        private ManagementEventWatcher? _insertWatcher;
        private ManagementEventWatcher? _removeWatcher;
        public event EventHandler? DeviceListChanged;

        public DeviceService()
        {
            try
            {
                _insertWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PnPEntity'"));
                _insertWatcher.EventArrived += (s, e) => DeviceListChanged?.Invoke(this, EventArgs.Empty);
                _insertWatcher.Start();
                _removeWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PnPEntity'"));
                _removeWatcher.EventArrived += (s, e) => DeviceListChanged?.Invoke(this, EventArgs.Empty);
                _removeWatcher.Start();
            }
            catch (Exception ex) { Debug.WriteLine(ex.Message); }
        }

        public List<DeviceInfo> GetConnectedDevices()
        {
            var devices = new List<DeviceInfo>();
            try
            {
                devices.AddRange(GetPnP());
                devices.AddRange(GetDisks());
                devices.AddRange(GetNetAdapters());
                var unique = devices.GroupBy(d => d.DeviceID).Select(g => g.First()).OrderBy(d => d.Category).ToList();
                foreach (var d in unique) CheckSafety(d);
                return unique;
            }
            catch { return new List<DeviceInfo>(); }
        }

        public void EjectDevice(string deviceId)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "rundll32.exe",
                    Arguments = "shell32.dll,Control_RunDLL hotplug.dll",
                    UseShellExecute = true
                });
            }
            catch (Exception ex) { throw new InvalidOperationException(ex.Message); }
        }

        public void OpenDeviceSettings(string deviceId)
        {
            try { Process.Start(new ProcessStartInfo { FileName = "mmc.exe", Arguments = "devmgmt.msc", UseShellExecute = true, Verb = "runas" }); }
            catch (Exception ex) { throw new InvalidOperationException(ex.Message); }
        }

        public void Dispose()
        {
            try { _insertWatcher?.Stop(); _insertWatcher?.Dispose(); } catch { }
            try { _removeWatcher?.Stop(); _removeWatcher?.Dispose(); } catch { }
        }

        private List<DeviceInfo> GetPnP()
        {
            var list = new List<DeviceInfo>();
            try
            {
                using var s = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE ConfigManagerErrorCode = 0");
                foreach (ManagementObject o in s.Get())
                {
                    var id = o["DeviceID"]?.ToString() ?? "";
                    var cls = o["PNPClass"]?.ToString() ?? "";
                    if (cls == "System" || cls == "Volume" || cls == "LegacyDriver" || id.StartsWith(@"SWD\")) continue;
                    var desc = o["Description"]?.ToString() ?? "";
                    list.Add(new DeviceInfo
                    {
                        Name = o["Name"]?.ToString() ?? desc,
                        DeviceID = id,
                        Manufacturer = o["Manufacturer"]?.ToString() ?? "Неизвестно",
                        Status = o["Status"]?.ToString() ?? "OK",
                        Description = desc,
                        Type = id.StartsWith("USB") ? "USB" : id.StartsWith("PCI") ? "PCI" : id.StartsWith("BTH") ? "Bluetooth" : "Другое",
                        Category = MapCategory(cls, desc),
                        IsRemovable = desc.ToLower().Contains("usb") || cls == "WPD"
                    });
                }
            }
            catch { }
            return list;
        }

        private List<DeviceInfo> GetDisks()
        {
            var list = new List<DeviceInfo>();
            try
            {
                using var s = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
                foreach (ManagementObject o in s.Get())
                {
                    var mt = o["MediaType"]?.ToString() ?? "";
                    var iface = o["InterfaceType"]?.ToString() ?? "";
                    list.Add(new DeviceInfo
                    {
                        Name = o["Caption"]?.ToString() ?? "Диск",
                        Type = "Накопитель",
                        Category = "Диск",
                        Status = o["Status"]?.ToString() ?? "OK",
                        Manufacturer = o["Manufacturer"]?.ToString() ?? "Generic",
                        DeviceID = o["DeviceID"]?.ToString() ?? "",
                        IsRemovable = mt.ToLower().Contains("removable") || iface.Equals("USB", StringComparison.OrdinalIgnoreCase)
                    });
                }
            }
            catch { }
            return list;
        }

        private List<DeviceInfo> GetNetAdapters()
        {
            var list = new List<DeviceInfo>();
            try
            {
                using var s = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE");
                foreach (ManagementObject o in s.Get())
                    list.Add(new DeviceInfo
                    {
                        Name = o["Name"]?.ToString() ?? "Сетевой адаптер",
                        Type = "Сеть",
                        Category = "Сеть",
                        Status = o["NetEnabled"]?.ToString() == "True" ? "Включен" : "Выключен",
                        Manufacturer = o["Manufacturer"]?.ToString() ?? "Unknown",
                        DeviceID = o["DeviceID"]?.ToString() ?? ""
                    });
            }
            catch { }
            return list;
        }

        private string MapCategory(string cls, string desc)
        {
            var d = desc.ToLower();
            if (cls == "Image" || d.Contains("camera")) return "Камера";
            if (cls == "Keyboard") return "Клавиатура";
            if (cls == "Mouse") return "Мышь";
            if (cls == "AudioEndpoint" || cls == "Media") return "Аудио";
            if (cls == "Net") return "Сеть";
            if (cls == "DiskDrive") return "Накопитель";
            if (cls == "Display") return "Видеокарта";
            if (cls == "Monitor") return "Монитор";
            if (cls == "Printer") return "Принтер";
            if (cls == "Bluetooth") return "Bluetooth";
            if (cls == "WPD") return "Мобильное";
            return string.IsNullOrEmpty(cls) ? "Другое" : cls;
        }

        private void CheckSafety(DeviceInfo d)
        {
            d.IsSafe = true;
            d.VulnerabilityStatus = "OK";
            var w = new List<string>();
            if (d.Status.Equals("ERROR", StringComparison.OrdinalIgnoreCase))
            { d.IsSafe = false; d.VulnerabilityStatus = "Сбой"; w.Add("Ошибка устройства."); }
            if (d.Category == "Накопитель" && d.IsRemovable)
            { d.IsSafe = false; d.VulnerabilityStatus = "Проверьте"; w.Add("Съёмный носитель."); }
            d.SafetyWarning = string.Join(" ", w);
        }
    }
}