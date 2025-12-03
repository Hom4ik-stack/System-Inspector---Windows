using SecurityShield.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Windows;

namespace SecurityShield.Services
{
    public class DeviceService : IDeviceService, IDisposable
    {

        private ManagementEventWatcher? _insertWatcher;
        private ManagementEventWatcher? _removeWatcher;


        public event EventHandler? DeviceListChanged;

        public DeviceService()
        {
            InitializeDeviceWatchers();
        }

        private void InitializeDeviceWatchers()
        {
            try
            {
                var insertQuery = new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PnPEntity'");
                _insertWatcher = new ManagementEventWatcher(insertQuery);
                _insertWatcher.EventArrived += (s, e) => DeviceListChanged?.Invoke(this, EventArgs.Empty);
                _insertWatcher.Start();

                var removeQuery = new WqlEventQuery("SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PnPEntity'");
                _removeWatcher = new ManagementEventWatcher(removeQuery);
                _removeWatcher.EventArrived += (s, e) => DeviceListChanged?.Invoke(this, EventArgs.Empty);
                _removeWatcher.Start();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка инициализации мониторинга (возможно, нет прав админа): {ex.Message}");
            }
        }

        public List<DeviceInfo> GetConnectedDevices()
        {
            var devices = new List<DeviceInfo>();
            try
            {

                // 1. PnP Устройства (включает USB, HID, Камеры, Телефоны)
                devices.AddRange(GetPnPDevices());

                // 2. Диски (Логические и Физические)
                devices.AddRange(GetDiskDevices());

                // 3. Сетевые адаптеры
                devices.AddRange(GetNetworkDevices());

                // Фильтрация дубликатов по DeviceID
                var uniqueDevices = devices
                    .GroupBy(d => d.DeviceID)
                    .Select(g => g.First())
                    .OrderBy(d => d.Type)
                    .ThenBy(d => d.Name)
                    .ToList();

                foreach (var device in uniqueDevices)
                {
                    CheckDeviceSafety(device);
                }

                return uniqueDevices;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения устройств: {ex.Message}");
                return new List<DeviceInfo>();
            }
        }


        private List<DeviceInfo> GetPnPDevices()
        {
            var list = new List<DeviceInfo>();
            try
            {
                // Берем только "present" устройства, исключаем некоторые системные (ROOT)
                using (var searcher = new ManagementObjectSearcher(@"SELECT * FROM Win32_PnPEntity WHERE ConfigManagerErrorCode = 0"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var deviceId = obj["DeviceID"]?.ToString() ?? "";
                        var name = obj["Name"]?.ToString() ?? obj["Description"]?.ToString() ?? "Неизвестное устройство";
                        var pnpClass = obj["PNPClass"]?.ToString() ?? "";
                        var description = obj["Description"]?.ToString() ?? "";

                        // Фильтр "мусора" (системные шины, драйверы томов и т.д., если они не интересны пользователю)
                        if (pnpClass == "System" || pnpClass == "Volume" || deviceId.StartsWith(@"SWD\"))
                            continue;

                        var device = new DeviceInfo
                        {
                            Name = name,
                            DeviceID = deviceId,
                            Manufacturer = obj["Manufacturer"]?.ToString() ?? "Неизвестно",
                            Status = obj["Status"]?.ToString() ?? "OK",
                            Description = description,
                            DriverVersion = "N/A", // Получение версии драйвера для каждого устройства - дорогая операция, можно опустить для скорости
                            Type = DetermineDeviceType(deviceId),
                            Category = DetermineCategory(pnpClass, description, deviceId),
                            IsRemovable = CheckIfRemovable(description, pnpClass)
                        };

                        list.Add(device);
                    }
                }
            }
            catch (Exception ex) { Debug.WriteLine($"PnP Error: {ex.Message}"); }
            return list;
        }

        private string DetermineDeviceType(string deviceId)
        {
            if (deviceId.StartsWith("USB")) return "Внешнее (USB)";
            if (deviceId.StartsWith("BTH")) return "Внешнее (Bluetooth)";
            if (deviceId.StartsWith("PCI")) return "Внутреннее (PCI)";
            if (deviceId.StartsWith("HDAUDIO")) return "Внутреннее (Audio)";
            return "Системное/Другое";
        }

        private string DetermineCategory(string pnpClass, string description, string deviceId)
        {
            var descLower = description.ToLower();
            if (pnpClass == "Image" || descLower.Contains("camera") || descLower.Contains("webcam")) return "Камера/Сканер";
            if (pnpClass == "Keyboard" || descLower.Contains("keyboard")) return "Клавиатура";
            if (pnpClass == "Mouse" || descLower.Contains("mouse")) return "Мышь";
            if (pnpClass == "AudioEndpoint" || pnpClass == "Media") return "Аудио";
            if (pnpClass == "Net") return "Сеть";
            if (pnpClass == "DiskDrive" || descLower.Contains("usb device")) return "Накопитель";
            if (pnpClass == "WPD" || descLower.Contains("phone") || descLower.Contains("android")) return "Мобильное устройство";
            if (pnpClass == "Bluetooth") return "Bluetooth";

            return pnpClass; // Возвращаем класс как категорию по умолчанию
        }

        private bool CheckIfRemovable(string description, string pnpClass)
        {
            var lower = description.ToLower();
            return lower.Contains("usb") || lower.Contains("flash") || lower.Contains("removable") || pnpClass == "WPD";
        }

        // Сохраняем логику для Дисков, но упрощаем
        private List<DeviceInfo> GetDiskDevices()
        {
            var disks = new List<DeviceInfo>();
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var mediaType = obj["MediaType"]?.ToString() ?? "";
                        disks.Add(new DeviceInfo
                        {
                            Name = obj["Caption"]?.ToString() ?? "Диск",
                            Type = "Накопитель",
                            Category = "Диск",
                            Status = obj["Status"]?.ToString() ?? "OK",
                            Manufacturer = obj["Manufacturer"]?.ToString() ?? "Generic",
                            DeviceID = obj["DeviceID"]?.ToString() ?? "",
                            Size = obj["Size"] != null ? Convert.ToUInt64(obj["Size"]) : 0,
                            IsRemovable = mediaType.ToLower().Contains("removable") || mediaType.ToLower().Contains("external")
                        });
                    }
                }
            }
            catch { }
            return disks;
        }
        public bool CheckDeviceSafety(DeviceInfo device)
        {
            if (device == null) return false;

            device.IsSafe = true;
            device.VulnerabilityStatus = "Без уязвимостей";
            var warnings = new List<string>();

          
            if (device.Status.ToUpper() == "ERROR" || device.Status.ToUpper() == "DEGRADED")
            {
                device.IsSafe = false;
                device.VulnerabilityStatus = "Сбой устройства";
                warnings.Add("Устройство сообщает об ошибке.");
            }

            if (device.Category == "Накопитель" && device.IsRemovable)
            {
                // Съемные диски всегда потенциально опасны
                device.IsSafe = false;
                device.VulnerabilityStatus = "Требуется сканирование";
                warnings.Add("Съемный носитель. Проверьте антивирусом.");
            }

            if (device.Category == "Клавиатура" && device.Type.Contains("USB") && device.Name.Contains("HID"))
            {
                // BadUSB атаки часто маскируются под клавиатуры
                // Это параноидальная проверка, но для Security Shield подходит
                device.VulnerabilityStatus = "Проверка BadUSB";
                // Мы не ставим IsSafe = false, но даем инфо
            }

            if (warnings.Any())
            {
                device.SafetyWarning = string.Join(" ", warnings);
            }
            else
            {
                device.SafetyWarning = "";
            }

            return device.IsSafe;
        }
        public void EjectDevice(string deviceId)
        {
            try
            {
                if (deviceId.ToLower().Contains("usb"))
                {
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT * FROM Win32_USBHub WHERE DeviceID = '{deviceId.Replace("\\", "\\\\")}'"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            obj.InvokeMethod("RemoveDevice", null);
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Не удалось извлечь устройство: {ex.Message}");
            }
        }

        public void OpenDeviceSettings(string deviceId)
        {
            try
            {
                
                Process.Start(new ProcessStartInfo
                {
                    FileName = "mmc.exe",
                    Arguments = "devmgmt.msc",
                    UseShellExecute = true,
                    Verb = "runas"
                });
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Не удалось открыть настройки устройства: {ex.Message}");
            }

        }
        public void Dispose()
        {
            _insertWatcher?.Stop();
            _insertWatcher?.Dispose();
            _removeWatcher?.Stop();
            _removeWatcher?.Dispose();
        }



        private List<DeviceInfo> GetNetworkDevices()
        {
            var networkDevices = new List<DeviceInfo>();
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var device = new DeviceInfo
                        {
                            Name = obj["Name"]?.ToString() ?? "Сетевой адаптер",
                            Type = "Внутреннее",
                            Category = "Сеть",
                            Status = obj["NetEnabled"]?.ToString() == "True" ? "Включен" : "Выключен",
                            Manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown",
                            DeviceID = obj["DeviceID"]?.ToString() ?? "",
                            Description = obj["Description"]?.ToString() ?? "",
                            DriverVersion = obj["DriverVersion"]?.ToString() ?? "Unknown"
                        };
                        networkDevices.Add(device);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения сетевых устройств: {ex.Message}");
            }
            return networkDevices;
        }
    }
}
