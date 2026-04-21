using SecurityShield.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Management;

namespace SecurityShield.Services
{
    public class DriverService : IDriverService
    {
        public List<DriverInfo> GetInstalledDrivers()
        {
            var list = new List<DriverInfo>();
            try
            {
                using var s = new ManagementObjectSearcher("SELECT * FROM Win32_PnPSignedDriver");
                foreach (ManagementObject o in s.Get())
                {
                    var name = o["DeviceName"]?.ToString();
                    var cls = o["DeviceClass"]?.ToString()?.ToUpper() ?? "";
                    if (string.IsNullOrEmpty(name) || cls == "SOFTWAREDEVICE" || cls == "LEGACYDRIVER" || cls == "VOLUME")
                        continue;

                    string dateStr = "";
                    try
                    {
                        var raw = o["DriverDate"]?.ToString();
                        if (!string.IsNullOrEmpty(raw))
                        {
                            var dt = ManagementDateTimeConverter.ToDateTime(raw);
                            if (dt.Year > 1970)
                                dateStr = dt.ToString("dd.MM.yyyy");
                        }
                    }
                    catch { dateStr = "—"; }

                    bool signed = false;
                    try
                    {
                        signed = o["IsSigned"] is bool b ? b : o["IsSigned"]?.ToString() == "True";
                    }
                    catch { }

                    var manufacturer = o["Manufacturer"]?.ToString() ?? "—";

                    list.Add(new DriverInfo
                    {
                        Name = name,
                        Description = o["Description"]?.ToString() ?? "",
                        Version = o["DriverVersion"]?.ToString() ?? "—",
                        Manufacturer = manufacturer,
                        Date = dateStr,
                        Class = o["DeviceClass"]?.ToString() ?? "",
                        DigitalSignature = signed ? "Подписан" : "Не подписан"
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
            return list;
        }

        public List<DriverInfo> CheckOutdatedDrivers()
        {
            var outdated = new List<DriverInfo>();
            foreach (var d in GetInstalledDrivers())
            {
                int riskScore = 0;

                if (d.DigitalSignature == "Не подписан") riskScore += 40;

                if (d.Manufacturer == "—" || d.Manufacturer.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                    riskScore += 10;

                bool isMicrosoft = d.Manufacturer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

                if (!string.IsNullOrEmpty(d.Date) && d.Date != "—")
                {
                    if (DateTime.TryParseExact(d.Date, "dd.MM.yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                    {
                        double years = (DateTime.Now - dt).TotalDays / 365.0;
                        if (years > 7) riskScore += 30;
                        else if (years > 5) riskScore += 20;
                        else if (years > 3) riskScore += 10;
                    }
                }

                bool isOutdated = isMicrosoft ? riskScore >= 50 : riskScore >= 30;

                if (isOutdated)
                {
                    d.IsOutdated = true;
                    d.UpdateStatus = "Требуется обновление";
                    d.RiskLevel = riskScore >= 70 ? "Высокий" : riskScore >= 40 ? "Средний" : "Низкий";
                    outdated.Add(d);
                }
                else
                {
                    d.IsOutdated = false;
                    d.UpdateStatus = "Актуальный";
                    d.RiskLevel = "Низкий";
                }
            }
            return outdated;
        }
    }
}