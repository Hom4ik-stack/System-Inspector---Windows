using System;

namespace SecurityShield.Models
{
    public class AntivirusInfo
    {
        public string Name { get; set; } = "Не обнаружен";
        public string Vendor { get; set; } = "Неизвестно";
        public string Status { get; set; } = "Неактивен";
        public string Version { get; set; } = "Неизвестно";
        public bool IsEnabled { get; set; }
        public bool IsUpToDate { get; set; }
        public DateTime LastUpdate { get; set; }
        public string RealTimeProtection { get; set; } = "Выключена";
    }
}