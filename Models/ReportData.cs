using System.Collections.Generic;

namespace SecurityShield.Models
{
    public class ReportData
    {
        public SystemInfo SystemInfo { get; set; } = new();
        public List<ProcessInfo> TopProcesses { get; set; } = new();
        public List<DriveInfoModel> Drives { get; set; } = new();
        public List<DriverInfo> Drivers { get; set; } = new();
        public List<DeviceInfo> Devices { get; set; } = new();
        public List<SecurityCheck> SecurityChecks { get; set; } = new();
        public List<SecurityThreat> Threats { get; set; } = new();
        public List<NetworkHost> NetworkHosts { get; set; } = new();
        public string ReportDate { get; set; } = string.Empty;
        public string OverallSecurityStatus { get; set; } = "Неизвестно";
        public int TotalSecurityIssues { get; set; }
        public int CriticalIssuesCount { get; set; }
    }
}