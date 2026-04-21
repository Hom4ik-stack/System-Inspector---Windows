namespace SecurityShield.Models
{
    public class ReportOptions
    {
        public bool IncludeSystemInfo { get; set; } = true;
        public bool IncludeSecurityChecks { get; set; } = true;
        public bool IncludeThreats { get; set; } = true;
        public bool IncludeDevices { get; set; } = true;
        public bool IncludeDrivers { get; set; } = true;
        public bool IncludeProcesses { get; set; } = true;
        public bool IncludeDrives { get; set; } = true;
        public bool IncludeNetworkHosts { get; set; } = true;
        public bool IncludeSoftware { get; set; } = true;
        public bool IncludeStartupPrograms { get; set; } = true;
        public bool IncludeHostDetails { get; set; } = true;
        public bool IncludeHostChecks { get; set; } = true;
        public bool IncludeStatistics { get; set; } = true;
    }
}