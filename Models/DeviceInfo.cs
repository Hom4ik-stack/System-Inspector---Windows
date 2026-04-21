namespace SecurityShield.Models
{
    public class DeviceInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string DeviceID { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsRemovable { get; set; }
        public bool IsSafe { get; set; } = true;
        public string SafetyWarning { get; set; } = string.Empty;
        public string VulnerabilityStatus { get; set; } = "Не проверено";
    }
}