namespace SecurityShield.Models
{
    public class DefenderStatus
    {
        public bool RealTimeProtection { get; set; }
        public bool CloudProtection { get; set; }
        public bool TamperProtection { get; set; }
        public string SignatureVersion { get; set; } = "Неизвестно";
        public string LastScanTime { get; set; } = "Неизвестно";
        public bool FirewallEnabled { get; set; }
    }
}