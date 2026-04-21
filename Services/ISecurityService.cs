using SecurityShield.Models;

namespace SecurityShield.Services
{
    public interface ISecurityService
    {
        AntivirusInfo GetInstalledAntivirus();
        DefenderStatus GetDefenderStatus();
        SecurityScanResult PerformComprehensiveSecurityScan();
        bool EnableDefenderProtection();
        void OpenWindowsSecurity();
        void OpenAntivirusUI();
    }
}