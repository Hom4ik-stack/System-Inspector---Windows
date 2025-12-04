using SecurityShield.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SecurityShield.Services
{
    public interface ISecurityService
    {
        // Основные методы безопасности
        List<SecurityVulnerability> ScanForVulnerabilities();

        bool CheckFirewallStatus();
        List<SecurityVulnerability> CheckSystemConfiguration();
        List<SecurityVulnerability> CheckUserAccounts();
        List<SecurityVulnerability> CheckNetworkSecurity();
        
     
        AntivirusInfo GetInstalledAntivirus();
     

        // Методы для Защитника Windows
        DefenderStatus GetDefenderStatus();
  
        (bool Success, string Output, int Progress) StartDefenderScanWithProgress(string scanType);
    
        bool EnableDefenderProtection();
        void OpenWindowsSecurity();
        void OpenAntivirusUI();

        // Дополнительные проверки безопасности
        SecurityScanResult PerformComprehensiveSecurityScan();
        string GetWindowsVersionStatus();
        bool CheckUACStatus();
        bool CheckBitLockerStatus();
        bool CheckSmartScreenStatus();
        bool CheckRDPStatus();
        List<SecurityVulnerability> PerformComprehensiveSecurityAudit();
    }
}