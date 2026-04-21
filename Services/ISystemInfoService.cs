using SecurityShield.Models;
using System.Collections.Generic;

namespace SecurityShield.Services
{
    public interface ISystemInfoService
    {
        SystemInfo GetDetailedSystemInfo();
        List<DriveInfoModel> GetDriveInfo();
        List<ProcessInfo> GetRunningProcesses();
        double GetCurrentCpuUsage();
        bool KillProcess(int processId);
        List<SoftwareInfo> GetInstalledSoftware();
        List<StartupProgram> GetStartupPrograms();
        List<NetworkConnectionInfo> GetActiveNetworkConnections();
    }
}