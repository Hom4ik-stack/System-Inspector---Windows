using SecurityShield.Models;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SecurityShield.Services
{
    public interface INetworkScanService
    {
        Task<List<NetworkHost>> DiscoverHostsAsync(string startIp, string endIp,
            CancellationToken ct = default);
        Task<SecurityScanResult> RemoteAuditAsync(string ip,
            string username, string password, string domain);
        Task<Dictionary<string, bool>> DisableSMB1Async(List<string> ips,
            string username, string password, string domain);
        int CalculateSecurityScore(SecurityScanResult result);
        (string startIp, string endIp) DetectLocalSubnet();
    }
}