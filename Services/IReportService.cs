using SecurityShield.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SecurityShield.Services
{
    public interface IReportService
    {
        Task<bool> ExportReportToFileAsync(
            string filePath, ReportData data, ReportOptions options);
        Task<bool> ExportNetworkReportAsync(
            string filePath, List<NetworkHost> hosts, ReportOptions options);
    }
}