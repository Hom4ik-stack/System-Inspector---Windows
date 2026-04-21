using SecurityShield.Models;
using System.Collections.Generic;

namespace SecurityShield.Services
{
    public interface IDriverService
    {
        List<DriverInfo> GetInstalledDrivers();
        List<DriverInfo> CheckOutdatedDrivers();
    }
}