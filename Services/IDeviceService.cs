using SecurityShield.Models;
using System;
using System.Collections.Generic;

namespace SecurityShield.Services
{
    public interface IDeviceService
    {
        event EventHandler? DeviceListChanged;
        List<DeviceInfo> GetConnectedDevices();
        void EjectDevice(string deviceId);
        void OpenDeviceSettings(string deviceId);
    }
}