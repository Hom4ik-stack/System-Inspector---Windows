using CommunityToolkit.Mvvm.ComponentModel;
using System;
using System.Linq;

namespace SecurityShield.Models
{
    public partial class ProcessInfo : ObservableObject
    {
        [ObservableProperty] private string _name = string.Empty;
        [ObservableProperty] private int _id;
        [ObservableProperty] private double _memoryMB;
        [ObservableProperty] private double _cpu;
        [ObservableProperty] private string _processPath = string.Empty;
        [ObservableProperty] private bool _isUserProcess;

        public bool IsSelfProcess => Id == Environment.ProcessId;

        public string KillButtonText => IsSelfProcess ? "Закрыть" : "Завершить";

        public bool CheckIsUserProcess()
        {
            if (string.IsNullOrEmpty(Name)) return false;
            if (IsSelfProcess) return true;

            string n = Name.ToLower();

            var critical = new[]
            {
                "system", "smss", "csrss", "wininit", "services", "lsass",
                "svchost", "winlogon", "fontdrvhost", "dwm", "taskhostw",
                "registry", "memory compression", "idle"
            };
            if (critical.Any(c => n.Equals(c)))
                return false;

            var systemSvc = new[]
            {
                "spoolsv", "taskeng", "searchindexer", "runtimebroker",
                "sihost", "ctfmon", "conhost", "audiodg", "securityhealthservice",
                "msmpeng", "wmiprvse", "dllhost", "dashost", "lsaiso",
                "sgrmbroker", "searchhost", "startmenuexperiencehost",
                "textinputhost", "widgetservice"
            };
            if (systemSvc.Any(s => n.Equals(s)))
                return false;

            if (!string.IsNullOrEmpty(ProcessPath) && !ProcessPath.Contains("Нет доступа"))
            {
                var sysPaths = new[]
                {
                    "C:\\Windows\\System32",
                    "C:\\Windows\\SysWOW64",
                    "C:\\Windows\\SystemApps"
                };
                if (sysPaths.Any(p => ProcessPath.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                    return false;
            }

            return true;
        }
    }
}