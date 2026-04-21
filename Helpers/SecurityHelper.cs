using System;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;

namespace SecurityShield.Helpers
{
    public static class SecurityHelper
    {
        private static readonly Regex SafeIpRegex = new(
            @"^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$",
            RegexOptions.Compiled);

        private static readonly Regex SafeWmiNameRegex = new(
            @"^[a-zA-Z0-9_\-\.\s]{1,256}$",
            RegexOptions.Compiled);

        private static readonly Regex SafeRegistryPathRegex = new(
            @"^[a-zA-Z0-9_\\\-\.\s]+$",
            RegexOptions.Compiled);

        public static bool IsValidIpAddress(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
                return false;
            if (!SafeIpRegex.IsMatch(ip))
                return false;
            return IPAddress.TryParse(ip, out _);
        }

        public static bool IsValidIpRange(string startIp, string endIp)
        {
            if (!IsValidIpAddress(startIp) || !IsValidIpAddress(endIp))
                return false;
            var s = IpToUint(startIp);
            var e = IpToUint(endIp);
            if (s == 0 || e == 0 || s > e)
                return false;
            if (e - s > 1024)
                return false;
            return true;
        }

        public static string SanitizeWmiValue(string value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;
            return value
                .Replace("\\", "\\\\")
                .Replace("'", "\\'")
                .Replace("\"", "\\\"");
        }

        public static bool IsValidWmiName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;
            return SafeWmiNameRegex.IsMatch(name);
        }

        public static bool IsValidRegistryPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;
            return SafeRegistryPathRegex.IsMatch(path);
        }

        public static bool IsValidFilePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;
            try
            {
                var fullPath = Path.GetFullPath(path);
                var invalidChars = Path.GetInvalidPathChars();
                foreach (var c in invalidChars)
                {
                    if (path.Contains(c))
                        return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static string SanitizeUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return string.Empty;
            var sanitized = username.Trim();
            if (sanitized.Length > 256)
                sanitized = sanitized[..256];
            if (sanitized.Contains('\0') || sanitized.Contains('\r') || sanitized.Contains('\n'))
                return string.Empty;
            return sanitized;
        }

        public static string SanitizeDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return string.Empty;
            var sanitized = domain.Trim();
            if (sanitized.Length > 256)
                sanitized = sanitized[..256];
            var domainRegex = new Regex(@"^[a-zA-Z0-9\.\-]+$");
            if (!domainRegex.IsMatch(sanitized))
                return string.Empty;
            return sanitized;
        }

        public static bool IsProcessIdValid(int processId)
        {
            return processId > 0 && processId <= 65535;
        }

        public static bool IsCriticalProcess(string processName)
        {
            if (string.IsNullOrEmpty(processName))
                return true;
            var critical = new[]
            {
                "system", "smss", "csrss", "wininit", "services",
                "lsass", "svchost", "winlogon", "fontdrvhost", "dwm",
                "audiodg", "registry", "memory compression", "idle"
            };
            var lower = processName.ToLower();
            foreach (var c in critical)
            {
                if (lower.Equals(c, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static uint IpToUint(string ip)
        {
            var p = ip.Split('.');
            if (p.Length != 4)
                return 0;
            if (!byte.TryParse(p[0], out byte a) ||
                !byte.TryParse(p[1], out byte b) ||
                !byte.TryParse(p[2], out byte c) ||
                !byte.TryParse(p[3], out byte d))
                return 0;
            return (uint)(a << 24 | b << 16 | c << 8 | d);
        }
    }
}