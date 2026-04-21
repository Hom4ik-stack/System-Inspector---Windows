using CommunityToolkit.Mvvm.ComponentModel;

namespace SecurityShield.Models
{
    public partial class DriveInfoModel : ObservableObject
    {
        [ObservableProperty] private string _name = string.Empty;
        [ObservableProperty] private long _totalSpace;
        [ObservableProperty] private long _freeSpace;
        [ObservableProperty] private string _driveType = string.Empty;
        [ObservableProperty] private string _driveFormat = string.Empty;

        public long UsedSpace => TotalSpace - FreeSpace;
        public double UsedPercentage => TotalSpace == 0 ? 0 : (1 - (double)FreeSpace / TotalSpace) * 100;

        public string TotalSpaceFormatted => FormatBytes(TotalSpace);
        public string FreeSpaceFormatted => FormatBytes(FreeSpace);
        public string UsedSpaceFormatted => FormatBytes(UsedSpace);

        private static string FormatBytes(long bytes)
            => bytes > 0 ? $"{bytes / 1024.0 / 1024.0 / 1024.0:F2} GB" : "N/A";
    }
}