using CommunityToolkit.Mvvm.ComponentModel;

namespace SecurityShield.Models
{
    public partial class NetworkHost : ObservableObject
    {
        [ObservableProperty] private string _ipAddress = string.Empty;
        [ObservableProperty] private string _hostName = string.Empty;
        [ObservableProperty] private bool _isOnline;
        [ObservableProperty] private string _status = "Неизвестно";
        [ObservableProperty] private int _securityScore = -1;
        [ObservableProperty] private string _osVersion = "Неизвестно";
        [ObservableProperty] private bool _isScanning;
        [ObservableProperty] private bool _isSelected;
        [ObservableProperty] private string _scanDetails = string.Empty;

        public SecurityScanResult? ScanResult { get; set; }

        public string ScoreDisplay => SecurityScore < 0 ? "—" : SecurityScore.ToString();

        public string ScoreCategory => SecurityScore < 0 ? "None"
            : SecurityScore >= 80 ? "Good"
            : SecurityScore >= 50 ? "Medium" : "Bad";

        partial void OnSecurityScoreChanged(int value)
        {
            OnPropertyChanged(nameof(ScoreCategory));
            OnPropertyChanged(nameof(ScoreDisplay));
        }
    }
}