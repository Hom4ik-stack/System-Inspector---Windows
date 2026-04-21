using CommunityToolkit.Mvvm.ComponentModel;

namespace SecurityShield.Models
{
    public partial class NetworkConnectionInfo : ObservableObject
    {
        [ObservableProperty] private string _localAddress = string.Empty;
        [ObservableProperty] private int _localPort;
        [ObservableProperty] private string _remoteAddress = string.Empty;
        [ObservableProperty] private int _remotePort;
        [ObservableProperty] private string _state = string.Empty;
        [ObservableProperty] private string _processName = "N/A";
        [ObservableProperty] private int _processId;
        [ObservableProperty] private string _remotePortDescription = string.Empty;
        [ObservableProperty] private string _connectionPurpose = string.Empty;
    }
}