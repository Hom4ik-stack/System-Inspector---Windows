using CommunityToolkit.Mvvm.ComponentModel;

namespace SecurityShield.Models
{
    public partial class DriverInfo : ObservableObject
    {
        [ObservableProperty] private string _name = string.Empty;
        [ObservableProperty] private string _description = string.Empty;
        [ObservableProperty] private string _version = string.Empty;
        [ObservableProperty] private string _date = string.Empty;
        [ObservableProperty] private string _manufacturer = string.Empty;
        [ObservableProperty] private bool _isOutdated;
        [ObservableProperty] private string _updateStatus = "Не проверен";
        [ObservableProperty] private string _class = string.Empty;
        [ObservableProperty] private string _riskLevel = "Низкий";
        [ObservableProperty] private string _digitalSignature = "Не проверена";
    }
}