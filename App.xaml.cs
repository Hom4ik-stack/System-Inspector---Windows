using System.Windows;
using SecurityShield.Services;
using SecurityShield.ViewModels;

namespace SecurityShield
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            var vm = new MainViewModel(
                new SystemInfoService(),
                new DriverService(),
                new DeviceService(),
                new SecurityService(),
                new ReportService(),
                new NetworkScanService());
            var w = new MainWindow { DataContext = vm };
            w.Show();
        }
    }
}