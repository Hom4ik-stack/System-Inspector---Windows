using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveCharts;
using LiveCharts.Wpf;
using Microsoft.Win32;
using SecurityShield.Models;
using SecurityShield.Services;
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace SecurityShield.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        private readonly ISystemInfoService _sys;
        private readonly IDriverService _drv;
        private readonly IDeviceService _dev;
        private readonly ISecurityService _sec;
        private readonly IReportService _rpt;
        private readonly INetworkScanService _net;
        private CancellationTokenSource? _scanCts;

        [ObservableProperty] private SystemInfo _systemInfo = new();
        [ObservableProperty] private string _currentTime = string.Empty;
        [ObservableProperty] private SeriesCollection _cpuSeries = new();
        [ObservableProperty] private ObservableCollection<ProcessInfo> _processes = new();
        [ObservableProperty] private ObservableCollection<DriveInfoModel> _drives = new();
        [ObservableProperty] private ObservableCollection<DriverInfo> _drivers = new();
        [ObservableProperty] private ObservableCollection<DeviceInfo> _devices = new();
        [ObservableProperty] private ObservableCollection<SecurityCheck> _securityChecks = new();
        [ObservableProperty] private ObservableCollection<SecurityThreat> _threats = new();
        [ObservableProperty] private AntivirusInfo _antivirusInfo = new();
        [ObservableProperty] private DefenderStatus _currentDefenderStatus = new();
        [ObservableProperty] private ObservableCollection<SoftwareInfo> _installedSoftware = new();
        [ObservableProperty] private ObservableCollection<StartupProgram> _startupPrograms = new();
        [ObservableProperty] private ObservableCollection<NetworkConnectionInfo> _networkConnections = new();
        [ObservableProperty] private SecurityScanResult _securityScanResult = new();
        [ObservableProperty] private string _driverStatus = "Загрузка...";
        [ObservableProperty] private string _deviceStatus = "Загрузка...";
        [ObservableProperty] private string _quickScanStatus = "Выполняется...";
        [ObservableProperty] private bool _isQuickScanInProgress;
        [ObservableProperty] private int _totalProcessesCount;

        [ObservableProperty] private ObservableCollection<NetworkHost> _networkHosts = new();
        [ObservableProperty] private string _startIp = "192.168.1.1";
        [ObservableProperty] private string _endIp = "192.168.1.254";
        [ObservableProperty] private string _networkUsername = string.Empty;
        [ObservableProperty] private string _networkPassword = string.Empty;
        [ObservableProperty] private string _networkDomain = string.Empty;
        [ObservableProperty] private bool _isNetworkScanning;
        [ObservableProperty] private string _networkScanStatus = "Готов к сканированию";
        [ObservableProperty] private int _totalHostsCount;
        [ObservableProperty] private int _onlineHostsCount;
        [ObservableProperty] private int _auditedHostsCount;
        [ObservableProperty] private int _vulnerableHostsCount;

        public MainViewModel(
            ISystemInfoService sys, IDriverService drv, IDeviceService dev,
            ISecurityService sec, IReportService rpt, INetworkScanService net)
        {
            _sys = sys; _drv = drv; _dev = dev; _sec = sec; _rpt = rpt; _net = net;

            var (s, e) = _net.DetectLocalSubnet();
            StartIp = s; EndIp = e;

            InitTimers();
            InitChart();

            if (_dev is DeviceService ds)
                ds.DeviceListChanged += (_, __) => _ = LoadDevices();

            _ = Task.Run(LoadAllOnStartup);
        }

        private async Task LoadAllOnStartup()
        {
            try { SystemInfo = _sys.GetDetailedSystemInfo(); } catch { }
            await Task.WhenAll(
                Task.Run(() => RefreshDrives()),
                Task.Run(() => RefreshProcesses()),
                Task.Run(() => LoadDevicesInternal()),
                Task.Run(() => LoadDriversInternal()),
                Task.Run(() => LoadAntivirusInfoInternal()),
                Task.Run(() => LoadInstalledSoftwareInternal()),
                Task.Run(() => LoadStartupProgramsInternal()),
                Task.Run(() => LoadNetworkConnectionsInternal()),
                Task.Run(() => RunSecurityScanInternal())
            );
        }

        private void InitTimers()
        {
            var t1 = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            t1.Tick += (_, __) => CurrentTime = DateTime.Now.ToString("HH:mm:ss  dd.MM.yyyy");
            t1.Start();

            var t2 = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            t2.Tick += (_, __) => UpdateCpu();
            t2.Start();

            var t3 = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            t3.Tick += (_, __) => RefreshProcesses();
            t3.Start();

            var t4 = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
            t4.Tick += (_, __) => RefreshDrives();
            t4.Start();
        }

        private void InitChart()
        {
            CpuSeries = new SeriesCollection
            {
                new LineSeries
                {
                    Values = new ChartValues<double>(Enumerable.Repeat(0.0, 30)),
                    PointGeometry = null,
                    Fill = System.Windows.Media.Brushes.Transparent,
                    Stroke = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(59, 130, 246)),
                    StrokeThickness = 2
                }
            };
        }

        private void UpdateCpu()
        {
            try
            {
                var v = _sys.GetCurrentCpuUsage();
                if (CpuSeries.Count > 0 && CpuSeries[0]?.Values != null)
                {
                    CpuSeries[0].Values.Add(v);
                    if (CpuSeries[0].Values.Count > 30) CpuSeries[0].Values.RemoveAt(0);
                }
            }
            catch { }
        }

        private void RefreshProcesses()
        {
            try
            {
                var list = _sys.GetRunningProcesses();
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    Processes.Clear();
                    foreach (var p in list) Processes.Add(p);
                    TotalProcessesCount = Processes.Count;
                });
            }
            catch { }
        }

        private void RefreshDrives()
        {
            try
            {
                var list = _sys.GetDriveInfo();
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    Drives.Clear();
                    foreach (var d in list) Drives.Add(d);
                });
            }
            catch { }
        }

        private void LoadDevicesInternal()
        {
            try
            {
                var list = _dev.GetConnectedDevices();
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    Devices.Clear();
                    foreach (var d in list) Devices.Add(d);
                    DeviceStatus = $"Устройств: {Devices.Count}";
                });
            }
            catch { }
        }

        private void LoadDriversInternal()
        {
            try
            {
                var list = _drv.GetInstalledDrivers();
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    Drivers.Clear();
                    foreach (var d in list) Drivers.Add(d);
                    DriverStatus = $"Загружено: {Drivers.Count}";
                });
            }
            catch { }
        }

        private void LoadAntivirusInfoInternal()
        {
            try
            {
                var av = _sec.GetInstalledAntivirus();
                var def = _sec.GetDefenderStatus();
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    AntivirusInfo = av;
                    CurrentDefenderStatus = def;
                });
            }
            catch { }
        }

        private void LoadInstalledSoftwareInternal()
        {
            try
            {
                var sw = _sys.GetInstalledSoftware();
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    InstalledSoftware.Clear();
                    foreach (var s in sw) InstalledSoftware.Add(s);
                });
            }
            catch { }
        }

        private void LoadStartupProgramsInternal()
        {
            try
            {
                var p = _sys.GetStartupPrograms();
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    StartupPrograms.Clear();
                    foreach (var x in p) StartupPrograms.Add(x);
                });
            }
            catch { }
        }

        private void LoadNetworkConnectionsInternal()
        {
            try
            {
                var n = _sys.GetActiveNetworkConnections();
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    NetworkConnections.Clear();
                    foreach (var x in n) NetworkConnections.Add(x);
                });
            }
            catch { }
        }

        private void RunSecurityScanInternal()
        {
            try
            {
                var r = _sec.PerformComprehensiveSecurityScan();
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    SecurityScanResult = r;
                    SecurityChecks.Clear();
                    foreach (var c in r.SecurityChecks
                        .OrderByDescending(c => c.IsCritical)
                        .ThenBy(c => c.Status.Contains("OK")))
                        SecurityChecks.Add(c);
                    Threats.Clear();
                    foreach (var t in r.Threats) Threats.Add(t);
                    QuickScanStatus = $"Угроз: {r.TotalThreats}, Предупреждений: {r.Warnings}";
                });
            }
            catch
            {
                Application.Current?.Dispatcher.Invoke(() =>
                    QuickScanStatus = "Ошибка сканирования");
            }
        }

        private void UpdateNetworkCounters()
        {
            TotalHostsCount = NetworkHosts.Count;
            OnlineHostsCount = NetworkHosts.Count(h => h.IsOnline);
            AuditedHostsCount = NetworkHosts.Count(h => h.SecurityScore >= 0);
            VulnerableHostsCount = NetworkHosts.Count(h => h.SecurityScore >= 0 && h.SecurityScore < 70);
        }

        [RelayCommand]
        private async Task KillProcess(ProcessInfo? p)
        {
            if (p == null || !p.IsUserProcess) return;

            if (p.IsSelfProcess)
            {
                if (MessageBox.Show("Закрыть программу?", "Подтверждение",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                    Application.Current.Shutdown();
                return;
            }

            if (MessageBox.Show($"Завершить {p.Name} (PID {p.Id})?", "Подтверждение",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

            if (_sys.KillProcess(p.Id))
            {
                var item = Processes.FirstOrDefault(x => x.Id == p.Id);
                if (item != null) Processes.Remove(item);
                TotalProcessesCount = Processes.Count;
            }
            else MessageBox.Show("Не удалось завершить.", "Ошибка",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }

        [RelayCommand]
        private void OpenDriveInExplorer(DriveInfoModel? d)
        {
            if (d == null) return;
            try { Process.Start(new ProcessStartInfo { FileName = d.Name, UseShellExecute = true }); }
            catch { }
        }

        [RelayCommand]
        private async Task LoadDrivers()
        {
            DriverStatus = "Загрузка...";
            await Task.Run(() => LoadDriversInternal());
        }

        [RelayCommand]
        private async Task CheckDriverUpdates()
        {
            DriverStatus = "Проверка...";
            var outdated = await Task.Run(() => _drv.CheckOutdatedDrivers());
            Application.Current.Dispatcher.Invoke(() =>
            {
                foreach (var d in Drivers)
                {
                    var m = outdated.FirstOrDefault(o => o.Name == d.Name);
                    d.IsOutdated = m != null;
                    d.UpdateStatus = m != null ? "Требуется обновление" : "Актуальный";
                    d.RiskLevel = m?.RiskLevel ?? "Низкий";
                }
                DriverStatus = outdated.Count > 0
                    ? $"Устаревших: {outdated.Count}" : "Все актуальны";
            });
        }

        [RelayCommand]
        private async Task LoadDevices()
        {
            DeviceStatus = "Сканирование...";
            await Task.Run(() => LoadDevicesInternal());
        }

        [RelayCommand]
        private void OpenDeviceManager()
        {
            try { _dev.OpenDeviceSettings(""); }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
        }

        [RelayCommand]
        private void EjectDevice(DeviceInfo? d)
        {
            if (d?.IsRemovable != true) { MessageBox.Show("Устройство не съёмное."); return; }
            try { _dev.EjectDevice(d.DeviceID); DeviceStatus = $"{d.Name} — извлечение"; }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
        }

        [RelayCommand]
        private async Task PerformComprehensiveSecurityScan()
        {
            if (IsQuickScanInProgress) return;
            IsQuickScanInProgress = true;
            QuickScanStatus = "Анализ...";
            await Task.Run(() => RunSecurityScanInternal());
            IsQuickScanInProgress = false;
        }

        [RelayCommand]
        private async Task RefreshAntivirusInfo() =>
            await Task.Run(() => LoadAntivirusInfoInternal());

        [RelayCommand]
        private void OpenDefenderSettings()
        {
            try { _sec.OpenWindowsSecurity(); }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
        }

        [RelayCommand]
        private void EnableDefenderProtection()
        {
            var ok = _sec.EnableDefenderProtection();
            MessageBox.Show(ok ? "Защита включена." : "Не удалось включить.",
                ok ? "OK" : "Ошибка");
            if (ok) _ = Task.Run(() => LoadAntivirusInfoInternal());
        }

        [RelayCommand]
        private void OpenAntivirus()
        {
            try { _sec.OpenAntivirusUI(); }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
        }

        [RelayCommand]
        private void UpdateProcessesImmediately() => RefreshProcesses();

        [RelayCommand]
        private async Task LoadInstalledSoftware() =>
            await Task.Run(() => LoadInstalledSoftwareInternal());

        [RelayCommand]
        private async Task LoadStartupPrograms() =>
            await Task.Run(() => LoadStartupProgramsInternal());

        [RelayCommand]
        private async Task LoadNetworkConnections() =>
            await Task.Run(() => LoadNetworkConnectionsInternal());

        [RelayCommand]
        private void OpenStartupSettings()
        {
            try { Process.Start(new ProcessStartInfo { FileName = "ms-settings:startupapps", UseShellExecute = true }); }
            catch { try { Process.Start("shell:startup"); } catch { } }
        }

        [RelayCommand]
        private async Task DiscoverHosts()
        {
            if (IsNetworkScanning) return;

            if (!Helpers.SecurityHelper.IsValidIpAddress(StartIp)
                || !Helpers.SecurityHelper.IsValidIpAddress(EndIp))
            {
                MessageBox.Show(
                    "Введите корректные IP-адреса.",
                    "Ошибка ввода",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            if (!Helpers.SecurityHelper.IsValidIpRange(StartIp, EndIp))
            {
                MessageBox.Show(
                    "Некорректный диапазон IP (максимум 1024 адреса).",
                    "Ошибка ввода",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            IsNetworkScanning = true;
            NetworkScanStatus = "Обнаружение хостов...";
            NetworkHosts.Clear();
            _scanCts?.Cancel();
            _scanCts = new CancellationTokenSource();

            try
            {
                var hosts = await _net.DiscoverHostsAsync(
                    StartIp, EndIp, _scanCts.Token);
                Application.Current.Dispatcher.Invoke(() =>
                {
                    foreach (var h in hosts.Where(h => h.IsOnline))
                        NetworkHosts.Add(h);
                    UpdateNetworkCounters();
                    NetworkScanStatus =
                        $"Найдено: {OnlineHostsCount} онлайн " +
                        $"из {hosts.Count} адресов";
                });
            }
            catch (OperationCanceledException)
            {
                NetworkScanStatus = "Отменено";
            }
            catch (Exception ex)
            {
                NetworkScanStatus = $"Ошибка: {ex.Message}";
            }
            finally { IsNetworkScanning = false; }
        }

        [RelayCommand]
        private async Task AuditSelectedHosts()
        {
            var selected = NetworkHosts
                .Where(h => h.IsSelected && h.IsOnline)
                .ToList();

            if (!selected.Any())
            {
                MessageBox.Show(
                    "Выберите хосты для аудита галочками.",
                    "Внимание",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            var sanitizedUser =
                Helpers.SecurityHelper.SanitizeUsername(NetworkUsername);
            if (string.IsNullOrEmpty(sanitizedUser))
            {
                MessageBox.Show(
                    "Введите корректный логин администратора.",
                    "Внимание",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            if (string.IsNullOrEmpty(NetworkPassword))
            {
                MessageBox.Show(
                    "Введите пароль.",
                    "Внимание",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            IsNetworkScanning = true;
            int done = 0;

            foreach (var host in selected)
            {
                if (!Helpers.SecurityHelper.IsValidIpAddress(host.IpAddress))
                    continue;

                host.IsScanning = true;
                host.Status = "Аудит...";
                NetworkScanStatus =
                    $"Аудит {++done}/{selected.Count}: {host.IpAddress}";

                try
                {
                    var result = await _net.RemoteAuditAsync(
                        host.IpAddress,
                        sanitizedUser,
                        NetworkPassword,
                        Helpers.SecurityHelper.SanitizeDomain(NetworkDomain));

                    host.ScanResult = result;
                    host.SecurityScore =
                        _net.CalculateSecurityScore(result);
                    host.Status = result.OverallStatus;
                    host.ScanDetails =
                        $"Угроз: {result.TotalThreats}, " +
                        $"Критич: {result.CriticalIssues}";

                    var osCheck = result.SecurityChecks
                        .FirstOrDefault(
                            c => c.CheckName.Contains("Операционная"));
                    if (osCheck != null) host.OsVersion = osCheck.Details;
                }
                catch (Exception ex)
                {
                    host.Status = "Ошибка";
                    host.ScanDetails = ex.Message;
                    host.SecurityScore = 0;
                }
                finally { host.IsScanning = false; }
            }

            Application.Current.Dispatcher.Invoke(UpdateNetworkCounters);
            IsNetworkScanning = false;
            NetworkScanStatus = $"Аудит завершён — проверено: {done}";
        }

        [RelayCommand]
        private void SelectAllHosts()
        {
            foreach (var h in NetworkHosts) h.IsSelected = true;
        }

        [RelayCommand]
        private void DeselectAllHosts()
        {
            foreach (var h in NetworkHosts) h.IsSelected = false;
        }

     

        [RelayCommand]
        private async Task GenerateReport()
        {
            var optWin = new ReportOptionsWindow(isNetworkReport: false);
            optWin.Owner = Application.Current.MainWindow;
            if (optWin.ShowDialog() != true)
                return;

            var options = optWin.Options;

            var data = new ReportData
            {
                SystemInfo = SystemInfo,
                TopProcesses = Processes.Take(10).ToList(),
                Drives = Drives.ToList(),
                Drivers = Drivers.ToList(),
                Devices = Devices.ToList(),
                NetworkHosts = NetworkHosts.ToList(),
                ReportDate = DateTime.Now.ToString("dd.MM.yyyy HH:mm"),
                SecurityChecks = SecurityScanResult.SecurityChecks ?? new(),
                Threats = SecurityScanResult.Threats ?? new(),
                OverallSecurityStatus = SecurityScanResult.OverallStatus,
                CriticalIssuesCount = SecurityScanResult.CriticalIssues,
                TotalSecurityIssues = SecurityScanResult.TotalThreats
                                      + SecurityScanResult.CriticalIssues
            };

            var dlg = new SaveFileDialog
            {
                Filter = "HTML (*.html)|*.html",
                DefaultExt = ".html",
                FileName = $"SystemReport_{DateTime.Now:yyyyMMdd_HHmm}"
            };
            if (dlg.ShowDialog() == true)
            {
                var ok = await _rpt.ExportReportToFileAsync(
                    dlg.FileName, data, options);
                if (ok)
                {
                    if (MessageBox.Show(
                        $"Сохранено: {dlg.FileName}\nОткрыть?",
                        "Отчёт",
                        MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                        try
                        {
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = dlg.FileName,
                                UseShellExecute = true
                            });
                        }
                        catch { }
                }
                else MessageBox.Show("Ошибка сохранения.");
            }
        }

        [RelayCommand]
        private async Task GenerateNetworkReport()
        {
            var hosts = NetworkHosts.ToList();
            if (!hosts.Any())
            {
                MessageBox.Show("Сначала выполните сканирование сети.");
                return;
            }

            var optWin = new ReportOptionsWindow(isNetworkReport: true);
            optWin.Owner = Application.Current.MainWindow;
            if (optWin.ShowDialog() != true)
                return;

            var options = optWin.Options;

            var dlg = new SaveFileDialog
            {
                Filter = "HTML (*.html)|*.html",
                DefaultExt = ".html",
                FileName = $"NetworkAudit_{DateTime.Now:yyyyMMdd_HHmm}"
            };
            if (dlg.ShowDialog() == true)
            {
                var ok = await _rpt.ExportNetworkReportAsync(
                    dlg.FileName, hosts, options);
                if (ok)
                {
                    if (MessageBox.Show(
                        $"Сохранено: {dlg.FileName}\nОткрыть?",
                        "Отчёт",
                        MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                        try
                        {
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = dlg.FileName,
                                UseShellExecute = true
                            });
                        }
                        catch { }
                }
                else MessageBox.Show("Ошибка сохранения.");
            }
        }
        [RelayCommand]
        private void ShowAbout()
        {
            MessageBox.Show(
                "System Inspector\n\n" +
                "Дипломный проект - инструмент сетевого и системного администратора:\n\n" +
                "• Мониторинг системы и процессов\n" +
                "• Безагентный аудит безопасности по сети (WMI)\n" +
                "• Обнаружение хостов и оценка защищённости\n" +
                "• Массовое устранение уязвимостей\n" +
                "• Анализ сетевых подключений\n" +
                "• Контроль оборудования и драйверов\n" +
                "• Генерация HTML-отчётов",
                "О программе");
        }
    }
}