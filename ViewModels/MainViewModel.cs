using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveCharts;
using LiveCharts.Wpf;
using Microsoft.Win32;
using SecurityShield.Models;
using SecurityShield.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
namespace SecurityShield.ViewModels


{
    public partial class MainViewModel : ObservableObject
    {
        // Сервисы
        private readonly ISystemInfoService _systemInfoService;
        private readonly IDriverService _driverService;
        private readonly IDeviceService _deviceService;
        private readonly ISecurityService _securityService;
        private readonly IReportService _reportService;

        // Таймеры
        private DispatcherTimer _cpuTimer = new DispatcherTimer();
        private DispatcherTimer _processTimer = new DispatcherTimer();
        private DispatcherTimer _driveTimer = new DispatcherTimer();
        private DispatcherTimer _timeTimer = new DispatcherTimer();

        // Свойства 
        [ObservableProperty] private SystemInfo _systemInfo = new SystemInfo();
        [ObservableProperty] private string _currentTime = string.Empty;
        [ObservableProperty] private SeriesCollection _cpuSeries = new SeriesCollection();

        [ObservableProperty] private ObservableCollection<ProcessInfo> _processes = new ObservableCollection<ProcessInfo>();
        [ObservableProperty] private ObservableCollection<DriveInfoModel> _drives = new ObservableCollection<DriveInfoModel>();
        [ObservableProperty] private ObservableCollection<DriverInfo> _drivers = new ObservableCollection<DriverInfo>();
        [ObservableProperty] private ObservableCollection<DeviceInfo> _devices = new ObservableCollection<DeviceInfo>();
       
        [ObservableProperty] private ObservableCollection<SecurityVulnerability> _vulnerabilities = new ObservableCollection<SecurityVulnerability>();


        // Для безопасности
        [ObservableProperty] private ObservableCollection<SecurityCheck> _securityChecks = new ObservableCollection<SecurityCheck>();
        [ObservableProperty] private ObservableCollection<SecurityThreat> _threats = new ObservableCollection<SecurityThreat>();
        [ObservableProperty] private ObservableCollection<SecurityEvent> _securityEvents = new ObservableCollection<SecurityEvent>();

        [ObservableProperty] private ObservableCollection<DeviceInfo> _vulnerableDevices = new ObservableCollection<DeviceInfo>();
        [ObservableProperty] private ObservableCollection<DeviceInfo> _newlyConnectedDevices = new ObservableCollection<DeviceInfo>();

        [ObservableProperty] private DefenderStatus _defenderStatus = new DefenderStatus();
        [ObservableProperty] private AntivirusInfo _antivirusInfo = new AntivirusInfo();

        [ObservableProperty] private ObservableCollection<SoftwareInfo> _installedSoftware = new ObservableCollection<SoftwareInfo>();
        [ObservableProperty] private ObservableCollection<StartupProgram> _startupPrograms = new ObservableCollection<StartupProgram>();
        [ObservableProperty] private ObservableCollection<NetworkConnectionInfo> _networkConnections = new ObservableCollection<NetworkConnectionInfo>();

        // Инициализируем, чтобы убрать warning CS8618
        [ObservableProperty] private SecurityScanResult _securityScanResult = new SecurityScanResult();

        // Статусы UI
        [ObservableProperty] private string _scanStatus = "Готов к проверке безопасности";
        [ObservableProperty] private string _driverStatus = "Нажмите 'Проверить драйверы' для анализа";
        [ObservableProperty] private string _deviceStatus = "Мониторинг устройств активен";
        [ObservableProperty] private string _defenderScanStatus = "Готов к сканированию";
        [ObservableProperty] private string _quickScanStatus = "Готов к проверке";

        // Флаги
        [ObservableProperty] private bool _isScanning;
        [ObservableProperty] private bool _isDefenderScanInProgress;
        [ObservableProperty] private bool _isQuickScanInProgress;
        [ObservableProperty] private int _defenderScanProgress;
        [ObservableProperty] private bool _showOnlyVulnerableDevices;

        [ObservableProperty] private int _totalProcessesCount;
        [ObservableProperty] private string _selectedScanType = "Быстрая проверка";

        // Фильтрация проверок безопасности
        public enum SecurityFilterType { All, Risks, Safe }
        [ObservableProperty] private SecurityFilterType _currentSecurityFilter = SecurityFilterType.All;

        // Коллекция для отображения в UI (фильтрованная)
        public IEnumerable<SecurityCheck> DisplayedSecurityChecks
        {
            get
            {
                if (SecurityChecks == null) return Enumerable.Empty<SecurityCheck>();

                return CurrentSecurityFilter switch
                {
                    SecurityFilterType.Risks => SecurityChecks.Where(c => !c.Status.Contains("OK") && !c.Status.Contains("Защищено")),
                    SecurityFilterType.Safe => SecurityChecks.Where(c => c.Status.Contains("OK") || c.Status.Contains("Защищено")),
                    _ => SecurityChecks
                };
            }
        }

        public List<string> ScanTypes { get; } = new List<string>
        { "Быстрая проверка", "Полная проверка", "Проверка автостарта", "Проверка сети" };

        public ObservableCollection<DeviceInfo> DisplayedDevices => ShowOnlyVulnerableDevices
            ? VulnerableDevices
            : Devices;

        public MainViewModel(
            ISystemInfoService systemInfoService,
            IDriverService driverService,
            IDeviceService deviceService,
            ISecurityService securityService,
            IReportService reportService)
        {
            _systemInfoService = systemInfoService;
            _driverService = driverService;
            _deviceService = deviceService;
            _securityService = securityService;
            _reportService = reportService;

            InitializeTimers();
            InitializeCharts();

 
            if (_deviceService is DeviceService ds)
            {
                ds.DeviceListChanged += (s, e) => _ = LoadDevices(isAutoUpdate: true);
            }

      
            _ = Task.Run(() => LoadInitialData());
            _ = Task.Run(() => LoadDevices());
            _ = Task.Run(() => LoadDefenderStatus());
            _ = Task.Run(() => LoadAntivirusInfo());
            _ = Task.Run(() => LoadInstalledSoftware());
            _ = Task.Run(() => LoadStartupPrograms());
            _ = Task.Run(() => LoadNetworkConnections());
        }

        private void InitializeTimers()
        {
            _timeTimer.Interval = TimeSpan.FromSeconds(1);
            _timeTimer.Tick += (s, e) => CurrentTime = DateTime.Now.ToString("HH:mm:ss");
            _timeTimer.Start();

            _cpuTimer.Interval = TimeSpan.FromSeconds(1);
            _cpuTimer.Tick += (s, e) => UpdateCpuData();
            _cpuTimer.Start();

            _processTimer.Interval = TimeSpan.FromSeconds(3);
            _processTimer.Tick += (s, e) => UpdateProcessesData();
            _processTimer.Start();

            _driveTimer.Interval = TimeSpan.FromSeconds(5);
            _driveTimer.Tick += (s, e) => UpdateDriveData();
            _driveTimer.Start();
        }
 

      
        private void LoadInitialData()
        {
            try
            {
                SystemInfo = _systemInfoService.GetDetailedSystemInfo();
                UpdateDriveData();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"LoadInitialData Error: {ex.Message}");
            }
        }
        private void InitializeCharts()
        {
            CpuSeries = new SeriesCollection
        {
            new LineSeries
            {
                Title = "Загрузка ЦП",
                Values = new ChartValues<double>(),
                PointGeometry = null,
                Fill = System.Windows.Media.Brushes.Transparent
            }
        };
            for (int i = 0; i < 20; i++)
            {
                CpuSeries[0].Values.Add(0.0);
            }
        }

        private void UpdateCpuData()
        {
            try
            {
                var cpuUsage = _systemInfoService.GetCurrentCpuUsage();
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (CpuSeries.Count > 0 && CpuSeries[0] != null)
                    {
                        CpuSeries[0].Values.Add(cpuUsage);
                        if (CpuSeries[0].Values.Count > 20)
                            CpuSeries[0].Values.RemoveAt(0);
                    }
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"UpdateCpuData Error: {ex.Message}");
            }
        }
        private async void UpdateProcessesData()
        {
            try
            {
                var procs = await Task.Run(() => _systemInfoService.GetRunningProcesses());
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Processes.Clear();
                    foreach (var p in procs) Processes.Add(p);
                    TotalProcessesCount = Processes.Count;
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"UpdateProcessesData Error: {ex.Message}");
            }
        }
        [RelayCommand]
        private async Task KillProcess(ProcessInfo process)
        {
            if (process == null) return;
            try
            {
                if (!process.IsUserProcess)
                {
                    MessageBox.Show(
                        $"Процесс '{process.Name}' является системным и не может быть завершен.\n\n" +
                        "Завершение системных процессов может привести к нестабильной работе системы или её зависанию!",
                        "Системный процесс",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }
                var result = MessageBox.Show(
                    $"Вы уверены, что хотите завершить процесс?\n\n" +
                    $"Имя: {process.Name}\n" +
                    $"ID: {process.Id}\n" +
                    $"ЦП: {process.Cpu:F1}%\n" +
                    $"Память: {process.MemoryMB:F1} МБ\n" +
                    $"Путь: {process.ProcessPath}\n\n" +
                    $" ⚠ ️ Убедитесь, что это не системный процесс!",
                    "Подтверждение завершения процесса",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    bool success = _systemInfoService.KillProcess(process.Id);
                    if (success)
                    {
                     
                        var processToRemove = Processes.FirstOrDefault(p => p.Id == process.Id);
                        if (processToRemove != null) Processes.Remove(processToRemove);


                        TotalProcessesCount = Processes.Count;

                        MessageBox.Show(
                            $"Процесс '{process.Name}' успешно завершен.",
                            "Процесс завершен",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                        await Task.Delay(1000);
                        UpdateProcessesData(); 
                    }
                    else
                    {
                        MessageBox.Show(
                            $"Не удалось завершить процесс '{process.Name}'.\n" +
                            "Возможно, процесс уже завершен или недостаточно прав.",
                            "Ошибка",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Ошибка при завершении процесса: {ex.Message}",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        private async void UpdateDriveData()
        {
            try
            {
                await Task.Run(() =>
                {
                    var newDrives = _systemInfoService.GetDriveInfo();
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        Drives.Clear();
                        foreach (var drive in newDrives)
                        {
                            Drives.Add(drive);
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка UpdateDriveData: {ex.Message}");
            }
        }

        [RelayCommand]
        private void OpenDriveInExplorer(DriveInfoModel drive)
        {
            if (drive == null || string.IsNullOrEmpty(drive.Name)) return;
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = drive.Name, 
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось открыть {drive.Name}: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        [RelayCommand]
        private async Task LoadDrivers()
        {
            try
            {
                DriverStatus = "Получение списка драйверов...";
                await Task.Run(() =>
                {
                    var driverList = _driverService.GetInstalledDrivers();
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        Drivers.Clear();
                        foreach (var driver in driverList)
                        {
                            Drivers.Add(driver);
                        }
                        DriverStatus = $"Загружено {Drivers.Count} драйверов";
                    });
                });
            }
            catch (Exception ex)
            {
                DriverStatus = "Ошибка загрузки драйверов";
                Debug.WriteLine($"LoadDrivers Error: {ex.Message}");
            }
        }

      
        [RelayCommand]
        private async Task CheckDriverUpdates()
        {
            try
            {
                DriverStatus = "Проверка обновлений драйверов...";
                await Task.Run(() =>
                {
                    var outdatedDrivers = _driverService.CheckOutdatedDrivers();
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        foreach (var driver in Drivers)
                        {
                            var outdatedDriver = outdatedDrivers.FirstOrDefault(d => d.Name == driver.Name);
                            if (outdatedDriver != null)
                            {
                                driver.IsOutdated = true;
                                driver.UpdateStatus = "Требуется обновление";
                                driver.RiskLevel = outdatedDriver.RiskLevel;
                            }
                            else
                            {
                                driver.IsOutdated = false;
                                driver.UpdateStatus = "Актуальный";
                                driver.RiskLevel = "Низкий";
                            }
                        }
                        DriverStatus = outdatedDrivers.Count > 0 ? $"Устаревших: {outdatedDrivers.Count}" : "Все драйверы в порядке";

                        if ( outdatedDrivers.Count > 0)
                            MessageBox.Show($"Найдено устаревших драйверов: {outdatedDrivers.Count}. Проверьте список (подсвечены красным).", "Драйверы", MessageBoxButton.OK, MessageBoxImage.Warning);
                    });
                });
            }
            catch (Exception ex)
            {
                DriverStatus = "Ошибка проверки драйверов";
                Debug.WriteLine($"CheckDriverUpdates Error: {ex.Message}");
            }
        }



        [RelayCommand]
        private void OpenDeviceManager()
        {
            try
            {
                // Вызываем OpenDeviceSettings без ID, чтобы просто открыть devmgmt.msc
                _deviceService.OpenDeviceSettings(string.Empty);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось открыть Диспетчер устройств: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


        private void OnDeviceListChanged(object? sender, EventArgs e)
        {
            // Запускаем обновление в фоне, чтобы не фризить UI
            Task.Run(() => LoadDevices(isAutoUpdate: true));
        }

        [RelayCommand]
        private async Task LoadDevices(bool isAutoUpdate = false)
        {
            try
            {
                if (!isAutoUpdate) DeviceStatus = "Сканирование...";

                var currentDevices = _deviceService.GetConnectedDevices();

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                   
                    var newDevices = currentDevices.Where(d => !Devices.Any(old => old.DeviceID == d.DeviceID)).ToList();


                    Devices.Clear();
                    foreach (var d in currentDevices) Devices.Add(d);

                    UpdateVulnerableDevices(); 

                    if (isAutoUpdate && newDevices.Any())
                    {
                        var names = string.Join(", ", newDevices.Select(x => x.Name));
                        DeviceStatus = $"Обнаружено новое устройство: {names}";

                        foreach (var nd in newDevices)
                        {
                            SecurityEvents.Insert(0, new SecurityEvent
                            {
                                TimeGenerated = DateTime.Now,
                                EventType = "Устройство",
                                Source = "DeviceMonitor",
                                Description = $"Подключено: {nd.Name} ({nd.Category})",
                                Severity = nd.IsSafe ? "Информация" : "Внимание"
                            });

                           
                            if (!nd.IsSafe) NewlyConnectedDevices.Add(nd);
                        }
                    }
                    else
                    {
                        DeviceStatus = $"Устройств: {Devices.Count}. Мониторинг активен.";
                    }

                    OnPropertyChanged(nameof(DisplayedDevices));
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка загрузки устройства: {ex.Message}");
            }
        }



        private void UpdateVulnerableDevices()
        {
            VulnerableDevices.Clear();
            var vulnerable = Devices.Where(d => !d.IsSafe ||
                d.VulnerabilityStatus != "Без уязвимостей" &&
                d.VulnerabilityStatus != "Не проверено").ToList();
            foreach (var device in vulnerable)
            {
                VulnerableDevices.Add(device);
            }
        }
        [RelayCommand]
        private void ShowOnlyVulnerableDevicesToggle()
        {
            ShowOnlyVulnerableDevices = !ShowOnlyVulnerableDevices;
            OnPropertyChanged(nameof(DisplayedDevices));
        }
        partial void OnShowOnlyVulnerableDevicesChanged(bool value)
        {
            OnPropertyChanged(nameof(DisplayedDevices));
        }
        [RelayCommand]
        private void OpenDeviceProperties(DeviceInfo device)
        {
            if (device == null) return;
            try
            {
                _deviceService.OpenDeviceSettings(device.DeviceID);
                DeviceStatus = "Открыт диспетчер устройств";
                MessageBox.Show(
                    "Диспетчер устройств открыт. Вы можете просмотреть свойства любого устройства.",
                    "Диспетчер устройств",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Не удалось открыть диспетчер устройств: {ex.Message}",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        [RelayCommand]
        private void OpenDeviceSettings(DeviceInfo device)
        {
            if (device == null) return;
            try
            {
                _deviceService.OpenDeviceSettings(device.DeviceID);
                DeviceStatus = $"Открыты настройки устройства: {device.Name}";
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Не удалось открыть настройки устройства: {ex.Message}\n\n" +
                    "Рекомендации:\n" +
                    "1. Запустите программу от имени администратора\n" +
                    "2. Проверьте, что оснастка 'devmgmt.msc' доступна в системе\n" +
                    "3. Попробуйте открыть диспетчер устройств вручную через Панель управления",
                    "Ошибка открытия настроек",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        [RelayCommand]
        private void EjectDevice(DeviceInfo device)
        {
            if (device == null) return;
            try
            {
                if (device.IsRemovable)
                {
                    var result = MessageBox.Show(
                        $"Безопасно извлечь устройство '{device.Name}'?",
                        "Извлечение устройства",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);
                    if (result == MessageBoxResult.Yes)
                    {
                        _deviceService.EjectDevice(device.DeviceID);
                        DeviceStatus = $"Устройство {device.Name} подготовлено к извлечению";
                        MessageBox.Show(
                            $"Устройство '{device.Name}' готово к безопасному извлечению.",
                            "Успех",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                }
                else
                {
                    MessageBox.Show(
                        "Это устройство не может быть извлечено безопасно.\nТолько съемные носители поддерживают извлечение.",
                        "Неизвлекаемое устройство",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Ошибка извлечения устройства: {ex.Message}",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        [RelayCommand]
        private async Task ScanSecurity()
        {
            try
            {
                IsScanning = true;
                ScanStatus = "Запуск комплексной проверки безопасности...";
                await Task.Run(() =>
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        Vulnerabilities.Clear();
                        ScanStatus = "Проверка обновлений системы...";
                    });
                    var vulnerabilities = _securityService.ScanForVulnerabilities();
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        foreach (var vuln in vulnerabilities)
                        {
                            Vulnerabilities.Add(vuln);
                        }
                        ScanStatus = $"Проверка завершена. Найдено {vulnerabilities.Count} уязвимостей";
                        IsScanning = false;
                        if (vulnerabilities.Count > 0)
                        {
                            MessageBox.Show(
                                $"Обнаружено {vulnerabilities.Count} потенциальных уязвимостей.\n\nРекомендуется устранить их для повышения безопасности системы.",
                                "Результат проверки безопасности",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                        }
                        else
                        {
                            MessageBox.Show(
                                "Система защищена! Серьезных уязвимостей не обнаружено.",
                                "Результат проверки безопасности",
                                MessageBoxButton.OK,
                                MessageBoxImage.Information);
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                ScanStatus = "Ошибка проверки безопасности";
                IsScanning = false;
                Debug.WriteLine($"Ошибка безопасности сканирования: {ex.Message}");
            }
        }
        [RelayCommand]
        
        private async Task StartDefenderScan()
        {
            if (IsDefenderScanInProgress) return;
            try
            {
                IsDefenderScanInProgress = true;
                DefenderScanProgress = 0;
                DefenderScanStatus = $"Запуск {SelectedScanType}...";
                var result = await Task.Run(() =>
                    _securityService.StartDefenderScanWithProgress(SelectedScanType));
              
                if (result.Progress == 0)
                {
                    for (int i = 0; i <= 100; i += 10)
                    {
                        if (!IsDefenderScanInProgress) break;
                        DefenderScanProgress = i;
                        DefenderScanStatus = $"{SelectedScanType} выполняется... {i}%";
                        await Task.Delay(1000);
                    }
                }
                else
                {
                    DefenderScanProgress = result.Progress;
                    DefenderScanStatus = $"{SelectedScanType} выполняется... {result.Progress}%";
                }
                DefenderScanProgress = 100;
                if (result.Success)
                {
                    DefenderScanStatus = $"{SelectedScanType} завершена успешно";
                }
                else
                {
                    DefenderScanStatus = "Ошибка запуска сканирования";
                }
                await LoadDefenderStatus();
                await LoadSecurityEvents();
            }
            catch (Exception ex)
            {
                DefenderScanStatus = "Ошибка сканирования";
                Debug.WriteLine($"StartDefenderScan Error: {ex.Message}");
            }
            finally
            {
                IsDefenderScanInProgress = false;
            }
        }
        [RelayCommand]
        private async Task LoadDefenderStatus()
        {
            try
            {
                await Task.Run(() =>
                {
                    var status = _securityService.GetDefenderStatus();
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        DefenderStatus = status;
                    });
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка загрузки статуса защитника: {ex.Message}");
            }
        }
        [RelayCommand]
        private async Task LoadAntivirusInfo()
        {
            try
            {
                await Task.Run(() =>
                {
                    var antivirus = _securityService.GetInstalledAntivirus();
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        AntivirusInfo = antivirus;
                    });
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка загрузки антивируса: {ex.Message}");
            }
        }
        [RelayCommand]
        private async Task PerformComprehensiveSecurityScan()
        {
            if (IsQuickScanInProgress) return;

            try
            {
                IsQuickScanInProgress = true;
                QuickScanStatus = "Анализ конфигурации системы...";

                var scanTask = Task.Run(() => _securityService.PerformComprehensiveSecurityScan());


                var result = await scanTask;

       
                QuickScanStatus = "Анализ журнала событий...";
                var freshEvents = await Task.Run(() => _securityService.SecurityEvents());

                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    SecurityScanResult = result;

                    // Обновляем списки угроз и проверок
                    SecurityChecks.Clear();
                    if (result.SecurityChecks != null)
                    {
                       
                        var sortedChecks = result.SecurityChecks
                            .OrderByDescending(c => c.IsCritical)
                            .ThenBy(c => c.Status.Contains("OK"));

                        foreach (var check in sortedChecks) SecurityChecks.Add(check);
                    }

                    Threats.Clear();
                    if (result.Threats != null)
                    {
                        foreach (var t in result.Threats) Threats.Add(t);
                    }

                    SecurityEvents.Clear();
                    foreach (var evt in freshEvents) SecurityEvents.Add(evt);

           
                    OnPropertyChanged(nameof(DisplayedSecurityChecks));

                    // Статус
                    QuickScanStatus = $"Завершено. Угроз: {result.TotalThreats}, Предупреждений: {result.Warnings}";

                    if (result.CriticalIssues > 0 || result.TotalThreats > 0)
                    {
                        MessageBox.Show($"Найдено проблем: {result.CriticalIssues + result.TotalThreats}. Проверьте вкладку 'Безопасность'.", "Сканирование завершено", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                });
            }
            catch (Exception ex)
            {
                QuickScanStatus = "Ошибка сканирования";
                Debug.WriteLine($"Scan Error: {ex.Message}");
            }
            finally
            {
                IsQuickScanInProgress = false;
            }
        }
        [RelayCommand]
        private void SetSecurityFilterAll()
        {
            CurrentSecurityFilter = SecurityFilterType.All;
            OnPropertyChanged(nameof(DisplayedSecurityChecks));
        }
        [RelayCommand]
        private void SetSecurityFilterRisks()
        {
            CurrentSecurityFilter = SecurityFilterType.Risks;
            OnPropertyChanged(nameof(DisplayedSecurityChecks));
        }
        [RelayCommand]
        private void SetSecurityFilterSafe()
        {
            CurrentSecurityFilter = SecurityFilterType.Safe;
            OnPropertyChanged(nameof(DisplayedSecurityChecks));
        }
        [RelayCommand]
        
        private async Task UpdateProcessesImmediately()
        {
            try
            {
                await Task.Run(() =>
                {
                    var newProcesses = _systemInfoService.GetRunningProcesses();
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        Processes.Clear();
                        foreach (var process in newProcesses.Take(30))
                        {
                            Processes.Add(process);
                        }
                        TotalProcessesCount = Processes.Count;
                    });
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка немедленного обновления процесса: {ex.Message}");
            }
        }
        [RelayCommand]
        private async Task LoadSecurityEvents()
        {
            try
            {
                await Task.Run(() =>
                {
                    var events = _securityService.SecurityEvents();
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        SecurityEvents.Clear();
                        foreach (var evt in events)
                        {
                            SecurityEvents.Add(evt);
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка загрузки событий безопасности: {ex.Message}");
            }
        }
        [RelayCommand]
        private void OpenDefenderSettings()
        {
            try
            {
                _securityService.OpenWindowsSecurity();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Не удалось открыть Безопасность Windows: {ex.Message}\n\n" +
                    "Альтернативные способы:\n" +
                    "1. Откройте Параметры Windows → Обновление и безопасность → Безопасность Windows\n" +
                    "2. В поиске Windows найдите 'Безопасность Windows'\n" +
                    "3. Проверьте, что Защитник Windows не отключен групповой политикой",
                    "Ошибка открытия Защитника",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        [RelayCommand]
        private void EnableDefenderProtection()
        {
            try
            {
                var result = _securityService.EnableDefenderProtection();
                if (result)
                {
                    MessageBox.Show(
                        "Защитник Windows успешно включен. Изменения вступят в силу через несколько секунд.",
                        "Защита включена",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    Task.Delay(3000).ContinueWith(_ =>
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            LoadDefenderStatus();
                        });
                    });
                }
                else
                {
                    MessageBox.Show(
                        "Не удалось включить Защитник Windows. Возможные причины:\n" +
                        "1. Отсутствуют права администратора\n" +
                        "2. Защитник отключен групповой политикой\n" +
                        "3. Установлено стороннее антивирусное ПО",
                        "Ошибка включения",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Ошибка включения Защитника: {ex.Message}",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        [RelayCommand]
        private void OpenAntivirus()
        {
            try
            {
                _securityService.OpenAntivirusUI();
            }
            catch (Exception ex)
            {
             
                MessageBox.Show(
                    $"Не удалось запустить программу антивируса: {ex.Message}\n\n" +
                    "Будет открыт стандартный центр 'Безопасность Windows'.",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        [RelayCommand]
        
        private async Task GenerateReport()
        {
            try
            {
                
                var reportData = new ReportData
                {
                    SystemInfo = SystemInfo,
                    TopProcesses = Processes.Take(10).ToList(),
                    Drives = Drives.ToList(),
                    Drivers = Drivers.ToList(),
                    Devices = Devices.ToList(),
                    ReportDate = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss"),

                   
                    SecurityChecks = SecurityScanResult.SecurityChecks ?? new List<SecurityCheck>(),
                    Threats = SecurityScanResult.Threats ?? new List<SecurityThreat>(),

                   
                    OverallSecurityStatus = SecurityScanResult.OverallStatus,
                    CriticalIssuesCount = SecurityScanResult.CriticalIssues,
                    TotalSecurityIssues = SecurityScanResult.TotalThreats + SecurityScanResult.CriticalIssues + SecurityScanResult.Warnings,

                   
                    Vulnerabilities = (SecurityScanResult.Threats ?? new List<SecurityThreat>()).Select(t => new SecurityVulnerability
                    {
                        Title = t.Name,
                        Description = t.Description,
                        Severity = t.Severity,
                        Category = t.Type,
                        Recommendation = t.Recommendation,
                        IsFixed = t.IsResolved
                    }).ToList()
                };
               

                var saveDialog = new SaveFileDialog
                {
                    Filter = "HTML files (*.html)|*.html|Text files (*.txt)|*.txt",
                    DefaultExt = ".html"
                };
                if (saveDialog.ShowDialog() == true)
                {
                    var result = await _reportService.ExportReportToFileAsync(saveDialog.FileName, reportData);
                    if (result)
                    {
                        MessageBox.Show(
                            $"Отчет успешно сохранен: {saveDialog.FileName}",
                            "Отчет сформирован",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show(
                            "Не удалось сохранить отчет",
                            "Ошибка",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Ошибка при формировании отчета: {ex.Message}",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        [RelayCommand]
        private async Task LoadInstalledSoftware()
        {
            try
            {
                var sw = await Task.Run(() => _systemInfoService.GetInstalledSoftware());
                Application.Current.Dispatcher.Invoke(() =>
                {
                    InstalledSoftware.Clear(); // Используем Свойство
                    foreach (var s in sw) InstalledSoftware.Add(s);
                });
            }
            catch { }
        }
        [RelayCommand]
        private async Task LoadStartupPrograms()
        {
            try
            {
                var progs = await Task.Run(() => _systemInfoService.GetStartupPrograms());
                Application.Current.Dispatcher.Invoke(() =>
                {
                    StartupPrograms.Clear(); // Используем Свойство
                    foreach (var p in progs) StartupPrograms.Add(p);
                });
            }
            catch { }
        }

        [RelayCommand]
        private async Task LoadNetworkConnections()
        {
            try
            {
                var nets = await Task.Run(() => _systemInfoService.GetActiveNetworkConnections());
                Application.Current.Dispatcher.Invoke(() =>
                {
                    NetworkConnections.Clear(); // Используем Свойство
                    foreach (var n in nets) NetworkConnections.Add(n);
                });
            }
            catch { }
        }


        [RelayCommand]
        private void OpenStartupSettings()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "ms-settings:startupapps",
                    UseShellExecute = true
                });
            }
            catch (Exception)
            {
                try
                {
                    Process.Start("shell:startup");
                }
                catch (Exception ex2)
                {
                    MessageBox.Show($"Не удалось открыть настройки автозагрузки: {ex2.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        [RelayCommand]
        private async Task RefreshAntivirusInfo()
        {
            await LoadAntivirusInfo();
        }
        [RelayCommand]
        private void ShowAbout()
        {
            MessageBox.Show(
                "System Inspector v1.0\n\n" +
                "Проект по информационной безопасности.\n\n" +
                "Расширенные функции:\n" +
                "- Мониторинг системы в реальном времени\n" +
                "- Контроль за драйверами и устройствами\n" +
                "- Проверка безопасности\n" +
                "- Анализ уязвимостей системы\n" +
                "- Детальная отчетность",
                "О программе",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        public override bool Equals(object? obj)
        {
            return base.Equals(obj);
        }
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
        public override string? ToString()
        {
            return base.ToString();
        }
        protected override void OnPropertyChanged(PropertyChangedEventArgs e)
        {
            base.OnPropertyChanged(e);
        }
        protected override void OnPropertyChanging(PropertyChangingEventArgs e)
        {
            base.OnPropertyChanging(e);
        }
    }
    
}
