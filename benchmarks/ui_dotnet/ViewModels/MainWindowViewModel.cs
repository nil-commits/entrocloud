using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using Avalonia.Media;
using ZeroVaultUi.Models;

namespace ZeroVaultUi.ViewModels;

public sealed class ActionCommand(Action execute) : ICommand
{
    public event EventHandler? CanExecuteChanged
    {
        add { }
        remove { }
    }

    public bool CanExecute(object? parameter) => true;
    public void Execute(object? parameter) => execute();
}

public sealed class MainWindowViewModel : INotifyPropertyChanged
{
    private static readonly IBrush UnlockedFgBrush = new SolidColorBrush(Color.Parse("#34D399"));
    private static readonly IBrush UnlockedBgBrush = new SolidColorBrush(Color.Parse("#064E3B"));
    private static readonly IBrush LockedFgBrush = new SolidColorBrush(Color.Parse("#F87171"));
    private static readonly IBrush LockedBgBrush = new SolidColorBrush(Color.Parse("#450A0A"));

    private bool _isVaultUnlocked = true;
    private string _mountPath = @"Z:\ZeroVault";
    private string _ipcStatusText = @"Connecting to \\.\pipe\zerovault-bakeoff-dotnet...";

    private string _uploadThroughputText = "0.0 MiB/s";
    private double _uploadBarPercent;
    private string _downloadThroughputText = "0.0 MiB/s";
    private double _downloadBarPercent;
    private double _transferProgressPercent;
    private string _transferProgressText = "0.0%";
    private string _activeChunksText = "0 active chunks";
    private string _frameSequenceText = "Seq #0";

    // 3-Provider Multi-Cloud Quota Cards
    private string _gDriveUsageText = "842.4 / 2048.0 GiB (41.1%)";
    private double _gDrivePercent = 41.1;
    private string _gDriveRateText = "▲ 0.0 MiB/s";

    private string _oneDriveUsageText = "614.8 / 1024.0 GiB (60.0%)";
    private double _oneDrivePercent = 60.0;
    private string _oneDriveRateText = "▲ 0.0 MiB/s";

    private string _s3UsageText = "1290.2 / 4096.0 GiB (31.5%)";
    private double _s3Percent = 31.5;
    private string _s3RateText = "▲ 0.0 MiB/s";

    // Settings
    private int _selectedRoutingPolicyIndex = 2; // Quota-Pooled
    private double _cacheLimitGib = 16.0;

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainWindowViewModel()
    {
        ToggleVaultLockCommand = new ActionCommand(ToggleVaultLock);
    }

    public ICommand ToggleVaultLockCommand { get; }

    public string EncryptionBadgeText => "AES-256-GCM VAES + ML-KEM-768";

    public string[] RoutingPolicies { get; } =
    [
        "Targeted",
        "Mirrored RAID-1",
        "Quota-Pooled"
    ];

    public bool IsVaultUnlocked
    {
        get => _isVaultUnlocked;
        private set
        {
            if (_isVaultUnlocked == value) return;
            _isVaultUnlocked = value;
            _mountPath = value ? @"Z:\ZeroVault" : "Unmounted (Vault Keys Zeroized)";
            OnPropertyChanged();
            OnPropertyChanged(nameof(VaultStatusBadgeText));
            OnPropertyChanged(nameof(VaultStatusForeground));
            OnPropertyChanged(nameof(VaultStatusBackground));
            OnPropertyChanged(nameof(MountPath));
            OnPropertyChanged(nameof(LockButtonText));
        }
    }

    public string VaultStatusBadgeText => _isVaultUnlocked ? "● VAULT UNLOCKED" : "■ VAULT LOCKED";
    public IBrush VaultStatusForeground => _isVaultUnlocked ? UnlockedFgBrush : LockedFgBrush;
    public IBrush VaultStatusBackground => _isVaultUnlocked ? UnlockedBgBrush : LockedBgBrush;
    public string MountPath => _mountPath;
    public string LockButtonText => _isVaultUnlocked ? "Lock Vault & Zeroize Keys" : "Unlock Vault (Z:\\ZeroVault)";

    public string IpcStatusText
    {
        get => _ipcStatusText;
        set => SetField(ref _ipcStatusText, value);
    }

    public string UploadThroughputText
    {
        get => _uploadThroughputText;
        private set => SetField(ref _uploadThroughputText, value);
    }

    public double UploadBarPercent
    {
        get => _uploadBarPercent;
        private set => SetField(ref _uploadBarPercent, value);
    }

    public string DownloadThroughputText
    {
        get => _downloadThroughputText;
        private set => SetField(ref _downloadThroughputText, value);
    }

    public double DownloadBarPercent
    {
        get => _downloadBarPercent;
        private set => SetField(ref _downloadBarPercent, value);
    }

    public double TransferProgressPercent
    {
        get => _transferProgressPercent;
        private set => SetField(ref _transferProgressPercent, value);
    }

    public string TransferProgressText
    {
        get => _transferProgressText;
        private set => SetField(ref _transferProgressText, value);
    }

    public string ActiveChunksText
    {
        get => _activeChunksText;
        private set => SetField(ref _activeChunksText, value);
    }

    public string FrameSequenceText
    {
        get => _frameSequenceText;
        private set => SetField(ref _frameSequenceText, value);
    }

    public string GDriveUsageText
    {
        get => _gDriveUsageText;
        private set => SetField(ref _gDriveUsageText, value);
    }

    public double GDrivePercent
    {
        get => _gDrivePercent;
        private set => SetField(ref _gDrivePercent, value);
    }

    public string GDriveRateText
    {
        get => _gDriveRateText;
        private set => SetField(ref _gDriveRateText, value);
    }

    public string OneDriveUsageText
    {
        get => _oneDriveUsageText;
        private set => SetField(ref _oneDriveUsageText, value);
    }

    public double OneDrivePercent
    {
        get => _oneDrivePercent;
        private set => SetField(ref _oneDrivePercent, value);
    }

    public string OneDriveRateText
    {
        get => _oneDriveRateText;
        private set => SetField(ref _oneDriveRateText, value);
    }

    public string S3UsageText
    {
        get => _s3UsageText;
        private set => SetField(ref _s3UsageText, value);
    }

    public double S3Percent
    {
        get => _s3Percent;
        private set => SetField(ref _s3Percent, value);
    }

    public string S3RateText
    {
        get => _s3RateText;
        private set => SetField(ref _s3RateText, value);
    }

    public int SelectedRoutingPolicyIndex
    {
        get => _selectedRoutingPolicyIndex;
        set
        {
            if (SetField(ref _selectedRoutingPolicyIndex, value))
            {
                OnPropertyChanged(nameof(RoutingPolicyDescription));
            }
        }
    }

    public string RoutingPolicyDescription => _selectedRoutingPolicyIndex switch
    {
        0 => "Targeted: Pins encrypted 4 MiB AEAD chunks to primary S3 bucket with deterministic prefix.",
        1 => "Mirrored RAID-1: Writes synchronous 2-of-3 replicas across Google Drive + S3 for zero-RPO resilience.",
        _ => "Quota-Pooled: Stripes ML-KEM-768 wrapped chunks proportionally across free Drive, OneDrive & S3 quota."
    };

    public double CacheLimitGib
    {
        get => _cacheLimitGib;
        set
        {
            if (SetField(ref _cacheLimitGib, value))
            {
                OnPropertyChanged(nameof(CacheLimitText));
            }
        }
    }

    public string CacheLimitText => string.Create(CultureInfo.InvariantCulture, $"{_cacheLimitGib:F1} GiB Local NVMe Staging Limit");

    public void ToggleVaultLock()
    {
        IsVaultUnlocked = !_isVaultUnlocked;
    }

    public void ApplyTelemetry(TelemetryFrame frame, string pipeName)
    {
        double clampedProgress = Math.Clamp(frame.Progress, 0.0, 1.0);
        double pct = clampedProgress * 100.0;

        UploadThroughputText = string.Create(CultureInfo.InvariantCulture, $"{frame.UpMibS:F1} MiB/s");
        UploadBarPercent = Math.Clamp(frame.UpMibS / 5.0, 0.0, 100.0); // 0..500 MiB/s full scale

        DownloadThroughputText = string.Create(CultureInfo.InvariantCulture, $"{frame.DownMibS:F1} MiB/s");
        DownloadBarPercent = Math.Clamp(frame.DownMibS / 10.0, 0.0, 100.0); // 0..1000 MiB/s full scale

        TransferProgressPercent = pct;
        TransferProgressText = string.Create(CultureInfo.InvariantCulture, $"{pct:F1}%");
        ActiveChunksText = string.Create(CultureInfo.InvariantCulture, $"{frame.ActiveChunks} in-flight AEAD chunks");
        FrameSequenceText = string.Create(CultureInfo.InvariantCulture, $"Seq #{frame.Seq}");
        IpcStatusText = string.Create(CultureInfo.InvariantCulture, $@"IPC Connected • \\.\pipe\{pipeName} • Seq #{frame.Seq}");

        // Live per-provider quota & shard stripe rate updates
        double deltaGib = clampedProgress * 24.0;
        double gdUsed = 842.4 + deltaGib * 0.35;
        double gdPct = (gdUsed / 2048.0) * 100.0;
        GDrivePercent = gdPct;
        GDriveUsageText = string.Create(CultureInfo.InvariantCulture, $"{gdUsed:F1} / 2048.0 GiB ({gdPct:F1}%)");
        GDriveRateText = string.Create(CultureInfo.InvariantCulture, $"▲ {frame.UpMibS * 0.30:F1} MiB/s  ▼ {frame.DownMibS * 0.30:F1} MiB/s");

        double odUsed = 614.8 + deltaGib * 0.20;
        double odPct = (odUsed / 1024.0) * 100.0;
        OneDrivePercent = odPct;
        OneDriveUsageText = string.Create(CultureInfo.InvariantCulture, $"{odUsed:F1} / 1024.0 GiB ({odPct:F1}%)");
        OneDriveRateText = string.Create(CultureInfo.InvariantCulture, $"▲ {frame.UpMibS * 0.20:F1} MiB/s  ▼ {frame.DownMibS * 0.20:F1} MiB/s");

        double s3Used = 1290.2 + deltaGib * 0.45;
        double s3Pct = (s3Used / 4096.0) * 100.0;
        S3Percent = s3Pct;
        S3UsageText = string.Create(CultureInfo.InvariantCulture, $"{s3Used:F1} / 4096.0 GiB ({s3Pct:F1}%)");
        S3RateText = string.Create(CultureInfo.InvariantCulture, $"▲ {frame.UpMibS * 0.50:F1} MiB/s  ▼ {frame.DownMibS * 0.50:F1} MiB/s");
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
