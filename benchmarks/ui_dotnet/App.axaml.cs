using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using ZeroVaultUi.ViewModels;
using ZeroVaultUi.Views;

namespace ZeroVaultUi;

public enum AppRunMode
{
    InteractiveUi,
    BenchCold,
    Bench60Fps,
    MockServer
}

public sealed class AppCliOptions
{
    public AppRunMode Mode { get; set; } = AppRunMode.InteractiveUi;
    public string PipeName { get; set; } = Services.PipeIpcService.DefaultPipeName;
    public double ServerHz { get; set; } = 60.0;
    public int TargetFrames { get; set; } = 300;
    public bool LoopServer { get; set; }
    public string? JsonOutputPath { get; set; }
}

public partial class App : Application
{
    public static AppCliOptions Options { get; set; } = new();

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var vm = new MainWindowViewModel();
            desktop.MainWindow = new MainWindow(vm, Options, desktop);
        }

        base.OnFrameworkInitializationCompleted();
    }
}
