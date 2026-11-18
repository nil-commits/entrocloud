using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using ZeroVaultUi.Models;
using ZeroVaultUi.Services;
using ZeroVaultUi.ViewModels;

namespace ZeroVaultUi.Views;

public partial class MainWindow : Window
{
    private readonly MainWindowViewModel _viewModel;
    private readonly AppCliOptions _options;
    private readonly IClassicDesktopStyleApplicationLifetime? _desktop;
    private readonly CancellationTokenSource _cts = new();

    private string _ipcServerMode = "external_named_pipe";
    private bool _isWindowOpened;
    private bool _firstIpcApplied;
    private bool _benchCompleted;

    private double _windowOpenedMs;
    private double _firstIpcRecvMs;
    private long _firstSeq;

    // 60 FPS benchmark state
    private readonly List<double> _frameDeltasMs = new(320);
    private readonly List<double> _renderLatenciesMs = new(320);
    private bool _renderCallbackQueued;
    private long _latestPendingIpcRecvTicks;
    private int _ipcFramesReceived;
    private int _renderedFrames;
    private long _firstStreamRenderTicks;
    private long _prevStreamRenderTicks;
    private long _streamStartAllocBytes;

    public MainWindow()
    {
        _viewModel = new MainWindowViewModel();
        _options = new AppCliOptions();
        DataContext = _viewModel;
        InitializeComponent();
    }

    public MainWindow(
        MainWindowViewModel viewModel,
        AppCliOptions options,
        IClassicDesktopStyleApplicationLifetime desktop)
    {
        _viewModel = viewModel;
        _options = options;
        _desktop = desktop;
        DataContext = _viewModel;

        InitializeComponent();

        if (_options.Mode == AppRunMode.BenchCold)
        {
            StartIpcPipeline(maxEmbeddedFrames: 15);
            StartWatchdog(timeoutSeconds: 12);
        }
        else if (_options.Mode == AppRunMode.Bench60Fps)
        {
            StartWatchdog(timeoutSeconds: 25);
        }
    }

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        _windowOpenedMs = Stopwatch.GetElapsedTime(Program.EntryTimestamp).TotalMilliseconds;
        _isWindowOpened = true;

        if (_options.Mode == AppRunMode.BenchCold)
        {
            TryCompleteColdBenchmark();
        }
        else if (_options.Mode == AppRunMode.Bench60Fps)
        {
            // Wait for initial window frame to be presented on screen, then connect & stream 300 frames at 60Hz
            TopLevel.GetTopLevel(this)?.RequestAnimationFrame(_ =>
            {
                StartIpcPipeline(maxEmbeddedFrames: _options.TargetFrames + 30);
            });
        }
        else if (_options.Mode == AppRunMode.InteractiveUi)
        {
            StartIpcPipeline(maxEmbeddedFrames: 0);
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _cts.Cancel();
        base.OnClosed(e);
    }

    private void StartWatchdog(int timeoutSeconds)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(timeoutSeconds), _cts.Token).ConfigureAwait(false);
                if (!_benchCompleted)
                {
                    Console.Error.WriteLine($"[ERROR] Benchmark timed out after {timeoutSeconds}s (opened={_isWindowOpened}, ipcFrames={_ipcFramesReceived}, rendered={_renderedFrames})");
                    Environment.Exit(2);
                }
            }
            catch (OperationCanceledException)
            {
            }
        });
    }

    private void StartIpcPipeline(int maxEmbeddedFrames)
    {
        string pipeName = _options.PipeName;
        if (PipeIpcService.IsExternalPipeAvailable(pipeName, timeoutMs: 5))
        {
            _ipcServerMode = "external_named_pipe";
        }
        else
        {
            _ipcServerMode = "embedded_named_pipe";
            using var ready = new ManualResetEventSlim(false);
            _ = PipeIpcService.StartEmbeddedServerAsync(
                pipeName,
                _options.ServerHz,
                maxEmbeddedFrames,
                ready,
                _cts.Token);
            ready.Wait(1000);
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await PipeIpcService.ReadTelemetryStreamAsync(
                    pipeName,
                    OnIpcTelemetryReceived,
                    _cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                if (!_benchCompleted)
                {
                    Console.Error.WriteLine($"[IPC ERROR] {ex.GetType().Name}: {ex.Message}");
                }
            }
        });
    }

    private void OnIpcTelemetryReceived(TelemetryFrame frame, long recvTimestamp)
    {
        if (_benchCompleted)
        {
            return;
        }

        if (_options.Mode == AppRunMode.BenchCold)
        {
            if (_firstIpcRecvMs == 0)
            {
                _firstIpcRecvMs = Stopwatch.GetElapsedTime(Program.EntryTimestamp, recvTimestamp).TotalMilliseconds;
            }

            Dispatcher.UIThread.Post(() =>
            {
                if (_benchCompleted) return;
                _viewModel.ApplyTelemetry(frame, _options.PipeName);
                _firstIpcApplied = true;
                _firstSeq = frame.Seq;
                TryCompleteColdBenchmark();
            }, DispatcherPriority.Send);
        }
        else if (_options.Mode == AppRunMode.Bench60Fps)
        {
            Dispatcher.UIThread.Post(() =>
            {
                if (_benchCompleted) return;
                _viewModel.ApplyTelemetry(frame, _options.PipeName);
                _ipcFramesReceived++;
                _latestPendingIpcRecvTicks = recvTimestamp;

                if (!_renderCallbackQueued)
                {
                    _renderCallbackQueued = true;
                    InvalidateVisual();
                    TopLevel.GetTopLevel(this)?.RequestAnimationFrame(OnStreamAnimationFrame);
                }
            }, DispatcherPriority.Render);
        }
        else
        {
            Dispatcher.UIThread.Post(() =>
            {
                _viewModel.ApplyTelemetry(frame, _options.PipeName);
            }, DispatcherPriority.Background);
        }
    }

    private void TryCompleteColdBenchmark()
    {
        if (!_isWindowOpened || !_firstIpcApplied || _benchCompleted)
        {
            return;
        }

        _benchCompleted = true;
        UpdateLayout();
        InvalidateVisual();

        TopLevel? topLevel = TopLevel.GetTopLevel(this);
        if (topLevel is not null)
        {
            topLevel.RequestAnimationFrame(_ => EmitColdResultAndExit());
        }
        else
        {
            Dispatcher.UIThread.Post(EmitColdResultAndExit, DispatcherPriority.Render);
        }
    }

    private void EmitColdResultAndExit()
    {
        double coldElapsedMs = Stopwatch.GetElapsedTime(Program.EntryTimestamp).TotalMilliseconds;
        using var proc = Process.GetCurrentProcess();
        proc.Refresh();

        var result = new BenchColdResult
        {
            Mode = "bench-cold",
            DotnetSdk = Program.CompiledDotnetSdkVersion,
            RuntimeFramework = RuntimeInformation.FrameworkDescription,
            AvaloniaVersion = GetAvaloniaVersion(),
            IsNativeAot = !RuntimeFeature.IsDynamicCodeSupported,
            PipePath = @"\\.\pipe\" + _options.PipeName,
            IpcServerMode = _ipcServerMode,
            ColdFirstFrameIpcMs = Math.Round(coldElapsedMs, 3),
            WindowOpenedMs = Math.Round(_windowOpenedMs, 3),
            FirstIpcReceivedMs = Math.Round(_firstIpcRecvMs, 3),
            FirstFrameSeq = _firstSeq,
            WorkingSetBytes = proc.WorkingSet64,
            WorkingSetMib = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 3),
            PeakWorkingSetBytes = proc.PeakWorkingSet64,
            PeakWorkingSetMib = Math.Round(proc.PeakWorkingSet64 / (1024.0 * 1024.0), 3),
            PrivateMemoryBytes = proc.PrivateMemorySize64,
            PrivateMemoryMib = Math.Round(proc.PrivateMemorySize64 / (1024.0 * 1024.0), 3),
            TimestampUtc = DateTime.UtcNow.ToString("O")
        };

        string json = JsonSerializer.Serialize(result, BakeoffJsonContext.Default.BenchColdResult);
        WriteTelemetryOutput(json);

        _cts.Cancel();
        _desktop?.Shutdown(0);
    }

    private void OnStreamAnimationFrame(TimeSpan _)
    {
        _renderCallbackQueued = false;
        if (_benchCompleted)
        {
            return;
        }

        long nowTicks = Stopwatch.GetTimestamp();
        double renderLatMs = Stopwatch.GetElapsedTime(_latestPendingIpcRecvTicks, nowTicks).TotalMilliseconds;
        _renderLatenciesMs.Add(Math.Round(renderLatMs, 4));

        if (_renderedFrames == 0)
        {
            _firstStreamRenderTicks = nowTicks;
            _streamStartAllocBytes = GC.GetTotalAllocatedBytes(precise: false);
        }
        else
        {
            double deltaMs = Stopwatch.GetElapsedTime(_prevStreamRenderTicks, nowTicks).TotalMilliseconds;
            _frameDeltasMs.Add(Math.Round(deltaMs, 4));
        }

        _prevStreamRenderTicks = nowTicks;
        _renderedFrames++;

        if (_renderedFrames >= _options.TargetFrames)
        {
            _benchCompleted = true;
            Emit60FpsResultAndExit(nowTicks);
        }
    }

    private void Emit60FpsResultAndExit(long finalRenderTicks)
    {
        double totalStreamMs = Stopwatch.GetElapsedTime(_firstStreamRenderTicks, finalRenderTicks).TotalMilliseconds;
        double effectiveFps = totalStreamMs > 0
            ? ((_renderedFrames - 1) * 1000.0) / totalStreamMs
            : 0.0;

        using var proc = Process.GetCurrentProcess();
        proc.Refresh();

        double[] rawDeltas = _frameDeltasMs.ToArray();
        double[] sortedDeltas = (double[])rawDeltas.Clone();
        Array.Sort(sortedDeltas);

        double[] rawLatencies = _renderLatenciesMs.ToArray();
        double[] sortedLatencies = (double[])rawLatencies.Clone();
        Array.Sort(sortedLatencies);

        int deltaGt1667 = 0;
        int droppedGt25 = 0;
        double sumDeltas = 0;
        for (int i = 0; i < rawDeltas.Length; i++)
        {
            double d = rawDeltas[i];
            sumDeltas += d;
            if (d > 16.67) deltaGt1667++;
            if (d > 25.0) droppedGt25++;
        }

        int latOverruns = 0;
        double sumLat = 0;
        for (int i = 0; i < rawLatencies.Length; i++)
        {
            double l = rawLatencies[i];
            sumLat += l;
            if (l > 16.67) latOverruns++;
        }

        var result = new Bench60FpsResult
        {
            Mode = "bench-60fps",
            DotnetSdk = Program.CompiledDotnetSdkVersion,
            RuntimeFramework = RuntimeInformation.FrameworkDescription,
            AvaloniaVersion = GetAvaloniaVersion(),
            IsNativeAot = !RuntimeFeature.IsDynamicCodeSupported,
            PipePath = @"\\.\pipe\" + _options.PipeName,
            IpcServerMode = _ipcServerMode,
            TargetFrames = _options.TargetFrames,
            IpcFramesReceived = _ipcFramesReceived,
            RenderedFrames = _renderedFrames,
            TotalStreamDurationMs = Math.Round(totalStreamMs, 3),
            EffectiveFps = Math.Round(effectiveFps, 2),

            RenderLatencyMinMs = sortedLatencies.Length > 0 ? Math.Round(sortedLatencies[0], 3) : 0,
            RenderLatencyP50Ms = Math.Round(Percentile(sortedLatencies, 0.50), 3),
            RenderLatencyP95Ms = Math.Round(Percentile(sortedLatencies, 0.95), 3),
            RenderLatencyP99Ms = Math.Round(Percentile(sortedLatencies, 0.99), 3),
            RenderLatencyMaxMs = sortedLatencies.Length > 0 ? Math.Round(sortedLatencies[^1], 3) : 0,
            RenderLatencyMeanMs = rawLatencies.Length > 0 ? Math.Round(sumLat / rawLatencies.Length, 3) : 0,
            RenderOverrunsGt16_67Ms = latOverruns,

            FrameDeltaMinMs = sortedDeltas.Length > 0 ? Math.Round(sortedDeltas[0], 3) : 0,
            FrameDeltaP50Ms = Math.Round(Percentile(sortedDeltas, 0.50), 3),
            FrameDeltaP95Ms = Math.Round(Percentile(sortedDeltas, 0.95), 3),
            FrameDeltaP99Ms = Math.Round(Percentile(sortedDeltas, 0.99), 3),
            FrameDeltaMaxMs = sortedDeltas.Length > 0 ? Math.Round(sortedDeltas[^1], 3) : 0,
            FrameDeltaMeanMs = rawDeltas.Length > 0 ? Math.Round(sumDeltas / rawDeltas.Length, 3) : 0,
            FrameDeltaGt16_67Ms = deltaGt1667,
            DroppedFramesGt25Ms = droppedGt25,

            PeakWorkingSetBytes = proc.PeakWorkingSet64,
            PeakWorkingSetMib = Math.Round(proc.PeakWorkingSet64 / (1024.0 * 1024.0), 3),
            WorkingSetBytes = proc.WorkingSet64,
            WorkingSetMib = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 3),
            PrivateMemoryBytes = proc.PrivateMemorySize64,
            PrivateMemoryMib = Math.Round(proc.PrivateMemorySize64 / (1024.0 * 1024.0), 3),
            GcTotalAllocatedBytes = GC.GetTotalAllocatedBytes(precise: false),
            GcStreamAllocatedBytes = Math.Max(0, GC.GetTotalAllocatedBytes(precise: false) - _streamStartAllocBytes),
            GcGen0Collections = GC.CollectionCount(0),
            GcGen1Collections = GC.CollectionCount(1),
            GcGen2Collections = GC.CollectionCount(2),
            TimestampUtc = DateTime.UtcNow.ToString("O"),
            RawFrameDeltasMs = rawDeltas,
            RawRenderLatenciesMs = rawLatencies
        };

        string json = JsonSerializer.Serialize(result, BakeoffJsonContext.Default.Bench60FpsResult);
        WriteTelemetryOutput(json);

        _cts.Cancel();
        _desktop?.Shutdown(0);
    }

    private void WriteTelemetryOutput(string json)
    {
        Console.Out.WriteLine(json);
        Console.Out.Flush();

        if (!string.IsNullOrWhiteSpace(_options.JsonOutputPath))
        {
            File.WriteAllText(_options.JsonOutputPath, json + Environment.NewLine);
        }
    }

    private static string GetAvaloniaVersion()
    {
        return typeof(Avalonia.Application).Assembly.GetName().Version?.ToString() ?? "unknown";
    }

    private static double Percentile(double[] sorted, double p)
    {
        if (sorted.Length == 0) return 0.0;
        if (sorted.Length == 1) return sorted[0];
        double rank = p * (sorted.Length - 1);
        int lo = (int)Math.Floor(rank);
        int hi = (int)Math.Ceiling(rank);
        if (lo == hi) return sorted[lo];
        return sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo);
    }
}
