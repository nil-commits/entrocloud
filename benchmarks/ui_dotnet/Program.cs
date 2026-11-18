using System.Diagnostics;
using System.Globalization;
using Avalonia;
using ZeroVaultUi.Services;

namespace ZeroVaultUi;

internal static class Program
{
    public const string CompiledDotnetSdkVersion = "9.0.320";
    public static long EntryTimestamp { get; private set; } = Stopwatch.GetTimestamp();

    [STAThread]
    public static int Main(string[] args)
    {
        EntryTimestamp = Stopwatch.GetTimestamp();

        AppCliOptions options = ParseArgs(args);
        App.Options = options;

        if (options.Mode == AppRunMode.MockServer)
        {
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            int serverMaxFrames = options.LoopServer ? options.TargetFrames + 40 : options.TargetFrames + 40;
            return PipeIpcService.RunStandaloneServerAsync(
                options.PipeName,
                options.ServerHz,
                serverMaxFrames,
                options.LoopServer,
                cts.Token).GetAwaiter().GetResult();
        }

        return BuildAvaloniaApp()
            .StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont();

    private static AppCliOptions ParseArgs(string[] args)
    {
        var opts = new AppCliOptions();
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            switch (arg)
            {
                case "--bench-cold":
                case "--bench-cold-exit":
                    opts.Mode = AppRunMode.BenchCold;
                    break;
                case "--bench-60fps":
                case "--bench-60fps-5s":
                    opts.Mode = AppRunMode.Bench60Fps;
                    break;
                case "--mock-server":
                    opts.Mode = AppRunMode.MockServer;
                    break;
                case "--loop":
                    opts.LoopServer = true;
                    break;
                case "--pipe" when i + 1 < args.Length:
                    opts.PipeName = PipeIpcService.NormalizePipeName(args[++i]);
                    break;
                case "--frames" when i + 1 < args.Length:
                    if (int.TryParse(args[++i], CultureInfo.InvariantCulture, out int frames) && frames > 0)
                    {
                        opts.TargetFrames = frames;
                    }
                    break;
                case "--hz" when i + 1 < args.Length:
                    if (double.TryParse(args[++i], CultureInfo.InvariantCulture, out double hz) && hz > 0)
                    {
                        opts.ServerHz = hz;
                    }
                    break;
                case "--json-out" when i + 1 < args.Length:
                    opts.JsonOutputPath = args[++i];
                    break;
            }
        }
        return opts;
    }
}
