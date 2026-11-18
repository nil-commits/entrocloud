using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using ZeroVaultUi.Models;

namespace ZeroVaultUi.Services;

public static class PipeIpcService
{
    public const string DefaultPipeName = "zerovault-bakeoff-dotnet";

    private const uint CreateWaitableTimerHighResolution = 0x00000002;
    private const uint TimerModifyState = 0x0002;
    private const uint Synchronize = 0x00100000;
    private const uint TimerAccessMask = TimerModifyState | Synchronize;

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern nint CreateWaitableTimerExW(nint lpTimerAttributes, nint lpTimerName, uint dwFlags, uint dwDesiredAccess);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWaitableTimer(nint hTimer, ref long pDueTime, int lPeriod, nint pfnCompletionRoutine, nint lpArgToCompletionRoutine, [MarshalAs(UnmanagedType.Bool)] bool fResume);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WaitNamedPipeW(string lpNamedPipeName, uint nTimeOut);

    public static string NormalizePipeName(string rawName)
    {
        const string prefix = @"\\.\pipe\";
        if (rawName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return rawName[prefix.Length..];
        }
        return rawName;
    }

    public static bool IsExternalPipeAvailable(string pipeName, uint timeoutMs = 5)
    {
        string fullPath = @"\\.\pipe\" + pipeName;
        return WaitNamedPipeW(fullPath, timeoutMs);
    }

    public static async Task<int> RunStandaloneServerAsync(
        string pipeName,
        double hz,
        int maxFrames,
        bool loopConnections,
        CancellationToken ct)
    {
        Console.Error.WriteLine($"[mock-server] Listening on \\\\.\\pipe\\{pipeName} (hz={hz:F1}, maxFrames={maxFrames}, loop={loopConnections})");
        do
        {
            try
            {
                await ServeSingleClientAsync(pipeName, hz, maxFrames, readySignal: null, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException)
            {
                // Client closed pipe cleanly after completing benchmark frames
            }
        }
        while (loopConnections && !ct.IsCancellationRequested);

        return 0;
    }

    public static Task StartEmbeddedServerAsync(
        string pipeName,
        double hz,
        int maxFrames,
        ManualResetEventSlim readySignal,
        CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            try
            {
                await ServeSingleClientAsync(pipeName, hz, maxFrames, readySignal, ct).ConfigureAwait(false);
            }
            catch
            {
                readySignal.Set();
            }
        }, ct);
    }

    private static async Task ServeSingleClientAsync(
        string pipeName,
        double hz,
        int maxFrames,
        ManualResetEventSlim? readySignal,
        CancellationToken ct)
    {
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.Out,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 65536);

        readySignal?.Set();
        await server.WaitForConnectionAsync(ct).ConfigureAwait(false);

        using var writer = new StreamWriter(server, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), bufferSize: 4096, leaveOpen: true)
        {
            NewLine = "\n",
            AutoFlush = false
        };

        nint timerHandle = CreateWaitableTimerExW(0, 0, CreateWaitableTimerHighResolution, TimerAccessMask);
        try
        {
            long startTicks = Stopwatch.GetTimestamp();
            double ticksPerFrame = Stopwatch.Frequency / hz;
            int totalToEmit = maxFrames <= 0 ? int.MaxValue : maxFrames;

            for (int i = 1; i <= totalToEmit && !ct.IsCancellationRequested && server.IsConnected; i++)
            {
                double phase = (i % 300) / 300.0;
                double progress = maxFrames > 0
                    ? Math.Clamp((double)i / maxFrames, 0.0, 1.0)
                    : phase;

                var frame = new TelemetryFrame
                {
                    Seq = i,
                    UpMibS = Math.Round(185.0 + 95.0 * Math.Sin(i * 0.09), 2),
                    DownMibS = Math.Round(420.0 + 160.0 * Math.Cos(i * 0.07), 2),
                    Progress = Math.Round(progress, 4),
                    ActiveChunks = 16 + (i % 33)
                };

                string json = JsonSerializer.Serialize(frame, BakeoffJsonContext.Default.TelemetryFrame);
                await writer.WriteLineAsync(json).ConfigureAwait(false);
                await writer.FlushAsync(ct).ConfigureAwait(false);

                if (i == totalToEmit)
                {
                    break;
                }

                // Drift-free absolute deadline scheduling for exact 60.00 Hz pacing
                long nextDeadlineTicks = startTicks + (long)Math.Round(i * ticksPerFrame);
                WaitUntilTimestamp(nextDeadlineTicks, timerHandle);
            }
        }
        finally
        {
            if (timerHandle != 0)
            {
                CloseHandle(timerHandle);
            }
        }
    }

    private static void WaitUntilTimestamp(long targetTimestamp, nint highResTimer)
    {
        while (true)
        {
            long now = Stopwatch.GetTimestamp();
            long remainingTicks = targetTimestamp - now;
            if (remainingTicks <= 0)
            {
                return;
            }

            double remainingMs = (remainingTicks * 1000.0) / Stopwatch.Frequency;
            if (remainingMs > 0.65 && highResTimer != 0)
            {
                // Leave ~0.35ms margin for kernel wakeup, then spin-finish to microsecond accuracy
                long sleep100Ns = -(long)((remainingMs - 0.35) * 10_000.0);
                if (sleep100Ns < 0 && SetWaitableTimer(highResTimer, ref sleep100Ns, 0, 0, 0, false))
                {
                    WaitForSingleObject(highResTimer, 50);
                }
            }
            else if (remainingMs > 2.0)
            {
                Thread.Sleep(1);
            }
            else
            {
                Thread.SpinWait(32);
            }
        }
    }

    public static async Task ReadTelemetryStreamAsync(
        string pipeName,
        Action<TelemetryFrame, long> onFrameReceived,
        CancellationToken ct)
    {
        await using var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.In,
            PipeOptions.Asynchronous);

        await client.ConnectAsync(5000, ct).ConfigureAwait(false);

        using var reader = new StreamReader(client, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096);
        while (!ct.IsCancellationRequested)
        {
            string? line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (line is null)
            {
                break;
            }

            if (line.Length == 0)
            {
                continue;
            }

            long recvTimestamp = Stopwatch.GetTimestamp();
            TelemetryFrame? frame = JsonSerializer.Deserialize(line, BakeoffJsonContext.Default.TelemetryFrame);
            if (frame is not null)
            {
                onFrameReceived(frame, recvTimestamp);
            }
        }
    }
}
