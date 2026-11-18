using System.Text.Json.Serialization;

namespace ZeroVaultUi.Models;

public sealed class TelemetryFrame
{
    [JsonPropertyName("seq")]
    public long Seq { get; set; }

    [JsonPropertyName("up_mib_s")]
    public double UpMibS { get; set; }

    [JsonPropertyName("down_mib_s")]
    public double DownMibS { get; set; }

    [JsonPropertyName("progress")]
    public double Progress { get; set; }

    [JsonPropertyName("active_chunks")]
    public int ActiveChunks { get; set; }
}

public sealed class BenchColdResult
{
    public string Mode { get; set; } = "bench-cold";
    public string DotnetSdk { get; set; } = "";
    public string RuntimeFramework { get; set; } = "";
    public string AvaloniaVersion { get; set; } = "";
    public bool IsNativeAot { get; set; }
    public string PipePath { get; set; } = "";
    public string IpcServerMode { get; set; } = "";
    public double ColdFirstFrameIpcMs { get; set; }
    public double WindowOpenedMs { get; set; }
    public double FirstIpcReceivedMs { get; set; }
    public long FirstFrameSeq { get; set; }
    public long WorkingSetBytes { get; set; }
    public double WorkingSetMib { get; set; }
    public long PeakWorkingSetBytes { get; set; }
    public double PeakWorkingSetMib { get; set; }
    public long PrivateMemoryBytes { get; set; }
    public double PrivateMemoryMib { get; set; }
    public string TimestampUtc { get; set; } = "";
}

public sealed class Bench60FpsResult
{
    public string Mode { get; set; } = "bench-60fps";
    public string DotnetSdk { get; set; } = "";
    public string RuntimeFramework { get; set; } = "";
    public string AvaloniaVersion { get; set; } = "";
    public bool IsNativeAot { get; set; }
    public string PipePath { get; set; } = "";
    public string IpcServerMode { get; set; } = "";
    public int TargetFrames { get; set; }
    public int IpcFramesReceived { get; set; }
    public int RenderedFrames { get; set; }
    public double TotalStreamDurationMs { get; set; }
    public double EffectiveFps { get; set; }

    // Frame render latency: IPC arrival -> ViewModel compiled binding update -> Layout + GPU Render callback
    public double RenderLatencyMinMs { get; set; }
    public double RenderLatencyP50Ms { get; set; }
    public double RenderLatencyP95Ms { get; set; }
    public double RenderLatencyP99Ms { get; set; }
    public double RenderLatencyMaxMs { get; set; }
    public double RenderLatencyMeanMs { get; set; }
    public int RenderOverrunsGt16_67Ms { get; set; }

    // Frame-to-frame cadence delta across the 60Hz stream (target ~16.67ms)
    public double FrameDeltaMinMs { get; set; }
    public double FrameDeltaP50Ms { get; set; }
    public double FrameDeltaP95Ms { get; set; }
    public double FrameDeltaP99Ms { get; set; }
    public double FrameDeltaMaxMs { get; set; }
    public double FrameDeltaMeanMs { get; set; }
    public int FrameDeltaGt16_67Ms { get; set; }
    public int DroppedFramesGt25Ms { get; set; }

    // Memory & GC telemetry at frame 300
    public long PeakWorkingSetBytes { get; set; }
    public double PeakWorkingSetMib { get; set; }
    public long WorkingSetBytes { get; set; }
    public double WorkingSetMib { get; set; }
    public long PrivateMemoryBytes { get; set; }
    public double PrivateMemoryMib { get; set; }
    public long GcTotalAllocatedBytes { get; set; }
    public long GcStreamAllocatedBytes { get; set; }
    public int GcGen0Collections { get; set; }
    public int GcGen1Collections { get; set; }
    public int GcGen2Collections { get; set; }
    public string TimestampUtc { get; set; } = "";
    public double[] RawFrameDeltasMs { get; set; } = [];
    public double[] RawRenderLatenciesMs { get; set; } = [];
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    WriteIndented = false,
    GenerationMode = JsonSourceGenerationMode.Default)]
[JsonSerializable(typeof(TelemetryFrame))]
[JsonSerializable(typeof(BenchColdResult))]
[JsonSerializable(typeof(Bench60FpsResult))]
internal partial class BakeoffJsonContext : JsonSerializerContext
{
}
