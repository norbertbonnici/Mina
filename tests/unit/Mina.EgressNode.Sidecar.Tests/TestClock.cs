namespace Mina.EgressNode.Sidecar.Tests;

/// <summary>
/// A clock whose wall time and monotonic timestamp both follow <see cref="Now"/>, so a test can
/// age the session view without waiting.
/// </summary>
internal sealed class TestClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;

    public override long GetTimestamp() => Now.UtcTicks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
}
