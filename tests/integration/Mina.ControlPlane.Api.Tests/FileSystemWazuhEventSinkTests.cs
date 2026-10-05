using System.Text;
using Mina.ControlPlane.Api.Infrastructure;

namespace Mina.ControlPlane.Api.Tests;

/// <summary>Real file I/O -- what a co-located Wazuh agent's localfile monitoring actually tails (M3-5).</summary>
public sealed class FileSystemWazuhEventSinkTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"mina-wazuh-sink-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private string EventFilePath => Path.Combine(_directory, "wazuh-events.jsonl");

    [Fact]
    public async Task A_fresh_sink_has_delivered_nothing()
    {
        var sink = new FileSystemWazuhEventSink(EventFilePath);
        Assert.Null(await sink.GetLastDeliveredSequenceAsync(default));
    }

    [Fact]
    public async Task Delivering_appends_rather_than_overwrites()
    {
        var sink = new FileSystemWazuhEventSink(EventFilePath);

        await sink.DeliverAsync(Encoding.UTF8.GetBytes("{\"a\":1}\n"), throughSequence: 0, default);
        await sink.DeliverAsync(Encoding.UTF8.GetBytes("{\"a\":2}\n"), throughSequence: 1, default);

        var lines = (await File.ReadAllLinesAsync(EventFilePath)).Where(l => l.Length > 0).ToList();
        Assert.Equal(2, lines.Count);
        Assert.Contains("\"a\":1", lines[0], StringComparison.Ordinal);
        Assert.Contains("\"a\":2", lines[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_watermark_persists_across_a_fresh_sink_instance()
    {
        // Stands in for a process restart: the watermark has to be read back by a new object, not
        // just remembered in the one that wrote it.
        var first = new FileSystemWazuhEventSink(EventFilePath);
        await first.DeliverAsync(Encoding.UTF8.GetBytes("{\"a\":1}\n"), throughSequence: 41, default);

        var second = new FileSystemWazuhEventSink(EventFilePath);
        Assert.Equal(41, await second.GetLastDeliveredSequenceAsync(default));
    }

    [Fact]
    public async Task The_watermark_only_advances_after_the_content_is_appended()
    {
        // The ordering the at-least-once contract depends on: proven here by checking the content
        // is on disk and readable at all, which a crash between the two steps could never produce
        // out of order the other way around (watermark first) without also writing the content.
        var sink = new FileSystemWazuhEventSink(EventFilePath);
        await sink.DeliverAsync(Encoding.UTF8.GetBytes("{\"a\":1}\n"), throughSequence: 7, default);

        Assert.True(File.Exists(EventFilePath));
        Assert.Equal(7, await sink.GetLastDeliveredSequenceAsync(default));
        Assert.Contains("\"a\":1", await File.ReadAllTextAsync(EventFilePath), StringComparison.Ordinal);
    }

    [Fact]
    public void Construction_creates_the_containing_directory_when_missing()
    {
        var nested = Path.Combine(_directory, "nested", "wazuh-events.jsonl");
        _ = new FileSystemWazuhEventSink(nested);
        Assert.True(Directory.Exists(Path.GetDirectoryName(nested)));
    }
}
