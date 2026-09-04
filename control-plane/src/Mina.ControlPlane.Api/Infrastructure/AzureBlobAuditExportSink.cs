using System.Globalization;
using System.Text.RegularExpressions;
using Azure;
using Azure.Core;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Mina.ControlPlane.Application.Audit;

namespace Mina.ControlPlane.Api.Infrastructure;

/// <summary>
/// Writes audit exports to an Azure Storage container protected by a time-based immutability
/// policy (D-18, M4-19).
/// </summary>
/// <remarks>
/// This is the production sink <see cref="FileSystemAuditExportSink"/>'s own remarks describe: the
/// container's immutability policy (Terraform, <c>control-plane-azure</c>) is what actually enforces
/// write-once here, not this class — a delete or overwrite attempt against a blob still inside its
/// retention window is refused by the storage service itself, before this code runs, and refused
/// even to the subscription owner. This class only has to not race itself: <see cref="WriteAsync"/>
/// uses a conditional upload (create-if-absent, not a check-then-write) so two writers racing the
/// same name get one winner and one clean refusal, the same guarantee
/// <c>FileMode.CreateNew</c> gives the filesystem sink.
/// </remarks>
public sealed partial class AzureBlobAuditExportSink : IAuditExportSink
{
    private readonly BlobContainerClient _container;
    private readonly string _environment;

    public AzureBlobAuditExportSink(Uri containerUri, TokenCredential credential, string environment)
    {
        ArgumentNullException.ThrowIfNull(containerUri);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentException.ThrowIfNullOrWhiteSpace(environment);

        _container = new BlobContainerClient(containerUri, credential);
        _environment = environment;
    }

    public async Task WriteAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var blob = _container.GetBlobClient(name);
        try
        {
            using var stream = new MemoryStream(content.ToArray(), writable: false);
            // overwrite: false asks the service for a conditional upload (If-None-Match: *) rather
            // than a check-then-write here — two writers racing the same name get one winner and
            // one 409, never a silent replace.
            await blob.UploadAsync(stream, overwrite: false, cancellationToken).ConfigureAwait(false);
        }
        catch (RequestFailedException ex) when (ex.Status == 409)
        {
            throw new InvalidOperationException(
                $"An export named '{name}' already exists; exports are write-once.", ex);
        }
    }

    public async Task<ReadOnlyMemory<byte>?> ReadAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        try
        {
            var response = await _container.GetBlobClient(name)
                .DownloadContentAsync(cancellationToken)
                .ConfigureAwait(false);
            return response.Value.Content.ToArray();
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public async Task<long?> GetLastExportedSequenceAsync(CancellationToken cancellationToken)
    {
        // Only this environment's exports — see FileSystemAuditExportSink's remarks on the same
        // property: sharing a container across environments and taking the highest sequence
        // anywhere in it would let one environment's export set another's high-water mark.
        long? highest = null;
        await foreach (var blob in _container
            .GetBlobsAsync(BlobTraits.None, BlobStates.None, $"{_environment}/", cancellationToken)
            .ConfigureAwait(false))
        {
            var match = ExportNamePattern().Match(blob.Name);
            if (match.Success
                && long.TryParse(match.Groups["to"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var to)
                && (highest is null || to > highest))
            {
                highest = to;
            }
        }

        return highest;
    }

    [GeneratedRegex(@"^[^/]+/audit-(?<from>\d+)-(?<to>\d+)-.*\.jsonl$")]
    private static partial Regex ExportNamePattern();
}
