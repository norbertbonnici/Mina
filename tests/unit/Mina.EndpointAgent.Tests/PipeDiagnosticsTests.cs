using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Text;
using Mina.EndpointAgent.Ipc;

namespace Mina.EndpointAgent.Tests;

#pragma warning disable CA1305 // locale-invariant formatting doesn't matter for throwaway diagnostic text

/// <summary>
/// TEMPORARY, round 2. The DACL owner bug (ERROR_INVALID_OWNER) is fixed and 61/63 tests pass on
/// real Windows now. One remains genuinely unexplained:
/// A_second_listener_on_the_same_name_is_refused expects a second FirstPipeInstance creation on an
/// already-live pipe name to throw, and on real Windows CI it does not — this is a behavioural
/// question about THREAT_MODEL B1's squatting defence, not a timing one, so a bigger timeout cannot
/// fix it. Isolates one variable the previous round's diagnostic could not, because both of its
/// calls failed for the (now-fixed) unrelated owner reason: does FirstPipeInstance work at all
/// through the ACL-aware creation path specifically, as opposed to a plain pipe with no custom
/// security. Remove once the real cause is known.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PipeDiagnosticsTests
{
    [WindowsOnlyFact]
    public void FirstPipeInstance_via_plain_creation_no_acl()
    {
        var pipeName = "mina-diag2-plain-" + Guid.NewGuid().ToString("N");
        var report = new StringBuilder();

        using var first = new NamedPipeServerStream(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance);
        report.AppendLine("First (plain, no ACL) creation succeeded.");

        try
        {
            using var second = new NamedPipeServerStream(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance);
            report.AppendLine("Second (plain, no ACL) creation on the SAME name SUCCEEDED " +
                "(expected: should throw IOException per FirstPipeInstance semantics).");
        }
        catch (Exception ex)
        {
            report.AppendLine($"Second (plain, no ACL) creation correctly FAILED: {Describe(ex)}");
        }

        Assert.Fail(report.ToString());
    }

    [WindowsOnlyFact]
    public void FirstPipeInstance_via_acl_creation_now_that_owner_is_fixed()
    {
        var pipeName = "mina-diag2-acl-" + Guid.NewGuid().ToString("N");
        var report = new StringBuilder();

        using var first = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
            inBufferSize: 4096, outBufferSize: 4096, TrayPipeSecurity.Create());
        report.AppendLine("First (ACL, fixed) creation succeeded.");

        try
        {
            using var second = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                inBufferSize: 4096, outBufferSize: 4096, TrayPipeSecurity.Create());
            report.AppendLine("Second (ACL, fixed) creation on the SAME name SUCCEEDED " +
                "(expected: should throw IOException per FirstPipeInstance semantics — this is " +
                "what A_second_listener_on_the_same_name_is_refused asserts against the real server).");
        }
        catch (Exception ex)
        {
            report.AppendLine($"Second (ACL, fixed) creation correctly FAILED: {Describe(ex)}");
        }

        Assert.Fail(report.ToString());
    }

    [WindowsOnlyFact]
    public void FirstPipeInstance_via_the_real_TrayIpcServer_paths_directly()
    {
        // Exactly what A_second_listener_on_the_same_name_is_refused does, but calling
        // TrayIpcServer.CreateInstance-equivalent logic isn't accessible (private), so this
        // reproduces it one layer down: two ACL creations back to back, no BackgroundService/async
        // machinery in between, to rule out a timing gap in how StartAsync schedules ExecuteAsync.
        var pipeName = "mina-diag2-direct-" + Guid.NewGuid().ToString("N");
        var report = new StringBuilder();

        NamedPipeServerStream? first = null;
        NamedPipeServerStream? second = null;
        try
        {
            first = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 4, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                inBufferSize: 4096, outBufferSize: 4096, TrayPipeSecurity.Create());
            report.AppendLine("First creation (Instances=4, matching production default) succeeded.");

            second = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 4, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                inBufferSize: 4096, outBufferSize: 4096, TrayPipeSecurity.Create());
            report.AppendLine("Second creation with Instances=4 also SUCCEEDED (matches CI failure).");
        }
        catch (Exception ex)
        {
            report.AppendLine($"FAILED as expected: {Describe(ex)}");
        }
        finally
        {
            first?.Dispose();
            second?.Dispose();
        }

        Assert.Fail(report.ToString());
    }

    private static string Describe(Exception ex)
    {
        var hresultHex = $"0x{ex.HResult:X8}";
        var win32Guess = (ex.HResult & 0xFFFF0000) == unchecked((int)0x80070000)
            ? (ex.HResult & 0xFFFF).ToString()
            : "n/a";

        return $"{ex.GetType().FullName}: \"{ex.Message}\" HResult={hresultHex} (Win32 guess: {win32Guess})";
    }
}
