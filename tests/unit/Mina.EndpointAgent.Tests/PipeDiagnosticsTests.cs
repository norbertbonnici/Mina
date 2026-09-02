using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Mina.EndpointAgent.Ipc;

namespace Mina.EndpointAgent.Tests;

#pragma warning disable CA1305 // locale-invariant formatting doesn't matter for throwaway diagnostic text

/// <summary>
/// TEMPORARY. Not a correctness test: every method here deliberately fails, so its report is
/// captured by CI regardless of console-logger verbosity (proven reliable via `--log-failed` on
/// three prior runs; Console output from a *passing* test is not). Exists to answer one question
/// with facts instead of another guess: TrayIpcServerTests/TrayViewModelTests fail 100% of the time
/// on GitHub's windows-latest runner — every connect times out even completely uncontended, and
/// A_second_listener_on_the_same_name_is_refused (which never touches a client at all) also fails,
/// with FirstPipeInstance not detecting a duplicate name. That is not a timing problem. Remove this
/// file once the real cause is known and fixed.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PipeDiagnosticsTests
{
    [WindowsOnlyFact]
    public void Identity_and_group_membership()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);

        var report = new StringBuilder()
            .AppendLine($"Name: {identity.Name}")
            .AppendLine($"User SID: {identity.User}")
            .AppendLine($"Owner SID: {identity.Owner}")
            .AppendLine($"AuthenticationType: {identity.AuthenticationType}")
            .AppendLine($"ImpersonationLevel: {identity.ImpersonationLevel}")
            .AppendLine($"IsSystem: {identity.IsSystem}")
            .AppendLine($"In Administrators: {principal.IsInRole(WindowsBuiltInRole.Administrator)}")
            .AppendLine($"In INTERACTIVE: {principal.IsInRole(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null))}")
            .AppendLine($"In LOCAL SYSTEM role check: {principal.IsInRole(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null))}")
            .AppendLine("Groups:")
            .AppendLine(string.Join(
                Environment.NewLine,
                identity.Groups?.Select(g =>
                {
                    try
                    {
                        return $"  {g.Translate(typeof(NTAccount))} ({g.Value})";
                    }
                    catch (IdentityNotMappedException)
                    {
                        return $"  <unmapped> ({g.Value})";
                    }
                }) ?? []));

        Assert.Fail(report.ToString());
    }

    [WindowsOnlyFact]
    public async Task Plain_pipe_no_custom_security_connects()
    {
        var pipeName = "mina-diag-plain-" + Guid.NewGuid().ToString("N");
        var report = new StringBuilder();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            using var server = new NamedPipeServerStream(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance);
            report.AppendLine($"Server created at {sw.ElapsedMilliseconds}ms (no custom ACL).");

            var acceptTask = server.WaitForConnectionAsync();

            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await client.ConnectAsync(connectTimeout.Token);
            report.AppendLine($"Client connected at {sw.ElapsedMilliseconds}ms.");

            await acceptTask.WaitAsync(TimeSpan.FromSeconds(5));
            report.AppendLine($"Server accepted at {sw.ElapsedMilliseconds}ms. SUCCESS.");
        }
        catch (Exception ex)
        {
            report.AppendLine($"FAILED at {sw.ElapsedMilliseconds}ms: {Describe(ex)}");
        }

        Assert.Fail(report.ToString());
    }

    [WindowsOnlyFact]
    public void Acl_pipe_creation_with_system_owner()
    {
        var pipeName = "mina-diag-acl-owner-" + Guid.NewGuid().ToString("N");
        var report = new StringBuilder();

        try
        {
            using var server = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                inBufferSize: 4096, outBufferSize: 4096, TrayPipeSecurity.Create());
            report.AppendLine("Creation with SetOwner(SYSTEM) SUCCEEDED.");

            try
            {
                var actual = server.GetAccessControl();
                report.AppendLine($"Resulting owner (as read back): {actual.GetOwner(typeof(NTAccount))}");
                report.AppendLine("SDDL: " + actual.GetSecurityDescriptorSddlForm(AccessControlSections.All));
            }
            catch (Exception ex)
            {
                report.AppendLine($"Could not read back the security descriptor: {Describe(ex)}");
            }
        }
        catch (Exception ex)
        {
            report.AppendLine($"Creation with SetOwner(SYSTEM) FAILED: {Describe(ex)}");
        }

        Assert.Fail(report.ToString());
    }

    [WindowsOnlyFact]
    public async Task Acl_pipe_without_explicit_owner_connects()
    {
        // Same access rules as production (SYSTEM full control, INTERACTIVE read/write), but no
        // SetOwner call — isolates whether assigning SYSTEM as owner specifically is the problem,
        // separate from having a custom DACL at all.
        var pipeName = "mina-diag-acl-noowner-" + Guid.NewGuid().ToString("N");
        var report = new StringBuilder();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        var security = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            interactive, PipeAccessRights.Read | PipeAccessRights.Write | PipeAccessRights.Synchronize,
            AccessControlType.Allow));

        try
        {
            using var server = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                inBufferSize: 4096, outBufferSize: 4096, security);
            report.AppendLine($"Creation without SetOwner SUCCEEDED at {sw.ElapsedMilliseconds}ms.");

            var acceptTask = server.WaitForConnectionAsync();
            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await client.ConnectAsync(connectTimeout.Token);
            report.AppendLine($"Client connected at {sw.ElapsedMilliseconds}ms.");

            await acceptTask.WaitAsync(TimeSpan.FromSeconds(5));
            report.AppendLine($"Server accepted at {sw.ElapsedMilliseconds}ms. SUCCESS.");
        }
        catch (Exception ex)
        {
            report.AppendLine($"FAILED at {sw.ElapsedMilliseconds}ms: {Describe(ex)}");
        }

        Assert.Fail(report.ToString());
    }

    [WindowsOnlyFact]
    public async Task Acl_pipe_with_system_owner_connects_given_a_minute()
    {
        // The real production DACL (TrayPipeSecurity.Create(), SetOwner(SYSTEM) included), but with
        // a very generous connect budget and no other test running at all — isolates "needs much
        // longer than 20s" from "never works regardless of how long you wait."
        var pipeName = "mina-diag-acl-generous-" + Guid.NewGuid().ToString("N");
        var report = new StringBuilder();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            using var server = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                inBufferSize: 4096, outBufferSize: 4096, TrayPipeSecurity.Create());
            report.AppendLine($"Created at {sw.ElapsedMilliseconds}ms.");

            var acceptTask = server.WaitForConnectionAsync();

            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            await client.ConnectAsync(connectTimeout.Token);
            report.AppendLine($"Client connected at {sw.ElapsedMilliseconds}ms.");

            await acceptTask.WaitAsync(TimeSpan.FromSeconds(10));
            report.AppendLine($"Server accepted at {sw.ElapsedMilliseconds}ms. SUCCESS.");
        }
        catch (Exception ex)
        {
            report.AppendLine($"FAILED at {sw.ElapsedMilliseconds}ms (budget 60s): {Describe(ex)}");
        }

        Assert.Fail(report.ToString());
    }

    [WindowsOnlyFact]
    public void FirstPipeInstance_second_attempt_on_same_name_in_isolation()
    {
        var pipeName = "mina-diag-dup-" + Guid.NewGuid().ToString("N");
        var report = new StringBuilder();

        NamedPipeServerStream? first = null;
        try
        {
            first = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                inBufferSize: 4096, outBufferSize: 4096, TrayPipeSecurity.Create());
            report.AppendLine("First FirstPipeInstance creation SUCCEEDED.");
        }
        catch (Exception ex)
        {
            report.AppendLine($"First FirstPipeInstance creation FAILED (unexpected): {Describe(ex)}");
        }

        try
        {
            using var second = NamedPipeServerStreamAcl.Create(
                pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                inBufferSize: 4096, outBufferSize: 4096, TrayPipeSecurity.Create());
            report.AppendLine("Second FirstPipeInstance creation on the SAME name SUCCEEDED " +
                "(production expects this to throw IOException).");
        }
        catch (Exception ex)
        {
            report.AppendLine($"Second FirstPipeInstance creation correctly FAILED: {Describe(ex)}");
        }
        finally
        {
            first?.Dispose();
        }

        Assert.Fail(report.ToString());
    }

    private static string Describe(Exception ex)
    {
        var hresultHex = $"0x{ex.HResult:X8}";
        // For HRESULT_FROM_WIN32-shaped values (facility 0x7, top bit set), the low 16 bits are the
        // original Win32 error code.
        var win32Guess = (ex.HResult & 0xFFFF0000) == unchecked((int)0x80070000)
            ? (ex.HResult & 0xFFFF).ToString()
            : "n/a";

        return $"{ex.GetType().FullName}: \"{ex.Message}\" HResult={hresultHex} (Win32 guess: {win32Guess})" +
            (ex.InnerException is { } inner ? $" | inner: {Describe(inner)}" : string.Empty);
    }
}
