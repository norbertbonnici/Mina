using Microsoft.Extensions.Options;
using Mina.ControlPlane.Application.Audit;
using Mina.ControlPlane.Application.Configuration;
using Mina.ControlPlane.Application.SensitiveSessions;
using Mina.ControlPlane.Application.Sessions;

namespace Mina.ControlPlane.Application.Tests;

/// <summary>
/// Configuration that would produce an insecure or silently broken platform must stop the host, not
/// surface later as a database error or as a workflow that quietly refuses everything. Each case
/// here is a value that started a healthy-looking host before this validation existed.
/// </summary>
public class OptionsValidationTests
{
    [Fact]
    public void The_shipped_defaults_are_valid()
    {
        Assert.True(Validate(new SensitiveSessionOptions()).Succeeded);
        Assert.True(Validate(new SessionServiceOptions()).Succeeded);
        Assert.True(new AuditOptionsValidator().Validate(null, new AuditOptions()).Succeeded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_non_positive_expiry_batch_is_refused(int batch)
    {
        // "0 means unlimited" is a natural reading and it is wrong here: the repository refuses a
        // limit below 1, the sweeper catches and retries, and the host stays healthy while
        // approvals stop expiring altogether — suppression outliving its window with no signal.
        var result = Validate(new SensitiveSessionOptions { ExpirySweepBatchSize = batch });

        Assert.True(result.Failed);
        Assert.Contains("ExpirySweepBatchSize", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void A_non_positive_queue_page_is_refused()
    {
        var result = Validate(new SensitiveSessionOptions { ApproverQueuePageSize = 0 });

        Assert.True(result.Failed);
        Assert.Contains("ApproverQueuePageSize", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(24)]
    [InlineData(48)]
    public void A_suppression_window_outside_the_storable_range_is_refused(int hours)
    {
        var result = Validate(new SensitiveSessionOptions { MaxDuration = TimeSpan.FromHours(hours) });

        Assert.True(result.Failed);
        Assert.Contains("MaxDuration", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void One_role_for_both_requester_and_approver_is_refused()
    {
        var result = Validate(new SensitiveSessionOptions
        {
            AnalystRole = "Mina.Analyst",
            ApproverRole = "Mina.Analyst",
        });

        Assert.True(result.Failed);
        Assert.Contains("distinct role", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(" ")]
    [InlineData(" c1")]
    [InlineData("c1 ")]
    public void A_padded_authentication_context_is_refused(string value)
    {
        // Whitespace here is worse than either extreme. The gate switches on "is this non-blank"
        // but matches with an exact ordinal comparison, so " " silently disables the compliance
        // check while " c1" arms a gate no token can satisfy — and the claims challenge then names
        // an id that does not exist in the tenant. Neither looks different from working.
        var result = Validate(new SessionServiceOptions { RequiredAuthContextId = value });

        Assert.True(result.Failed);
        Assert.Contains("RequiredAuthContextId", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_authentication_context_is_valid_and_means_disabled()
    {
        Assert.True(Validate(new SessionServiceOptions { RequiredAuthContextId = string.Empty }).Succeeded);
        Assert.True(Validate(new SessionServiceOptions { RequiredAuthContextId = "c1" }).Succeeded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(25)]
    public void A_lease_outside_the_permitted_range_is_refused(int hours)
    {
        // The lease is also the session certificate's lifetime, so a mistyped value does not merely
        // keep a row alive — it mints a long-lived credential for the egress tunnel.
        var result = Validate(new SessionServiceOptions { LeaseTtl = TimeSpan.FromHours(hours) });

        Assert.True(result.Failed);
        Assert.Contains("LeaseTtl", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void An_audit_environment_must_be_set_and_appends_must_be_attempted()
    {
        Assert.True(new AuditOptionsValidator()
            .Validate(null, new AuditOptions { Environment = "  " }).Failed);
        Assert.True(new AuditOptionsValidator()
            .Validate(null, new AuditOptions { MaxAppendAttempts = 0 }).Failed);
    }

    [Fact]
    public void A_configured_export_container_uri_must_be_an_absolute_https_uri()
    {
        // Unset is valid — it means the filesystem sink runs, gated by HostingGuard instead (M4-19).
        Assert.True(new AuditOptionsValidator().Validate(null, new AuditOptions()).Succeeded);

        Assert.True(new AuditOptionsValidator()
            .Validate(null, new AuditOptions
            {
                ExportContainerUri = "https://staccountaudit.blob.core.windows.net/audit-exports",
            })
            .Succeeded);

        Assert.True(new AuditOptionsValidator()
            .Validate(null, new AuditOptions { ExportContainerUri = "not a uri" }).Failed);
        Assert.True(new AuditOptionsValidator()
            .Validate(null, new AuditOptions
            {
                // http, not https: a storage account reachable in plain text is not immutable
                // storage, it is a storage account someone forgot to configure.
                ExportContainerUri = "http://staccountaudit.blob.core.windows.net/audit-exports",
            })
            .Failed);
    }

    private static ValidateOptionsResult Validate(SensitiveSessionOptions options) =>
        new SensitiveSessionOptionsValidator().Validate(null, options);

    private static ValidateOptionsResult Validate(SessionServiceOptions options) =>
        new SessionServiceOptionsValidator().Validate(null, options);
}
