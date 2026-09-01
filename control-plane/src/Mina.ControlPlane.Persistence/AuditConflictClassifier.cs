using System.Data.Common;
using Microsoft.EntityFrameworkCore;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// Decides whether a failed audit append was another writer taking the sequence, or a genuine
/// database failure.
/// </summary>
/// <remarks>
/// The distinction matters because the two demand opposite responses. A sequence conflict is
/// expected under concurrency and is safely retried by re-reading the tip. Anything else — a
/// truncation, a null violation, a deadlock, a dropped connection — is a real fault, and calling it
/// a conflict both burns the retry budget against a database that is not going to recover and names
/// the wrong cause in the error whoever is on call eventually reads.
///
/// The test is deliberately semantic rather than a list of provider error numbers. "Another writer
/// took this position" means exactly one thing — a row with that sequence now exists — and asking
/// the database that question answers it precisely, for every provider, with no driver types
/// leaking into this assembly (Azure SQL in production, SQLite in the integration tests, and
/// whatever a future environment uses). Matching on SQL Server's 2601/2627 and SQLite's extended
/// constraint codes would need this project to reference both drivers and would still be a guess
/// about which constraint fired.
///
/// The probe runs only on the failure path, and only failure to answer it is treated as "not a
/// conflict": if the database cannot even be read, this is not contention.
/// </remarks>
internal static class AuditConflictClassifier
{
    public static async Task<bool> IsSequenceTakenAsync(
        MinaDbContext context, long sequence, CancellationToken cancellationToken)
    {
        try
        {
            return await context.AuditEvents
                .AsNoTracking()
                .AnyAsync(e => e.Sequence == sequence, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is DbException or DbUpdateException or InvalidOperationException)
        {
            // The database could not answer. Whatever went wrong, it is not another writer winning
            // a race, so let the original failure be reported as the fault it is.
            return false;
        }
    }
}
