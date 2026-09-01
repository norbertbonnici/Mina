using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Persistence;
using Mina.ControlPlane.Pki;

namespace Mina.ControlPlane.Persistence.Tests;

/// <summary>
/// A real relational database for the persistence tests, using SQLite in-memory. It exercises the
/// same EF Core mapping, change tracking and concurrency behaviour as Azure SQL without needing a
/// server; the connection is held open because an in-memory SQLite database only lives as long as
/// its connection.
/// </summary>
/// <remarks>
/// SQLite is not SQL Server: provider-specific behaviour (column types, collation, retry) is
/// verified against Azure SQL when the dev environment exists. What these tests do prove is the
/// mapping, the aggregate round-trip and the optimistic-concurrency contract.
/// </remarks>
public sealed class SqliteDatabaseFixture : IDisposable
{
    private readonly SqliteConnection _connection;

    public SqliteDatabaseFixture()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        using var context = CreateContext();
        context.Database.EnsureCreated();
    }

    public MinaDbContext CreateContext() =>
        new(new DbContextOptionsBuilder<MinaDbContext>().UseSqlite(_connection).Options);

    public void Dispose() => _connection.Dispose();
}

/// <summary>Holds one issuing CA for a test class, so tests do not pay to mint a key each time.</summary>
/// <remarks>
/// The window is deliberately wide. Tests drive the service from fixed clocks, and a CA anchored a
/// day either side of "now" silently stops covering those instants as the calendar moves — issuing
/// a leaf that starts before its issuer does throws, and the suite starts failing on a date rather
/// than on a change.
/// </remarks>
public sealed class TestCertificateAuthorityFixture : IDisposable
{
    public CertificateAuthority Authority { get; } =
        CertificateAuthority.Create("Mina Test CA", DateTimeOffset.UtcNow.AddYears(-2), TimeSpan.FromDays(365 * 5));

    public void Dispose() => Authority.Dispose();
}
