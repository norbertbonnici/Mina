using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Mina.ControlPlane.Domain.Coordination;

namespace Mina.ControlPlane.Persistence.Tests;

/// <summary>
/// The lease that decides which control-plane instance exports the audit chain (M4-23). It replaced
/// a configuration switch, so the property that matters is that two instances contending for a free
/// lease produce exactly one holder — a switch cannot get that wrong, and a lease can.
/// </summary>
public sealed class BackgroundLeaseTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 2, 9, 0, 0, TimeSpan.Zero);
    private const string Lease = "audit-export";

    private readonly SqliteConnection _connection;

    public BackgroundLeaseTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        using var context = CreateContext();
        context.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private MinaDbContext CreateContext() =>
        new(new DbContextOptionsBuilder<MinaDbContext>().UseSqlite(_connection).Options);

    private EfBackgroundLeaseStore Store(DateTimeOffset now) =>
        new(CreateContext(), new Fixed(now));

    [Fact]
    public async Task Only_one_of_two_instances_takes_a_free_lease()
    {
        Assert.True(await Store(T0).TryAcquireAsync(Lease, "instance-a", TimeSpan.FromMinutes(45), default));
        Assert.False(await Store(T0).TryAcquireAsync(Lease, "instance-b", TimeSpan.FromMinutes(45), default));
    }

    [Fact]
    public async Task The_holder_renews_without_losing_it()
    {
        await Store(T0).TryAcquireAsync(Lease, "instance-a", TimeSpan.FromMinutes(45), default);

        // Fifteen minutes later, the export's next tick. The holder must keep it, or two instances
        // would trade the work back and forth.
        Assert.True(await Store(T0.AddMinutes(15))
            .TryAcquireAsync(Lease, "instance-a", TimeSpan.FromMinutes(45), default));
        Assert.False(await Store(T0.AddMinutes(15))
            .TryAcquireAsync(Lease, "instance-b", TimeSpan.FromMinutes(45), default));
    }

    [Fact]
    public async Task A_lapsed_lease_is_taken_over_without_anyone_unlocking_it()
    {
        // The reason the lease is short and re-acquired rather than held: an instance that dies, or
        // wedges without dying, releases nothing. Expiry is the only recovery path, and it must not
        // need an operator.
        await Store(T0).TryAcquireAsync(Lease, "instance-a", TimeSpan.FromMinutes(45), default);

        Assert.True(await Store(T0.AddMinutes(46))
            .TryAcquireAsync(Lease, "instance-b", TimeSpan.FromMinutes(45), default));

        // And the original holder does not simply take it back on its next tick.
        Assert.False(await Store(T0.AddMinutes(47))
            .TryAcquireAsync(Lease, "instance-a", TimeSpan.FromMinutes(45), default));
    }

    [Fact]
    public async Task Separate_pieces_of_work_do_not_contend()
    {
        Assert.True(await Store(T0).TryAcquireAsync("audit-export", "a", TimeSpan.FromMinutes(45), default));
        Assert.True(await Store(T0).TryAcquireAsync("something-else", "b", TimeSpan.FromMinutes(45), default));
    }

    private sealed class Fixed(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
