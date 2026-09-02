using Mina.ControlPlane.Domain;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// Commits the scoped <see cref="MinaDbContext"/>. Because every repository in a request shares
/// that context, changes made through several of them commit in one transaction.
/// </summary>
public sealed class EfUnitOfWork(MinaDbContext context) : IUnitOfWork
{
    private readonly MinaDbContext _context = context ?? throw new ArgumentNullException(nameof(context));

    public Task CommitAsync(CancellationToken cancellationToken) => _context.SaveChangesAsync(cancellationToken);
}

/// <summary>
/// Unit of work for the in-memory stores, which hold the aggregate instances themselves, so a
/// mutation is already visible and there is nothing to commit.
/// </summary>
/// <remarks>
/// This provides no atomicity. The in-memory stores are for local development only; the guarantee
/// that matters comes from <see cref="EfUnitOfWork"/> against a real database.
/// </remarks>
public sealed class InMemoryUnitOfWork : IUnitOfWork
{
    public Task CommitAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
