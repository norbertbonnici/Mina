namespace Mina.ControlPlane.Domain;

/// <summary>
/// Commits everything mutated in the current unit of work together.
/// </summary>
/// <remarks>
/// Needed where one governance decision changes more than one aggregate. Suppression expiry, for
/// instance, ends the approval *and* terminates the session it belonged to; committing those
/// separately meant a failure in between could leave an expired approval with a live session still
/// in sensitive mode, browsing past the window an approver granted (D-06).
/// </remarks>
public interface IUnitOfWork
{
    Task CommitAsync(CancellationToken cancellationToken);
}
