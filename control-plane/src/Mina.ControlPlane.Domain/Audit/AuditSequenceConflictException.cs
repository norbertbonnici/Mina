namespace Mina.ControlPlane.Domain.Audit;

/// <summary>
/// Two writers raced for the same position in the chain and this one lost. The caller re-reads the
/// tip and appends again; the chain never forks, because the store's unique sequence lets exactly
/// one of them win.
/// </summary>
public sealed class AuditSequenceConflictException : Exception
{
    public AuditSequenceConflictException()
        : base("The audit sequence was taken by another writer.")
    {
    }

    public AuditSequenceConflictException(string message)
        : base(message)
    {
    }

    public AuditSequenceConflictException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
