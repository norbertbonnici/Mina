using Mina.ControlPlane.Application.Sessions;

namespace Mina.ManagementUi.Infrastructure;

/// <summary>
/// Supplies the signed-in user to the form-post endpoints as the application layer's
/// <see cref="SessionPrincipal"/>, so identity reaches the services the same way it does from the
/// API — from validated claims, never from the request body.
/// </summary>
public sealed class ClaimsPrincipalAccessor(IHttpContextAccessor accessor)
{
    public SessionPrincipal Principal =>
        (accessor.HttpContext?.User
         ?? throw new InvalidOperationException("No HTTP context; this type is request-scoped."))
        .ToSessionPrincipal();
}
