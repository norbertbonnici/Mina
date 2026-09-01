using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Mina.ControlPlane.Domain.Audit;
using Mina.ControlPlane.Domain;
using Mina.ControlPlane.Domain.SensitiveSessions;
using Mina.ControlPlane.Domain.Sessions;
using Mina.ControlPlane.Domain.Telemetry;

namespace Mina.ControlPlane.Persistence;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the control-plane database against Azure SQL and the EF-backed session repository.
    /// Authentication is expected to be a managed identity in the connection string
    /// (<c>Authentication=Active Directory Default</c>) — no passwords in configuration (SR-005).
    /// </summary>
    public static IServiceCollection AddMinaSqlPersistence(this IServiceCollection services, string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.AddDbContext<MinaDbContext>(options =>
            options.UseSqlServer(connectionString, sql => sql.EnableRetryOnFailure()));

        services.AddScoped<ISessionRepository, EfSessionRepository>();
        services.AddScoped<ISensitiveSessionRepository, EfSensitiveSessionRepository>();
        services.AddScoped<IAuditEventStore, EfAuditEventStore>();
        services.AddScoped<IUnitOfWork, EfUnitOfWork>();
        return services.AddScoped<ITelemetryRepository, EfTelemetryRepository>();
    }
}
