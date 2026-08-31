using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Mina.ControlPlane.Persistence;

/// <summary>
/// Design-time factory so <c>dotnet ef migrations</c> can build the model without starting the API
/// or reaching a database. The connection string here is a placeholder: migration scaffolding needs
/// only the provider and the model, never a live server.
/// </summary>
public sealed class MinaDbContextFactory : IDesignTimeDbContextFactory<MinaDbContext>
{
    public MinaDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<MinaDbContext>()
            .UseSqlServer("Server=(design-time);Database=Mina;")
            .Options;

        return new MinaDbContext(options);
    }
}
