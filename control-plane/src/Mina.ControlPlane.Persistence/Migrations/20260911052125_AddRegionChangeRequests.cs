using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mina.ControlPlane.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddRegionChangeRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RegionChangeRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestedByObjectId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    RequestedByUpn = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Kind = table.Column<string>(type: "nvarchar(24)", maxLength: 24, nullable: false),
                    RegionName = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Justification = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    RequestedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    ResolvedByObjectId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    ResolvedByUpn = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    ResolvedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ResolutionNote = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: true),
                    Version = table.Column<int>(type: "int", nullable: false, defaultValue: 0)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RegionChangeRequests", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RegionChangeRequests_Status_RequestedAt",
                table: "RegionChangeRequests",
                columns: new[] { "Status", "RequestedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_RegionChangeRequests_Status_ResolvedAt",
                table: "RegionChangeRequests",
                columns: new[] { "Status", "ResolvedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RegionChangeRequests");
        }
    }
}
