using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mina.ControlPlane.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddTelemetryTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "telemetry");

            migrationBuilder.CreateTable(
                name: "Hostnames",
                schema: "telemetry",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SessionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Region = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    OccurredAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Hostname = table.Column<string>(type: "nvarchar(253)", maxLength: 253, nullable: false),
                    Port = table.Column<int>(type: "int", nullable: false),
                    BytesUp = table.Column<long>(type: "bigint", nullable: false),
                    BytesDown = table.Column<long>(type: "bigint", nullable: false),
                    DurationMs = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Hostnames", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SuppressedTraffic",
                schema: "telemetry",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SessionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Region = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    IntervalStart = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ConnectionCount = table.Column<int>(type: "int", nullable: false),
                    BytesTotal = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SuppressedTraffic", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Hostnames_OccurredAt",
                schema: "telemetry",
                table: "Hostnames",
                column: "OccurredAt");

            migrationBuilder.CreateIndex(
                name: "IX_Hostnames_SessionId_OccurredAt",
                schema: "telemetry",
                table: "Hostnames",
                columns: new[] { "SessionId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_SuppressedTraffic_SessionId_IntervalStart",
                schema: "telemetry",
                table: "SuppressedTraffic",
                columns: new[] { "SessionId", "IntervalStart" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Hostnames",
                schema: "telemetry");

            migrationBuilder.DropTable(
                name: "SuppressedTraffic",
                schema: "telemetry");
        }
    }
}
