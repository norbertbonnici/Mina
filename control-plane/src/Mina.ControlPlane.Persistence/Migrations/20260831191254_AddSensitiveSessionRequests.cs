using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mina.ControlPlane.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddSensitiveSessionRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<DateTime>(
                name: "LeaseExpiresAt",
                table: "Sessions",
                type: "datetime2",
                nullable: false,
                oldClrType: typeof(DateTimeOffset),
                oldType: "datetimeoffset");

            migrationBuilder.AlterColumn<DateTime>(
                name: "EndedAt",
                table: "Sessions",
                type: "datetime2",
                nullable: true,
                oldClrType: typeof(DateTimeOffset),
                oldType: "datetimeoffset",
                oldNullable: true);

            migrationBuilder.AlterColumn<DateTime>(
                name: "CreatedAt",
                table: "Sessions",
                type: "datetime2",
                nullable: false,
                oldClrType: typeof(DateTimeOffset),
                oldType: "datetimeoffset");

            migrationBuilder.CreateTable(
                name: "SensitiveSessionRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SessionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequesterObjectId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    RequesterUpn = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    JustificationReference = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    RequestedDuration = table.Column<TimeSpan>(type: "time", nullable: false),
                    RequestedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    State = table.Column<string>(type: "nvarchar(24)", maxLength: 24, nullable: false),
                    ApproverObjectId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    ApproverUpn = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    ApprovedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ActivatedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    EndedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    EndReason = table.Column<string>(type: "nvarchar(24)", maxLength: 24, nullable: true),
                    Version = table.Column<int>(type: "int", nullable: false, defaultValue: 0)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SensitiveSessionRequests", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SensitiveSessionRequests_SessionId",
                table: "SensitiveSessionRequests",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_SensitiveSessionRequests_State_ExpiresAt",
                table: "SensitiveSessionRequests",
                columns: new[] { "State", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_SensitiveSessionRequests_State_RequestedAt",
                table: "SensitiveSessionRequests",
                columns: new[] { "State", "RequestedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SensitiveSessionRequests");

            migrationBuilder.AlterColumn<DateTimeOffset>(
                name: "LeaseExpiresAt",
                table: "Sessions",
                type: "datetimeoffset",
                nullable: false,
                oldClrType: typeof(DateTime),
                oldType: "datetime2");

            migrationBuilder.AlterColumn<DateTimeOffset>(
                name: "EndedAt",
                table: "Sessions",
                type: "datetimeoffset",
                nullable: true,
                oldClrType: typeof(DateTime),
                oldType: "datetime2",
                oldNullable: true);

            migrationBuilder.AlterColumn<DateTimeOffset>(
                name: "CreatedAt",
                table: "Sessions",
                type: "datetimeoffset",
                nullable: false,
                oldClrType: typeof(DateTime),
                oldType: "datetime2");
        }
    }
}
