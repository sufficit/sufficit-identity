using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddIdentityApplicationMetrics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "identityapplicationusageevents",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    occurredatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    clientid = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    eventtype = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    endpointtype = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    granttype = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    outcome = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    subjecthash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_identityapplicationusageevents", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "identitymetricsconfiguration",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false),
                    enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    retentiondays = table.Column<int>(type: "int", nullable: false),
                    exportenabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    provider = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    endpoint = table.Column<string>(type: "varchar(1024)", maxLength: 1024, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    database = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    authorizationscheme = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    username = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    secretciphertext = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    timeoutseconds = table.Column<int>(type: "int", nullable: false),
                    batchsize = table.Column<int>(type: "int", nullable: false),
                    updatedatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_identitymetricsconfiguration", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_identityusage_clientid_occurredatutc",
                table: "identityapplicationusageevents",
                columns: new[] { "clientid", "occurredatutc" });

            migrationBuilder.CreateIndex(
                name: "IX_identityusage_eventtype_occurredatutc",
                table: "identityapplicationusageevents",
                columns: new[] { "eventtype", "occurredatutc" });

            migrationBuilder.CreateIndex(
                name: "IX_identityusage_occurredatutc",
                table: "identityapplicationusageevents",
                column: "occurredatutc");

            migrationBuilder.InsertData(
                table: "identitymetricsconfiguration",
                columns: new[]
                {
                    "id", "enabled", "retentiondays", "exportenabled",
                    "provider", "timeoutseconds", "batchsize", "updatedatutc"
                },
                values: new object[]
                {
                    1, true, 90, false, "internal", 10, 250,
                    new DateTime(2026, 8, 7, 2, 8, 59, DateTimeKind.Utc)
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "identityapplicationusageevents");

            migrationBuilder.DropTable(
                name: "identitymetricsconfiguration");
        }
    }
}
