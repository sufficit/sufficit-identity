using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AggregateUsageMetrics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "identityapplicationusagedaily",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    day = table.Column<DateTime>(type: "date", nullable: false),
                    node = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    clientid = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    eventtype = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    endpointtype = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    granttype = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    outcome = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    count = table.Column<long>(type: "bigint", nullable: false),
                    lastoccurredatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_identityapplicationusagedaily", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_identityusagedaily_clientid_day",
                table: "identityapplicationusagedaily",
                columns: new[] { "clientid", "day" });

            migrationBuilder.CreateIndex(
                name: "IX_identityusagedaily_key",
                table: "identityapplicationusagedaily",
                columns: new[] { "day", "node", "clientid", "eventtype", "endpointtype", "granttype", "outcome" },
                unique: true);

            // History moves into the aggregate as node "legacy" (one row per day
            // and dimension); the per-event table and its user hashes then go.
            migrationBuilder.Sql(
                "INSERT INTO `identityapplicationusagedaily` (`day`, `node`, `clientid`, `eventtype`, `endpointtype`, " +
                "`granttype`, `outcome`, `count`, `lastoccurredatutc`) " +
                "SELECT DATE(`occurredatutc`), 'legacy', `clientid`, `eventtype`, `endpointtype`, COALESCE(`granttype`, ''), " +
                "`outcome`, COUNT(*), MAX(`occurredatutc`) FROM `identityapplicationusageevents` " +
                "GROUP BY DATE(`occurredatutc`), `clientid`, `eventtype`, `endpointtype`, COALESCE(`granttype`, ''), `outcome`;");

            migrationBuilder.DropTable(
                name: "identityapplicationusageevents");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "identityapplicationusagedaily");

            migrationBuilder.CreateTable(
                name: "identityapplicationusageevents",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    clientid = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    endpointtype = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    eventtype = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    granttype = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    occurredatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
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
        }
    }
}
