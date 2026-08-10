using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddVaultSigningKeyLifecycle : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "lifecycleversion",
                table: "vaultkeys",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "retireafterutc",
                table: "vaultkeys",
                type: "datetime(6)",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "revokedatutc",
                table: "vaultkeys",
                type: "datetime(6)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "signingstate",
                table: "vaultkeys",
                type: "varchar(16)",
                maxLength: 16,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            // Rolling-deployment backfill: exactly the latest non-retired
            // signing version becomes active. Older published versions get a
            // conservative 14-day overlap matching the secure default; the
            // runtime subsequently journals their retirement.
            migrationBuilder.Sql(
                "UPDATE vaultkeys SET signingstate = 'Retired' " +
                "WHERE purpose = 'signing' AND retiredatutc IS NOT NULL;");
            migrationBuilder.Sql(
                "UPDATE vaultkeys AS currentkey " +
                "INNER JOIN (" +
                "SELECT keyname, MAX(keyversion) AS activeversion " +
                "FROM vaultkeys WHERE purpose = 'signing' " +
                "AND retiredatutc IS NULL GROUP BY keyname" +
                ") AS latest ON latest.keyname = currentkey.keyname " +
                "SET currentkey.signingstate = CASE " +
                "WHEN currentkey.keyversion = latest.activeversion THEN 'Active' " +
                "ELSE 'Retiring' END, " +
                "currentkey.retireafterutc = CASE " +
                "WHEN currentkey.keyversion = latest.activeversion THEN NULL " +
                "ELSE DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 14 DAY) END " +
                "WHERE currentkey.purpose = 'signing' " +
                "AND currentkey.retiredatutc IS NULL;");

            migrationBuilder.CreateTable(
                name: "vaultsigningkeylocks",
                columns: table => new
                {
                    keyname = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    ownerid = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    expiresatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_vaultsigningkeylocks", x => x.keyname);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "vaultsigningkeyoperations",
                columns: table => new
                {
                    operationid = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    keyname = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    keyversion = table.Column<int>(type: "int", nullable: false),
                    previouskeyversion = table.Column<int>(type: "int", nullable: true),
                    action = table.Column<string>(type: "varchar(24)", maxLength: 24, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    reason = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    occurredatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    retireafterutc = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_vaultsigningkeyoperations", x => x.operationid);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_vaultsigningkeyoperations_keyname_occurred",
                table: "vaultsigningkeyoperations",
                columns: new[] { "keyname", "occurredatutc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "vaultsigningkeylocks");

            migrationBuilder.DropTable(
                name: "vaultsigningkeyoperations");

            migrationBuilder.DropColumn(
                name: "lifecycleversion",
                table: "vaultkeys");

            migrationBuilder.DropColumn(
                name: "retireafterutc",
                table: "vaultkeys");

            migrationBuilder.DropColumn(
                name: "revokedatutc",
                table: "vaultkeys");

            migrationBuilder.DropColumn(
                name: "signingstate",
                table: "vaultkeys");
        }
    }
}
