using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <summary>
    /// Retires <c>vaultpersonalsecrets</c>, a second design for user-owned
    /// secrets that only the Vault UI ever reached. User-typed secrets now live
    /// in <c>vaultsecrets</c> under the caller's own <c>user-&lt;sub&gt;</c>
    /// context and the reserved <c>personal</c> namespace, alongside the
    /// credentials written by connected applications.
    ///
    /// No data migration accompanies this drop: the table held zero rows in
    /// production, so nothing was copied and nothing was lost. Down() recreates
    /// the empty table so the migration is still reversible.
    /// </summary>
    public partial class DropVaultPersonalSecrets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "vaultpersonalsecrets");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "vaultpersonalsecrets",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    aadjson = table.Column<string>(type: "longtext", nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    ciphertext = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    name = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    @namespace = table.Column<string>(name: "namespace", type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    ownersubject = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    updatedatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    updatedby = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_vaultpersonalsecrets", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "AK_vaultpersonalsecrets_owner_namespace_name",
                table: "vaultpersonalsecrets",
                columns: new[] { "ownersubject", "namespace", "name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_vaultpersonalsecrets_owner_namespace",
                table: "vaultpersonalsecrets",
                columns: new[] { "ownersubject", "namespace" });
        }
    }
}
