using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddVaultSecretNamespaces : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "AK_vaultsecrets_name",
                table: "vaultsecrets");

            migrationBuilder.AddColumn<string>(
                name: "contextid",
                table: "vaultsecrets",
                type: "varchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "namespace",
                table: "vaultsecrets",
                type: "varchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "ownersubject",
                table: "vaultsecrets",
                type: "varchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.Sql(
                "UPDATE vaultsecrets SET " +
                "contextid = 'global', " +
                "namespace = LOWER(SUBSTRING_INDEX(TRIM(name), '/', 1)), " +
                "ownersubject = CASE WHEN TRIM(updatedby) = '' " +
                "THEN 'legacy-migration' ELSE LEFT(TRIM(updatedby), 128) END;");

            migrationBuilder.CreateIndex(
                name: "AK_vaultsecrets_context_name",
                table: "vaultsecrets",
                columns: new[] { "contextid", "name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_vaultsecrets_context_namespace",
                table: "vaultsecrets",
                columns: new[] { "contextid", "namespace" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "AK_vaultsecrets_context_name",
                table: "vaultsecrets");

            migrationBuilder.DropIndex(
                name: "IX_vaultsecrets_context_namespace",
                table: "vaultsecrets");

            migrationBuilder.DropColumn(
                name: "contextid",
                table: "vaultsecrets");

            migrationBuilder.DropColumn(
                name: "namespace",
                table: "vaultsecrets");

            migrationBuilder.DropColumn(
                name: "ownersubject",
                table: "vaultsecrets");

            migrationBuilder.CreateIndex(
                name: "AK_vaultsecrets_name",
                table: "vaultsecrets",
                column: "name",
                unique: true);
        }
    }
}
