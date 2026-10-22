using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddUserToUsageMetrics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_identityusagedaily_key",
                table: "identityapplicationusagedaily");

            migrationBuilder.AddColumn<string>(
                name: "userid",
                table: "identityapplicationusagedaily",
                type: "varchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_identityusagedaily_key",
                table: "identityapplicationusagedaily",
                columns: new[] { "day", "node", "clientid", "eventtype", "endpointtype", "granttype", "outcome", "userid" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_identityusagedaily_userid_day",
                table: "identityapplicationusagedaily",
                columns: new[] { "userid", "day" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_identityusagedaily_key",
                table: "identityapplicationusagedaily");

            migrationBuilder.DropIndex(
                name: "IX_identityusagedaily_userid_day",
                table: "identityapplicationusagedaily");

            migrationBuilder.DropColumn(
                name: "userid",
                table: "identityapplicationusagedaily");

            migrationBuilder.CreateIndex(
                name: "IX_identityusagedaily_key",
                table: "identityapplicationusagedaily",
                columns: new[] { "day", "node", "clientid", "eventtype", "endpointtype", "granttype", "outcome" },
                unique: true);
        }
    }
}
