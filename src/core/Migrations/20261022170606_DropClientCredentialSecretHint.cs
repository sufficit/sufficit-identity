using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class DropClientCredentialSecretHint : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "secrethint",
                table: "oauthclientcredentials");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "secrethint",
                table: "oauthclientcredentials",
                type: "varchar(12)",
                maxLength: 12,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");
        }
    }
}
