using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddDcrInitialAccessTokenPolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "allowedgranttypesjson",
                table: "dcrinitialaccesstokens",
                type: "varchar(2048)",
                maxLength: 2048,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "allowedscopesjson",
                table: "dcrinitialaccesstokens",
                type: "varchar(2048)",
                maxLength: 2048,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "allowedgranttypesjson",
                table: "dcrinitialaccesstokens");

            migrationBuilder.DropColumn(
                name: "allowedscopesjson",
                table: "dcrinitialaccesstokens");
        }
    }
}
