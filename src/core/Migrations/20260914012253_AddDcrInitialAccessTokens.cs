using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddDcrInitialAccessTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "dcrinitialaccesstokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    label = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    tokenhash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    tokenhint = table.Column<string>(type: "varchar(12)", maxLength: 12, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    issuedby = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    createdatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    expiresatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    singleuse = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    registrationcount = table.Column<int>(type: "int", nullable: false),
                    lastusedatutc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    revokedatutc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    revokedby = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_dcrinitialaccesstokens", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_dcrinitialaccesstokens_expiresatutc",
                table: "dcrinitialaccesstokens",
                column: "expiresatutc");

            migrationBuilder.CreateIndex(
                name: "IX_dcrinitialaccesstokens_tokenhash",
                table: "dcrinitialaccesstokens",
                column: "tokenhash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "dcrinitialaccesstokens");
        }
    }
}
