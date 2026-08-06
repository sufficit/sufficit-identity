using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddOidcUserSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "oidcusersessions",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    sessionid = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    subject = table.Column<string>(type: "varchar(400)", maxLength: 400, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    remoteipaddress = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    useragent = table.Column<string>(type: "varchar(512)", maxLength: 512, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    createdatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    lastactivityutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    expiresutc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    protectedticket = table.Column<byte[]>(type: "longblob", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_oidcusersessions", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "AK_oidcusersessions_sessionid",
                table: "oidcusersessions",
                column: "sessionid",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_oidcusersessions_expiresutc",
                table: "oidcusersessions",
                column: "expiresutc");

            migrationBuilder.CreateIndex(
                name: "IX_oidcusersessions_subject",
                table: "oidcusersessions",
                column: "subject");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "oidcusersessions");
        }
    }
}
