using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddTrustedProxyConfiguration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "afterjson",
                table: "managementauditevents",
                type: "longtext",
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "beforejson",
                table: "managementauditevents",
                type: "longtext",
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "trustedproxyconfiguration",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false),
                    networksjson = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    forwardlimit = table.Column<int>(type: "int", nullable: true),
                    revision = table.Column<string>(type: "varchar(36)", maxLength: 36, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    updatedatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_trustedproxyconfiguration", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.InsertData(
                table: "trustedproxyconfiguration",
                columns: new[] { "id", "forwardlimit", "networksjson", "revision", "updatedatutc" },
                values: new object[] { 1, null, "[]", "initial", new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "trustedproxyconfiguration");

            migrationBuilder.DropColumn(
                name: "afterjson",
                table: "managementauditevents");

            migrationBuilder.DropColumn(
                name: "beforejson",
                table: "managementauditevents");
        }
    }
}
