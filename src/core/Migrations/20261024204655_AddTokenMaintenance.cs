using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddTokenMaintenance : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "tokenmaintenance",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false),
                    enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    retentiondays = table.Column<int>(type: "int", nullable: false),
                    intervalminutes = table.Column<int>(type: "int", nullable: false),
                    nextrunatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    runrequested = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    revision = table.Column<string>(type: "varchar(36)", maxLength: 36, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    owner = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    leaseuntilutc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    currentrunid = table.Column<string>(type: "varchar(36)", maxLength: 36, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tokenmaintenance", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "tokenmaintenanceruns",
                columns: table => new
                {
                    id = table.Column<string>(type: "varchar(36)", maxLength: 36, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    startedatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    finishedatutc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    status = table.Column<string>(type: "varchar(24)", maxLength: 24, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    tokens = table.Column<long>(type: "bigint", nullable: false),
                    authorizations = table.Column<long>(type: "bigint", nullable: false),
                    owner = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tokenmaintenanceruns", x => x.id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.InsertData(
                table: "tokenmaintenance",
                columns: new[] { "id", "currentrunid", "enabled", "intervalminutes", "leaseuntilutc", "nextrunatutc", "owner", "retentiondays", "revision", "runrequested" },
                values: new object[] { 1, null, false, 360, null, new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, 30, "initial", false });

            migrationBuilder.CreateIndex(
                name: "IX_tokenmaintenanceruns_startedatutc",
                table: "tokenmaintenanceruns",
                column: "startedatutc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "tokenmaintenance");

            migrationBuilder.DropTable(
                name: "tokenmaintenanceruns");
        }
    }
}
