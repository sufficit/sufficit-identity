using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class HardenSsfStreams : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ownerclientid",
                table: "ssfstreams",
                type: "varchar(100)",
                maxLength: 100,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "verificationchallengehash",
                table: "ssfstreams",
                type: "varchar(43)",
                maxLength: 43,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<DateTime>(
                name: "verificationexpiresatutc",
                table: "ssfstreams",
                type: "datetime(6)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "deliverykey",
                table: "ssfsetdeliveries",
                type: "varchar(64)",
                maxLength: 64,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            // The historical schema did not retain the creating OAuth client.
            // Existing SSF audiences are the only durable client binding, so
            // preserve those streams by adopting that value as their owner.
            migrationBuilder.Sql("""
                UPDATE `ssfstreams`
                SET `ownerclientid` = `audience`
                WHERE `ownerclientid` IS NULL;
                """);

            migrationBuilder.CreateIndex(
                name: "IX_ssfstreams_ownerclientid_status",
                table: "ssfstreams",
                columns: new[] { "ownerclientid", "status" });

            migrationBuilder.CreateIndex(
                name: "AK_ssfsetdeliveries_deliverykey",
                table: "ssfsetdeliveries",
                column: "deliverykey",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ssfstreams_ownerclientid_status",
                table: "ssfstreams");

            migrationBuilder.DropIndex(
                name: "AK_ssfsetdeliveries_deliverykey",
                table: "ssfsetdeliveries");

            migrationBuilder.DropColumn(
                name: "ownerclientid",
                table: "ssfstreams");

            migrationBuilder.DropColumn(
                name: "verificationchallengehash",
                table: "ssfstreams");

            migrationBuilder.DropColumn(
                name: "verificationexpiresatutc",
                table: "ssfstreams");

            migrationBuilder.DropColumn(
                name: "deliverykey",
                table: "ssfsetdeliveries");
        }
    }
}
