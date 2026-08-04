using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddUserCreatedAtUtc : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "createdatutc",
                table: "users",
                type: "datetime(6)",
                nullable: true);

            // The legacy timestamp is the only historical signal available.
            // It may reflect a later profile update, but is a better backfill
            // than assigning every existing account the migration instant.
            // New accounts receive an immutable database-generated value.
            migrationBuilder.Sql(
                "UPDATE `users` SET `createdatutc` = `timestamp` " +
                "WHERE `createdatutc` IS NULL;");

            migrationBuilder.AlterColumn<DateTime>(
                name: "createdatutc",
                table: "users",
                type: "datetime(6)",
                nullable: false,
                defaultValueSql: "(UTC_TIMESTAMP(6))",
                oldClrType: typeof(DateTime),
                oldType: "datetime(6)",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_users_createdatutc",
                table: "users",
                column: "createdatutc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_users_createdatutc",
                table: "users");

            migrationBuilder.DropColumn(
                name: "createdatutc",
                table: "users");
        }
    }
}
