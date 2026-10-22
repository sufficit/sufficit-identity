using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class SystemUsersAsOrdinaryUsers : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Audit events may carry their own expiry; null keeps the default retention.
            migrationBuilder.AddColumn<DateTime>(
                name: "expiresatutc",
                table: "managementauditevents",
                type: "datetime(6)",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_managementauditevents_expiresatutc",
                table: "managementauditevents",
                column: "expiresatutc");

            // A system user becomes an ordinary user without e-mail or password.
            // Its origin moves to a permanent audit event, its disabled state to
            // the ordinary lockout; only then the marker table goes.
            migrationBuilder.Sql(
                "UPDATE `managementauditevents` SET `expiresatutc` = '9999-12-31 00:00:00' " +
                "WHERE `reasoncode` = 'system_user_created';");
            migrationBuilder.Sql(
                "INSERT INTO `managementauditevents` (`occurredatutc`, `operatorsubject`, `capability`, `resourcetype`, " +
                "`resourceid`, `authorizationoutcome`, `operationoutcome`, `reasoncode`, `correlationid`, `expiresatutc`) " +
                "SELECT s.`createdatutc`, s.`createdby`, 'identity.users.create', 'user', s.`userid`, 'allowed', 'succeeded', " +
                "'system_user_created', COALESCE(s.`correlationid`, 'migration-system-users'), '9999-12-31 00:00:00' " +
                "FROM `systemusers` s WHERE NOT EXISTS (SELECT 1 FROM `managementauditevents` e " +
                "WHERE e.`resourceid` = s.`userid` AND e.`reasoncode` = 'system_user_created');");
            migrationBuilder.Sql(
                "UPDATE `users` u JOIN `systemusers` s ON s.`userid` = u.`id` " +
                "SET u.`lockoutenabled` = 1, u.`lockoutend` = '9999-12-31 00:00:00' " +
                "WHERE s.`disabledatutc` IS NOT NULL;");

            migrationBuilder.DropForeignKey(
                name: "FK_systemuserenrollments_systemusers_userid",
                table: "systemuserenrollments");

            migrationBuilder.DropTable(
                name: "systemusers");

            migrationBuilder.AddForeignKey(
                name: "FK_systemuserenrollments_users_userid",
                table: "systemuserenrollments",
                column: "userid",
                principalTable: "users",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_systemuserenrollments_users_userid",
                table: "systemuserenrollments");

            migrationBuilder.DropIndex(
                name: "IX_managementauditevents_expiresatutc",
                table: "managementauditevents");

            migrationBuilder.DropColumn(
                name: "expiresatutc",
                table: "managementauditevents");

            migrationBuilder.CreateTable(
                name: "systemusers",
                columns: table => new
                {
                    userid = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    correlationid = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    createdatutc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    createdby = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    disabledatutc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    disabledby = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_systemusers", x => x.userid);
                    table.ForeignKey(
                        name: "FK_systemusers_users_userid",
                        column: x => x.userid,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddForeignKey(
                name: "FK_systemuserenrollments_systemusers_userid",
                table: "systemuserenrollments",
                column: "userid",
                principalTable: "systemusers",
                principalColumn: "userid",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
