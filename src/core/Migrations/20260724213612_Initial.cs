using System;
using Microsoft.EntityFrameworkCore.Migrations;
using MySql.EntityFrameworkCore.Metadata;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterDatabase()
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "applications",
                columns: table => new
                {
                    id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false),
                    application_type = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true),
                    client_id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true),
                    client_secret = table.Column<string>(type: "longtext", nullable: true),
                    client_type = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true),
                    concurrency_token = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true),
                    consent_type = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true),
                    display_name = table.Column<string>(type: "longtext", nullable: true),
                    display_names = table.Column<string>(type: "longtext", nullable: true),
                    json_web_key_set = table.Column<string>(type: "longtext", nullable: true),
                    permissions = table.Column<string>(type: "longtext", nullable: true),
                    post_logout_redirect_uris = table.Column<string>(type: "longtext", nullable: true),
                    properties = table.Column<string>(type: "longtext", nullable: true),
                    redirect_uris = table.Column<string>(type: "longtext", nullable: true),
                    requirements = table.Column<string>(type: "longtext", nullable: true),
                    settings = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_applications", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "dataprotectionkeys",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    friendlyname = table.Column<string>(type: "longtext", nullable: true),
                    xml = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_dataprotectionkeys", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "roles",
                columns: table => new
                {
                    id = table.Column<string>(type: "varchar(255)", nullable: false),
                    name = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true),
                    normalizedname = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true),
                    concurrencystamp = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_roles", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "scopes",
                columns: table => new
                {
                    id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false),
                    concurrency_token = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true),
                    description = table.Column<string>(type: "longtext", nullable: true),
                    descriptions = table.Column<string>(type: "longtext", nullable: true),
                    display_name = table.Column<string>(type: "longtext", nullable: true),
                    display_names = table.Column<string>(type: "longtext", nullable: true),
                    name = table.Column<string>(type: "varchar(200)", maxLength: 200, nullable: true),
                    properties = table.Column<string>(type: "longtext", nullable: true),
                    resources = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scopes", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "userpasskeys",
                columns: table => new
                {
                    credentialid = table.Column<byte[]>(type: "varbinary(1024)", maxLength: 1024, nullable: false),
                    userid = table.Column<string>(type: "varchar(255)", nullable: false),
                    publickey = table.Column<byte[]>(type: "longblob", nullable: false),
                    name = table.Column<string>(type: "longtext", nullable: true),
                    createdat = table.Column<DateTimeOffset>(type: "datetime(6)", nullable: false),
                    signcount = table.Column<uint>(type: "int unsigned", nullable: false),
                    transports = table.Column<string>(type: "longtext", nullable: false),
                    isuserverified = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    isbackupeligible = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    isbackedup = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    attestationobject = table.Column<byte[]>(type: "longblob", nullable: false),
                    clientdatajson = table.Column<byte[]>(type: "longblob", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_userpasskeys", x => x.credentialid);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    id = table.Column<string>(type: "varchar(255)", nullable: false),
                    timestamp = table.Column<DateTime>(type: "timestamp", nullable: false, defaultValueSql: "(UTC_TIMESTAMP())"),
                    username = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true),
                    normalizedusername = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true),
                    email = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true),
                    normalizedemail = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true),
                    emailconfirmed = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    passwordhash = table.Column<string>(type: "longtext", nullable: true),
                    securitystamp = table.Column<string>(type: "longtext", nullable: true),
                    concurrencystamp = table.Column<string>(type: "longtext", nullable: true),
                    phonenumber = table.Column<string>(type: "longtext", nullable: true),
                    phonenumberconfirmed = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    twofactorenabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    lockoutend = table.Column<DateTimeOffset>(type: "datetime(6)", nullable: true),
                    lockoutenabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    accessfailedcount = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "authorizations",
                columns: table => new
                {
                    id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false),
                    application_id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true),
                    concurrency_token = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true),
                    creation_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    properties = table.Column<string>(type: "longtext", nullable: true),
                    scopes = table.Column<string>(type: "longtext", nullable: true),
                    status = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true),
                    subject = table.Column<string>(type: "varchar(400)", maxLength: 400, nullable: true),
                    type = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_authorizations", x => x.id);
                    table.ForeignKey(
                        name: "FK_authorizations_applications_application_id",
                        column: x => x.application_id,
                        principalTable: "applications",
                        principalColumn: "id");
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "roleclaims",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    roleid = table.Column<string>(type: "varchar(255)", nullable: false),
                    claimtype = table.Column<string>(type: "longtext", nullable: true),
                    claimvalue = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_roleclaims", x => x.id);
                    table.ForeignKey(
                        name: "FK_roleclaims_roles_roleid",
                        column: x => x.roleid,
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "userclaims",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    userid = table.Column<string>(type: "varchar(255)", nullable: false),
                    claimtype = table.Column<string>(type: "longtext", nullable: true),
                    claimvalue = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_userclaims", x => x.id);
                    table.ForeignKey(
                        name: "FK_userclaims_users_userid",
                        column: x => x.userid,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "userlogins",
                columns: table => new
                {
                    loginprovider = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    providerkey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    providerdisplayname = table.Column<string>(type: "longtext", nullable: true),
                    userid = table.Column<string>(type: "varchar(255)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_userlogins", x => new { x.loginprovider, x.providerkey });
                    table.ForeignKey(
                        name: "FK_userlogins_users_userid",
                        column: x => x.userid,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "userroles",
                columns: table => new
                {
                    userid = table.Column<string>(type: "varchar(255)", nullable: false),
                    roleid = table.Column<string>(type: "varchar(255)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_userroles", x => new { x.userid, x.roleid });
                    table.ForeignKey(
                        name: "FK_userroles_roles_roleid",
                        column: x => x.roleid,
                        principalTable: "roles",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_userroles_users_userid",
                        column: x => x.userid,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "usertokens",
                columns: table => new
                {
                    userid = table.Column<string>(type: "varchar(255)", nullable: false),
                    loginprovider = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    name = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    value = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_usertokens", x => new { x.userid, x.loginprovider, x.name });
                    table.ForeignKey(
                        name: "FK_usertokens_users_userid",
                        column: x => x.userid,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "tokens",
                columns: table => new
                {
                    id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false),
                    application_id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true),
                    authorization_id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true),
                    concurrency_token = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true),
                    creation_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    expiration_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    payload = table.Column<string>(type: "longtext", nullable: true),
                    properties = table.Column<string>(type: "longtext", nullable: true),
                    redemption_date = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    reference_id = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: true),
                    status = table.Column<string>(type: "varchar(50)", maxLength: 50, nullable: true),
                    subject = table.Column<string>(type: "varchar(400)", maxLength: 400, nullable: true),
                    type = table.Column<string>(type: "varchar(150)", maxLength: 150, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tokens", x => x.id);
                    table.ForeignKey(
                        name: "FK_tokens_applications_application_id",
                        column: x => x.application_id,
                        principalTable: "applications",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "FK_tokens_authorizations_authorization_id",
                        column: x => x.authorization_id,
                        principalTable: "authorizations",
                        principalColumn: "id");
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "AK_OpenIddictApplications_ClientId",
                table: "applications",
                column: "client_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictAuthorizations_ApplicationId_Status_Subject_Type",
                table: "authorizations",
                columns: new[] { "application_id", "status", "subject", "type" });

            migrationBuilder.CreateIndex(
                name: "IX_roleclaims_roleid",
                table: "roleclaims",
                column: "roleid");

            migrationBuilder.CreateIndex(
                name: "RoleNameIndex",
                table: "roles",
                column: "normalizedname",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "AK_OpenIddictScopes_Name",
                table: "scopes",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "AK_OpenIddictTokens_ReferenceId",
                table: "tokens",
                column: "reference_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictTokens_ApplicationId_Status_Subject_Type",
                table: "tokens",
                columns: new[] { "application_id", "status", "subject", "type" });

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictTokens_AuthorizationId",
                table: "tokens",
                column: "authorization_id");

            migrationBuilder.CreateIndex(
                name: "IX_userclaims_userid",
                table: "userclaims",
                column: "userid");

            migrationBuilder.CreateIndex(
                name: "IX_userlogins_userid",
                table: "userlogins",
                column: "userid");

            migrationBuilder.CreateIndex(
                name: "IX_userpasskeys_userid",
                table: "userpasskeys",
                column: "userid");

            migrationBuilder.CreateIndex(
                name: "IX_userroles_roleid",
                table: "userroles",
                column: "roleid");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "users",
                column: "normalizedemail");

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "users",
                column: "normalizedusername",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "dataprotectionkeys");

            migrationBuilder.DropTable(
                name: "roleclaims");

            migrationBuilder.DropTable(
                name: "scopes");

            migrationBuilder.DropTable(
                name: "tokens");

            migrationBuilder.DropTable(
                name: "userclaims");

            migrationBuilder.DropTable(
                name: "userlogins");

            migrationBuilder.DropTable(
                name: "userpasskeys");

            migrationBuilder.DropTable(
                name: "userroles");

            migrationBuilder.DropTable(
                name: "usertokens");

            migrationBuilder.DropTable(
                name: "authorizations");

            migrationBuilder.DropTable(
                name: "roles");

            migrationBuilder.DropTable(
                name: "users");

            migrationBuilder.DropTable(
                name: "applications");
        }
    }
}
