using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sufficit.Identity.Core.Migrations
{
    /// <summary>
    /// Consolidates the vaultsecrets row key into (type, contextid, name):
    /// adds the owner-kind discriminator ("user" | "tenant" | "client" |
    /// "global"), converts contextid to binary(16) and ownersubject to
    /// binary(16), both in Guid.ToByteArray byte order.
    ///
    /// Historical classification (must mirror VaultSecretContext.Parse):
    /// - "global", empty or unrecognized values -> type "global", zero guid;
    /// - "user-&lt;guid&gt;", "tenant-&lt;guid&gt;", "client-&lt;guid&gt;" -> matching type;
    /// - a bare "&lt;guid&gt;" -> type "client" (system credentials were the only
    ///   pre-discriminator writers of bare guids).
    /// Unparsable guid portions collapse to the zero guid. <see cref="Down"/> is
    /// best-effort: zero guids render back as "global" / empty and the type
    /// discriminator itself is lost, exactly like the contextid cutover.
    /// </summary>
    public partial class AddVaultSecretTypes : Migration
    {
        private const string GuidPattern =
            "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$";

        private const string ZeroGuidHex = "00000000000000000000000000000000";

        /// <summary>UNHEX expression producing Guid.ToByteArray byte order:
        /// the first three dash groups are little-endian, so their byte pairs
        /// are reversed; the last two groups stay big-endian.</summary>
        private static string GuidBytesFromText(string textExpression) =>
            "UNHEX(CONCAT(" +
            $"SUBSTRING({textExpression},7,2),SUBSTRING({textExpression},5,2)," +
            $"SUBSTRING({textExpression},3,2),SUBSTRING({textExpression},1,2)," +
            $"SUBSTRING({textExpression},12,2),SUBSTRING({textExpression},10,2)," +
            $"SUBSTRING({textExpression},17,2),SUBSTRING({textExpression},15,2)," +
            $"SUBSTRING({textExpression},20,4)," +
            $"SUBSTRING({textExpression},25,12)))";

        /// <summary>Inverse of <see cref="GuidBytesFromText"/>: canonical
        /// lowercase guid text from the stored 32-char hex string.</summary>
        private static string GuidTextFromHex(string hexExpression) =>
            "LOWER(CONCAT(" +
            $"SUBSTRING({hexExpression},7,2),SUBSTRING({hexExpression},5,2)," +
            $"SUBSTRING({hexExpression},3,2),SUBSTRING({hexExpression},1,2),'-'," +
            $"SUBSTRING({hexExpression},11,2),SUBSTRING({hexExpression},9,2),'-'," +
            $"SUBSTRING({hexExpression},15,2),SUBSTRING({hexExpression},13,2),'-'," +
            $"SUBSTRING({hexExpression},17,8),'-'," +
            $"SUBSTRING({hexExpression},25,8)))";

        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "AK_vaultsecrets_context_name",
                table: "vaultsecrets");

            migrationBuilder.DropIndex(
                name: "IX_vaultsecrets_context_namespace",
                table: "vaultsecrets");

            migrationBuilder.AddColumn<string>(
                name: "type",
                table: "vaultsecrets",
                type: "varchar(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            // Nullable shadow columns first: MariaDB fills them with NULL for
            // existing rows without touching the still-authoritative text
            // columns. They become NOT NULL only after every row is converted.
            migrationBuilder.Sql(
                "ALTER TABLE `vaultsecrets` " +
                "ADD COLUMN `contextid_bin` binary(16) NULL, " +
                "ADD COLUMN `ownersubject_bin` binary(16) NULL;");

            // Type classification + contextid conversion in one pass. The
            // derived table normalizes each row to its bare guid text so the
            // byte-swap expression always sees fixed offsets.
            migrationBuilder.Sql(
                "UPDATE `vaultsecrets` `v` " +
                "JOIN (" +
                "  SELECT `id`, " +
                "    CASE " +
                "      WHEN LOWER(TRIM(`contextid`)) LIKE 'user-%' THEN 'user' " +
                "      WHEN LOWER(TRIM(`contextid`)) LIKE 'tenant-%' THEN 'tenant' " +
                "      WHEN LOWER(TRIM(`contextid`)) LIKE 'client-%' THEN 'client' " +
                $"      WHEN TRIM(`contextid`) REGEXP '{GuidPattern}' THEN 'client' " +
                "      ELSE 'global' " +
                "    END AS `derived_type`, " +
                "    CASE " +
                "      WHEN LOWER(TRIM(`contextid`)) LIKE 'user-%' THEN SUBSTRING(TRIM(`contextid`), 6) " +
                "      WHEN LOWER(TRIM(`contextid`)) LIKE 'tenant-%' THEN SUBSTRING(TRIM(`contextid`), 8) " +
                "      WHEN LOWER(TRIM(`contextid`)) LIKE 'client-%' THEN SUBSTRING(TRIM(`contextid`), 8) " +
                "      ELSE TRIM(`contextid`) " +
                "    END AS `bare` " +
                "  FROM `vaultsecrets` " +
                ") `n` ON `n`.`id` = `v`.`id` " +
                "SET `v`.`type` = `n`.`derived_type`, " +
                "  `v`.`contextid_bin` = CASE " +
                $"    WHEN `n`.`derived_type` = 'global' THEN UNHEX('{ZeroGuidHex}') " +
                $"    WHEN `n`.`bare` REGEXP '{GuidPattern}' THEN {GuidBytesFromText("`n`.`bare`")} " +
                $"    ELSE UNHEX('{ZeroGuidHex}') " +
                "  END;");

            // A user context IS its owner: the row key already carries the
            // user guid the secrets are private to.
            migrationBuilder.Sql(
                "UPDATE `vaultsecrets` SET `ownersubject_bin` = `contextid_bin` " +
                "WHERE `type` = 'user';");

            // Remaining rows keep the legacy subject rules: a textual guid
            // survives, a legacy "user-" prefix is stripped, anything else
            // collapses to the zero guid.
            migrationBuilder.Sql(
                "UPDATE `vaultsecrets` `v` " +
                "JOIN (" +
                "  SELECT `id`, " +
                "    CASE " +
                "      WHEN LOWER(TRIM(`ownersubject`)) LIKE 'user-%' THEN SUBSTRING(TRIM(`ownersubject`), 6) " +
                "      ELSE TRIM(`ownersubject`) " +
                "    END AS `bare` " +
                "  FROM `vaultsecrets` " +
                "  WHERE `type` IS NULL OR `type` <> 'user' " +
                ") `n` ON `n`.`id` = `v`.`id` " +
                "SET `v`.`ownersubject_bin` = CASE " +
                $"    WHEN `n`.`bare` REGEXP '{GuidPattern}' THEN {GuidBytesFromText("`n`.`bare`")} " +
                $"    ELSE UNHEX('{ZeroGuidHex}') " +
                "  END;");

            // Swap the converted shadows in place of the text columns. CHANGE
            // COLUMN instead of RenameColumn keeps MariaDB 10.4 happy.
            migrationBuilder.Sql(
                "ALTER TABLE `vaultsecrets` " +
                "DROP COLUMN `contextid`, DROP COLUMN `ownersubject`;");
            migrationBuilder.Sql(
                "ALTER TABLE `vaultsecrets` " +
                "CHANGE COLUMN `contextid_bin` `contextid` binary(16) NOT NULL;");
            migrationBuilder.Sql(
                "ALTER TABLE `vaultsecrets` " +
                "CHANGE COLUMN `ownersubject_bin` `ownersubject` binary(16) NOT NULL;");

            migrationBuilder.CreateIndex(
                name: "AK_vaultsecrets_context_name",
                table: "vaultsecrets",
                columns: new[] { "type", "contextid", "name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_vaultsecrets_context_namespace",
                table: "vaultsecrets",
                columns: new[] { "type", "contextid", "namespace" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "AK_vaultsecrets_context_name",
                table: "vaultsecrets");

            migrationBuilder.DropIndex(
                name: "IX_vaultsecrets_context_namespace",
                table: "vaultsecrets");

            migrationBuilder.Sql(
                "ALTER TABLE `vaultsecrets` " +
                "ADD COLUMN `contextid_text` varchar(64) NULL, " +
                "ADD COLUMN `ownersubject_text` varchar(128) NULL;");

            migrationBuilder.Sql(
                "UPDATE `vaultsecrets` `v` " +
                "JOIN (SELECT `id`, `type`, LOWER(HEX(`contextid`)) AS `h`, LOWER(HEX(`ownersubject`)) AS `oh` " +
                "  FROM `vaultsecrets`) `n` ON `n`.`id` = `v`.`id` " +
                "SET `v`.`contextid_text` = CASE " +
                $"    WHEN `n`.`type` = 'global' OR `n`.`h` = '{ZeroGuidHex}' THEN 'global' " +
                "    WHEN `n`.`type` = 'user' THEN CONCAT('user-', " + GuidTextFromHex("`n`.`h`") + ") " +
                "    WHEN `n`.`type` = 'tenant' THEN CONCAT('tenant-', " + GuidTextFromHex("`n`.`h`") + ") " +
                "    ELSE " + GuidTextFromHex("`n`.`h`") + " " +
                "  END, " +
                "  `v`.`ownersubject_text` = CASE " +
                $"    WHEN `n`.`oh` = '{ZeroGuidHex}' THEN '' " +
                "    ELSE " + GuidTextFromHex("`n`.`oh`") + " " +
                "  END;");

            migrationBuilder.Sql(
                "ALTER TABLE `vaultsecrets` " +
                "DROP COLUMN `contextid`, DROP COLUMN `ownersubject`;");
            migrationBuilder.Sql(
                "ALTER TABLE `vaultsecrets` " +
                "CHANGE COLUMN `contextid_text` `contextid` varchar(64) NOT NULL;");
            migrationBuilder.Sql(
                "ALTER TABLE `vaultsecrets` " +
                "CHANGE COLUMN `ownersubject_text` `ownersubject` varchar(128) NOT NULL;");

            migrationBuilder.DropColumn(
                name: "type",
                table: "vaultsecrets");

            migrationBuilder.CreateIndex(
                name: "AK_vaultsecrets_context_name",
                table: "vaultsecrets",
                columns: new[] { "contextid", "name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_vaultsecrets_context_namespace",
                table: "vaultsecrets",
                columns: new[] { "contextid", "namespace" });
        }
    }
}
