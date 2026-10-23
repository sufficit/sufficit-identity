-- Schema snapshot (plan F8): tables, columns (no ordinal), indexes, foreign keys
-- and the migration history, one comparable line each. Run it against any
-- deployment with `mysql -N -B --raw <db> < schema-snapshot.sql > live.txt`, then
-- `docs/migration/check-schema-parity.sh live.txt`.
SELECT 'T', table_name, engine, table_collation FROM information_schema.tables WHERE table_schema=DATABASE() ORDER BY 2;
SELECT 'C', table_name, column_name, column_type, is_nullable, IFNULL(column_default,'<null>'), extra, IFNULL(character_set_name,'-'), IFNULL(collation_name,'-') FROM information_schema.columns WHERE table_schema=DATABASE() ORDER BY 2,3;
SELECT 'I', table_name, index_name, non_unique, GROUP_CONCAT(CONCAT(column_name, IFNULL(CONCAT('(',sub_part,')'),'')) ORDER BY seq_in_index) FROM information_schema.statistics WHERE table_schema=DATABASE() GROUP BY table_name, index_name, non_unique ORDER BY 2,3;
SELECT 'F', k.table_name, k.constraint_name, GROUP_CONCAT(k.column_name ORDER BY k.ordinal_position), k.referenced_table_name, GROUP_CONCAT(k.referenced_column_name ORDER BY k.ordinal_position), r.delete_rule, r.update_rule FROM information_schema.key_column_usage k JOIN information_schema.referential_constraints r ON r.constraint_schema=k.table_schema AND r.constraint_name=k.constraint_name AND r.table_name=k.table_name WHERE k.table_schema=DATABASE() AND k.referenced_table_name IS NOT NULL GROUP BY k.table_name, k.constraint_name, k.referenced_table_name, r.delete_rule, r.update_rule ORDER BY 2,3;
SELECT 'M', MigrationId, ProductVersion FROM __sufficit_identity_migrations ORDER BY 2;
