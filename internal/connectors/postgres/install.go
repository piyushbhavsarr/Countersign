package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// InstallSQL sets up capture once per database (run as the table owner or a superuser):
// a trigger function that logs the full old/new image of every row change into a
// session-local temporary table - but only in a session that has set undolayer.tx, so
// every other session pays one cheap check per row and nothing else. Triggers are
// ENABLE ALWAYS so they still capture while undo runs with session_replication_role
// = replica (which keeps user triggers from re-firing). An event trigger attaches capture
// to tables created later.
const InstallSQL = `
CREATE SCHEMA IF NOT EXISTS undolayer;

CREATE OR REPLACE FUNCTION undolayer.capture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF coalesce(current_setting('undolayer.tx', true), '') = '' THEN
    RETURN NULL;
  END IF;
  INSERT INTO pg_temp.undolayer_log(tbl, op, old_row, new_row)
  VALUES (quote_ident(TG_TABLE_SCHEMA) || '.' || quote_ident(TG_TABLE_NAME), TG_OP,
          CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
          CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END);
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION undolayer.attach(rel regclass) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = rel AND tgname = 'undolayer_capture') THEN
    EXECUTE format('CREATE TRIGGER undolayer_capture AFTER INSERT OR UPDATE OR DELETE ON %s
                    FOR EACH ROW EXECUTE FUNCTION undolayer.capture()', rel);
    EXECUTE format('ALTER TABLE %s ENABLE ALWAYS TRIGGER undolayer_capture', rel);
  END IF;
END $$;

CREATE OR REPLACE FUNCTION undolayer.on_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$
DECLARE r record;
BEGIN
  FOR r IN SELECT objid FROM pg_event_trigger_ddl_commands()
           WHERE object_type = 'table' AND schema_name NOT IN ('pg_temp', 'undolayer') AND schema_name NOT LIKE 'pg_temp%'
  LOOP
    PERFORM undolayer.attach(r.objid::regclass);
  END LOOP;
END $$;

DROP EVENT TRIGGER IF EXISTS undolayer_attach;
CREATE EVENT TRIGGER undolayer_attach ON ddl_command_end
  WHEN TAG IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO') EXECUTE FUNCTION undolayer.on_ddl();

DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'undolayer')
             AND n.nspname NOT LIKE 'pg_temp%' AND n.nspname NOT LIKE 'pg_toast%'
  LOOP
    PERFORM undolayer.attach(r.oid::regclass);
  END LOOP;
END $$;
`

// Install runs InstallSQL against dsn.
func Install(dsn string) error {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, InstallSQL)
	return err
}
