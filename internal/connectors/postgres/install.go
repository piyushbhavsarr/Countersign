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

-- outbox: what gateway sessions change, written by the capture trigger inside the same
-- transaction as the change, so it is exactly as durable as the change and commits or
-- rolls back with it. The gateway moves it to the vault in the background. Nobody but
-- its owner can read it.
CREATE TABLE IF NOT EXISTS undolayer.outbox(seq bigserial PRIMARY KEY, xid bigint NOT NULL, usr text,
  tbl text NOT NULL, op text NOT NULL, old_row jsonb, new_row jsonb);
CREATE INDEX IF NOT EXISTS outbox_xid ON undolayer.outbox(xid);
REVOKE ALL ON undolayer.outbox FROM PUBLIC;

-- outbox_guard: the commit-time budget, held by the database itself, so a transaction
-- whose before state goes to the vault after it commits still cannot change too much.
-- It runs once per transaction at commit (once per statement under SET CONSTRAINTS
-- IMMEDIATE: it recounts whenever rows came after its last count).
CREATE OR REPLACE FUNCTION undolayer.outbox_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  done text := current_setting('undolayer.checked', true);
  me text := txid_current()::text;
  n bigint; top bigint; lim bigint; frac float8; t record; total float8;
BEGIN
  IF current_setting('undolayer.guard', true) = 'watch' THEN
    RETURN NULL; -- the gateway is in watch mode: it audits, the database refuses nothing
  END IF;
  IF done IS NOT NULL AND split_part(done, ':', 1) = me AND NEW.seq <= split_part(done, ':', 2)::bigint THEN
    RETURN NULL;
  END IF;
  SELECT count(*), coalesce(max(seq), 0) INTO n, top FROM undolayer.outbox WHERE xid = me::bigint;
  PERFORM set_config('undolayer.checked', me || ':' || top, true);
  IF n = 0 THEN
    RETURN NULL;
  END IF;
  lim := coalesce(nullif(current_setting('undolayer.max_rows', true), ''), '100000')::bigint;
  IF n > lim THEN
    RAISE EXCEPTION USING ERRCODE = '42501',
      MESSAGE = format('refused by Countersign: the transaction changes %s rows, more than %s; it was rolled back', n, lim);
  END IF;
  frac := coalesce(nullif(current_setting('undolayer.max_fraction', true), ''), '0.5')::float8;
  FOR t IN SELECT o.tbl, count(*) AS c FROM undolayer.outbox o WHERE o.xid = me::bigint GROUP BY o.tbl LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_index WHERE indrelid = t.tbl::regclass AND indisprimary) THEN
      RAISE EXCEPTION USING ERRCODE = '42501',
        MESSAGE = format('refused by Countersign: %s has no primary key, so its rows could not be put back; the transaction was rolled back', t.tbl);
    END IF;
    IF t.c <= 1000 THEN
      CONTINUE;
    END IF;
    SELECT reltuples INTO total FROM pg_class WHERE oid = t.tbl::regclass;
    IF total IS NULL OR total <= 0 THEN -- never analyzed: count it (its size before this transaction)
      EXECUTE format('SELECT count(*) FROM %s', t.tbl) INTO total;
      total := total + (SELECT count(*) FILTER (WHERE op = 'DELETE') - count(*) FILTER (WHERE op = 'INSERT')
                        FROM undolayer.outbox WHERE xid = me::bigint AND tbl = t.tbl);
    END IF;
    IF t.c > frac * greatest(total, t.c) THEN
      RAISE EXCEPTION USING ERRCODE = '42501',
        MESSAGE = format('refused by Countersign: the transaction changes %s of the %s rows of %s, over half of a table; it was rolled back', t.c, total::bigint, t.tbl);
    END IF;
  END LOOP;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS outbox_guard ON undolayer.outbox;
CREATE CONSTRAINT TRIGGER outbox_guard AFTER INSERT ON undolayer.outbox
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION undolayer.outbox_guard();

CREATE OR REPLACE FUNCTION undolayer.capture() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tx text := coalesce(current_setting('undolayer.tx', true), '');
BEGIN
  IF tx = '' THEN
    RETURN NULL;
  END IF;
  IF tx = 'gateway' THEN
    INSERT INTO undolayer.outbox(xid, usr, tbl, op, old_row, new_row)
    VALUES (txid_current(), current_setting('undolayer.user', true),
            quote_ident(TG_TABLE_SCHEMA) || '.' || quote_ident(TG_TABLE_NAME), TG_OP,
            CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
            CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END);
    RETURN NULL;
  END IF;
  INSERT INTO pg_temp.undolayer_log(tbl, op, old_row, new_row)
  VALUES (quote_ident(TG_TABLE_SCHEMA) || '.' || quote_ident(TG_TABLE_NAME), TG_OP,
          CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
          CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END);
  RETURN NULL;
END $$;

-- refuse: how the gateway refuses a statement. The server itself raises the error, so the
-- transaction it is in fails exactly as it would for any other error.
CREATE OR REPLACE FUNCTION undolayer.refuse(msg text, code text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION USING MESSAGE = msg, ERRCODE = code;
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
