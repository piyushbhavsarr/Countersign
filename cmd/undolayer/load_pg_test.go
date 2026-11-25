package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// pgOrders makes a fresh database with an orders table of n rows and returns its DSN.
func pgOrders(t *testing.T, base string, n int) string {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("ul_load_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	admin.Close(ctx)
	dsn := base[:strings.LastIndex(base, "/")+1] + name
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, "CREATE TABLE orders(id int PRIMARY KEY, note text)"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, "INSERT INTO orders SELECT g, 'x' FROM generate_series(1, $1) g", n); err != nil {
		t.Fatal(err)
	}
	return dsn
}

func pgCount(t *testing.T, dsn string, k int) int {
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var n int
	_ = c.QueryRow(ctx, "SELECT COUNT(*) FROM orders WHERE id = $1", k).Scan(&n)
	return n
}

// pgConfig points the fixture's config at the PostgreSQL database instead of SQLite.
func pgConfig(t *testing.T, f *fixture, dsn string) string {
	b, err := os.ReadFile(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(b), `dsn = "app.db"`, fmt.Sprintf("dsn = %q", dsn), 1)
	if err := os.WriteFile(f.cfg, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(f.cfg)
}
