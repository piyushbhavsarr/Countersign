package pggw

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestThroughput measures what the gateway adds, against the same database directly.
func TestThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	e := setup(t, nil)
	ctx := context.Background()
	run := func(url, what string, workers int, d time.Duration, fn func(*pgxpool.Pool, int64) error) {
		cfg, _ := pgxpool.ParseConfig(url)
		cfg.MaxConns = int32(workers)
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		var n, i atomic.Int64
		deadline := time.Now().Add(d)
		done := make(chan error, workers)
		for w := 0; w < workers; w++ {
			go func() {
				for time.Now().Before(deadline) {
					if err := fn(p, i.Add(1)); err != nil {
						done <- err
						return
					}
					n.Add(1)
				}
				done <- nil
			}()
		}
		for w := 0; w < workers; w++ {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%-34s %3d conns: %8.0f /s  (%.3f ms each)", what, workers, float64(n.Load())/d.Seconds(),
			d.Seconds()*1000*float64(workers)/float64(n.Load()))
	}
	read := func(p *pgxpool.Pool, i int64) error {
		var o string
		return p.QueryRow(ctx, "SELECT owner FROM accounts WHERE id = $1", i%3000+1).Scan(&o)
	}
	write := func(p *pgxpool.Pool, i int64) error {
		_, err := p.Exec(ctx, "UPDATE accounts SET balance = balance + 1 WHERE id = $1", i%3000+1)
		return err
	}
	d := 3 * time.Second
	if os.Getenv("CS_QUICK") != "" {
		run(e.url, "gateway write", 1, d, write)
		return
	}
	for _, w := range []int{1, 32} {
		run(e.dsn, "direct read", w, d, read)
		run(e.url, "through the gateway read", w, d, read)
	}
	for _, w := range []int{1, 32} {
		run(e.dsn, "direct write (autocommit)", w, d, write)
		run(e.url, "gateway write, vault on 3 replicas", w, d, write)
	}
	_ = fmt.Sprint
}
