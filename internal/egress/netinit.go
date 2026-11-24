package egress

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
)

// MaybeNetinit handles `<self> __netinit --proxy-sock S --port P -- cmd...`, which runs
// inside a Linux network namespace: it bridges loopback:P to the proxy's Unix socket and
// runs cmd. Call it first in main() (and TestMain), before anything else.
func MaybeNetinit() {
	if len(os.Args) < 2 || os.Args[1] != "__netinit" {
		return
	}
	fs := flag.NewFlagSet("__netinit", flag.ExitOnError)
	sock := fs.String("proxy-sock", "", "")
	port := fs.Int("port", 0, "")
	_ = fs.Parse(os.Args[2:])
	argv := fs.Args()
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if *sock != "" {
		if _, err := Bridge("127.0.0.1:"+strconv.Itoa(*port), *sock); err != nil {
			fmt.Fprintln(os.Stderr, "undolayer netinit:", err)
			os.Exit(126)
		}
	}
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "undolayer netinit:", err)
		os.Exit(127)
	}
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sig {
			_ = c.Process.Signal(s)
		}
	}()
	_ = c.Wait()
	os.Exit(c.ProcessState.ExitCode())
}
