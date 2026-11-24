package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"undolayer/internal/tx"
)

// notifier tells reviewers that a request is waiting: a command (the request as JSON on
// stdin) and/or a URL (POSTed the same JSON, with a one-line "text" field that chat
// webhooks display). Failures are reported on stderr and never block the request.
func notifier(command []string, url string) func(tx.PendingAction) {
	if len(command) == 0 && url == "" {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	return func(p tx.PendingAction) {
		payload := map[string]any{"request": p, "text": summary(p), "decide": decideCommand(p)}
		b, _ := json.Marshal(payload)
		if len(command) > 0 {
			cmd := exec.Command(command[0], command[1:]...)
			cmd.Stdin = bytes.NewReader(b)
			if out, err := cmd.CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "undolayer: notify command failed: %v: %s\n", err, strings.TrimSpace(string(out)))
			}
		}
		if url != "" {
			resp, err := client.Post(url, "application/json", bytes.NewReader(b))
			if err != nil {
				fmt.Fprintf(os.Stderr, "undolayer: notify %s failed: %v\n", url, err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "undolayer: notify %s answered %s\n", url, resp.Status)
			}
		}
	}
}

func summary(p tx.PendingAction) string {
	what := "commit of the whole task"
	if p.Kind == "action" && p.Action != nil {
		what = p.Action.Connector + "." + p.Action.Operation
	}
	s := fmt.Sprintf("Approval needed for %s in %q (%s): %s", what, p.Task, p.Tx, strings.Join(p.Reasons, "; "))
	if len(p.Needs) > 0 {
		s += ". Needs " + strings.Join(p.Needs, "; ")
	}
	return s + ". " + decideCommand(p)
}

func decideCommand(p tx.PendingAction) string {
	if p.Kind == "action" && p.Action != nil {
		return fmt.Sprintf("undolayer approve %s --action %s [--decline]", p.Tx, p.Action.ID)
	}
	return fmt.Sprintf("undolayer approve %s [--decline]", p.Tx)
}
