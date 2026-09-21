package worker

import (
	"fmt"
	"os"
	"strings"

	"github.com/sindredg/ai-k8s/internal/ledger"
)

// exitCode is distinct from the 1 the worker exits with on a startup failure, so a drill crash is
// separable from a real one in the Pod's last state.
const exitCode = 70

// boundaries are the three points the crash drills interrupt. classified is a ledger state but not
// a boundary: nothing observable sits between writing it and writing the notification attempt.
var boundaries = []ledger.State{ledger.Received, ledger.NotificationAttempted, ledger.Acknowledged}

// ParseCrashAt reads the -crash-at flag. An empty value leaves the hook off, which is how the
// worker runs everywhere except a drill.
func ParseCrashAt(value string) (ledger.State, error) {
	if value == "" {
		return "", nil
	}
	for _, b := range boundaries {
		if value == string(b) {
			return b, nil
		}
	}

	names := make([]string, len(boundaries))
	for i, b := range boundaries {
		names[i] = string(b)
	}
	return "", fmt.Errorf("%q is not a crash boundary, want one of: %s", value, strings.Join(names, ", "))
}

// crashIf stops the process at a named boundary, so the recovery the idempotency decision
// describes is drilled rather than described. It takes no input from a finding: only the command
// line the operator controls reaches it.
//
// os.Exit runs no deferred call, so nothing is acknowledged and no client closes. From Pub/Sub's
// side and the ledger's side that is indistinguishable from a SIGKILL, which is the point.
func (w *Worker) crashIf(state ledger.State) {
	if w.CrashAt == "" || w.CrashAt != state {
		return
	}
	w.logger().Error("crashing on purpose, the drill boundary was reached", "boundary", state)
	w.exit()(exitCode)
}

// exit is os.Exit unless a test injected something that returns.
func (w *Worker) exit() func(int) {
	if w.Exit != nil {
		return w.Exit
	}
	return os.Exit
}
