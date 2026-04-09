// Package hook handles the hook event lifecycle.
// It reads hook events from stdin, hands them to the local evaluator,
// and writes the resulting decision to stdout.
package hook

import (
	"fmt"
	"io"
	"os"

	"github.com/kontext-dev/kontext-cli/internal/agent"
)

// Run processes a single hook event. Called by `kontext hook --agent <name>`.
// Reads JSON from stdin, decodes via the agent adapter, evaluates the event,
// and writes the decision to stdout/stderr with the appropriate exit code.
func Run(a agent.Agent, evaluate func(*agent.HookEvent) (bool, string, error)) {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		// Fail-closed: deny on read error
		fmt.Fprintf(os.Stderr, "kontext: failed to read stdin: %v", err)
		os.Exit(2)
	}

	event, err := a.DecodeHookInput(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kontext: failed to decode hook input: %v", err)
		os.Exit(2)
	}

	allowed, reason, err := evaluate(event)
	if err != nil {
		// Fail-closed: deny on evaluation error
		fmt.Fprintf(os.Stderr, "kontext: evaluation error: %v", err)
		os.Exit(2)
	}

	if !allowed {
		out, _ := a.EncodeDeny(event, reason)
		os.Stderr.Write([]byte(fmt.Sprintf("Blocked by Kontext: %s", reason)))
		os.Stdout.Write(out)
		os.Exit(2)
	}

	out, _ := a.EncodeAllow(event, reason)
	os.Stdout.Write(out)
	os.Exit(0)
}
