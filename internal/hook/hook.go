package hook

import (
	"fmt"
	"io"
	"os"

	"github.com/kontext-security/kontext-cli/internal/agent"
)

func Run(a agent.Agent, evaluate func(*agent.HookEvent) (bool, string, error)) {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr, a, evaluate))
}

func run(stdin io.Reader, stdout, stderr io.Writer, a agent.Agent, evaluate func(*agent.HookEvent) (bool, string, error)) int {
	input, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to read stdin: %v\n", err)
		return 2
	}

	event, err := a.DecodeHookInput(input)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to decode hook input: %v\n", err)
		return 2
	}

	allowed, reason, err := evaluate(event)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: evaluation error: %v\n", err)
		return 2
	}

	if !allowed {
		out, err := a.EncodeDeny(event, reason)
		if err != nil {
			fmt.Fprintf(stderr, "kontext: failed to encode deny output: %v\n", err)
			return 2
		}
		if _, err := fmt.Fprintf(stderr, "Blocked by Kontext: %s\n", reason); err != nil {
			fmt.Fprintf(stderr, "kontext: failed to write deny message: %v\n", err)
			return 2
		}
		if _, err := stdout.Write(out); err != nil {
			fmt.Fprintf(stderr, "kontext: failed to write hook output: %v\n", err)
			return 2
		}
		return 2
	}

	out, err := a.EncodeAllow(event, reason)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: failed to encode allow output: %v\n", err)
		return 2
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintf(stderr, "kontext: failed to write hook output: %v\n", err)
		return 2
	}
	return 0
}
