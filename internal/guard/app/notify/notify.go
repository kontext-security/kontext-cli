package notify

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

// Decision sends a local notification for high-signal recommendations.
func Decision(decision risk.RiskDecision) {
	if runtime.GOOS != "darwin" || os.Getenv("KONTEXT_NOTIFY") == "0" {
		return
	}
	if os.Getenv("KONTEXT_NOTIFY_ALL") != "1" && decision.Decision == risk.DecisionAllow {
		return
	}
	title := "Kontext would allow"
	switch decision.Decision {
	case risk.DecisionDeny:
		title = "Kontext would deny"
	}
	cmd := exec.Command("osascript", "-e", fmt.Sprintf(`display notification %q with title %q`, decision.Reason, title))
	if err := cmd.Start(); err == nil {
		go func() {
			_ = cmd.Wait()
		}()
	}
}
