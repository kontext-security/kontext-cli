package agent

type Agent interface {
	Name() string

	DecodeHookInput(input []byte) (*HookEvent, error)

	EncodeAllow(event *HookEvent, reason string) ([]byte, error)

	EncodeDeny(event *HookEvent, reason string) ([]byte, error)
}

type HookEvent struct {
	SessionID      string
	HookEventName  string
	ToolName       string
	ToolInput      map[string]any
	ToolResponse   map[string]any
	ToolUseID      string
	CWD            string
	PermissionMode string
	DurationMs     *int64
	Error          string
	IsInterrupt    *bool
}

var registry = map[string]Agent{}

func Register(a Agent) {
	registry[a.Name()] = a
}

func Get(name string) (Agent, bool) {
	a, ok := registry[name]
	return a, ok
}

func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
