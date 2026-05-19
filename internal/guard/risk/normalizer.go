package risk

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var credentialAssignment = regexp.MustCompile(`(?i)\b([a-z0-9_]*(?:api[_-]?key|token|secret|access[_-]?key)[a-z0-9_]*|api[_-]?key|token|secret)\s*=\s*("[^"]*"|'[^']*'|[^\s;&|]+)`)
var credentialHeader = regexp.MustCompile(`(?i)(authorization\s*:\s*)(bearer\s+)?("[^"]*"|'[^']*'|[^\s;&|]+)`)
var credentialBearer = regexp.MustCompile(`(?i)\bbearer\s+("[^"]*"|'[^']*'|[a-z0-9._~+/=-]+)`)
var credentialShape = regexp.MustCompile(`(?i)(authorization\s*:|api[_-]?key\s*[=:]|secret\s*[=:]|token\s*[=:])`)
var credentialReference = regexp.MustCompile(`(?i)(authorization\s*:|bearer\s+[a-z0-9._~+/=-]+|api[_-]?key\s*[=:]|secret\s*[=:]|token\s*[=:]|\$[A-Z0-9_]*(TOKEN|SECRET|API_KEY|ACCESS_KEY)[A-Z0-9_]*)`)
var destructiveWord = regexp.MustCompile(`(?i)\b(delete|destroy|drop|truncate|wipe)\b`)
var resourceWord = regexp.MustCompile(`(?i)\b(database|volume|backup|bucket|project|repo|repository|branch|deployment|namespace|secret)\b`)
var productionEnvironment = regexp.MustCompile(`(?i)(^|[^a-z0-9])(prod|production)([^a-z0-9]|$)`)
var destructiveDatabaseText = regexp.MustCompile(`(?i)\b(drop\s+(database|schema|table)|truncate\s+(table\s+)?[a-z0-9_.-]+|dropdb|mysqladmin\s+drop|flushall|flushdb)\b`)
var recursiveRemoveText = regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+.*(postgres|mysql|mongodb|redis|/var/lib|/data)\b`)
var textValueOption = regexp.MustCompile(`(?s)(^|\s)(-m|--message|--title|--body|--body-file|--notes|--notes-file)(=|\s+)("[^"]*"|'[^']*'|\S+)`)

func NormalizeHookEvent(event HookEvent) RiskEvent {
	toolName := strings.TrimSpace(event.ToolName)
	inputText := strings.ToLower(MarshalInput(event.ToolInput))
	command := commandFromInput(event.ToolInput)
	path := pathFromInput(event.ToolInput)
	commandSignalText := commandRiskText(command)
	environmentText := inputText + " " + strings.ToLower(path)
	if command != "" {
		environmentText = strings.ToLower(commandSignalText + " " + path)
	}
	riskEvent := RiskEvent{
		Type:             EventNormalToolCall,
		ProviderCategory: "unknown",
		OperationClass:   "unknown",
		ResourceClass:    "unknown",
		Environment:      environmentFromText(environmentText),
		CommandSummary:   redact(command),
		RequestSummary:   summarizeRequest(toolName, path, command),
		Confidence:       0.75,
	}

	lowerTool := strings.ToLower(toolName)
	lowerCommand := strings.ToLower(command)
	combinedInput := inputText
	if command != "" {
		combinedInput = ""
	}
	combined := strings.ToLower(fmt.Sprintf("%s %s %s", toolName, commandSignalText, combinedInput))

	if strings.HasPrefix(lowerTool, "mcp__") {
		riskEvent.Type = EventManagedToolCall
		addSignal(&riskEvent, "managed_tool")
		classifyManagedTool(&riskEvent, lowerTool, inputText)
	}
	if lowerTool == "bash" || strings.Contains(lowerTool, "bash") || strings.Contains(lowerTool, "shell") {
		classifySourceControl(&riskEvent, lowerCommand)
	}
	if isReadTool(lowerTool) && isCredentialPath(path) {
		riskEvent.Type = EventCredentialAccess
		riskEvent.CredentialObserved = true
		riskEvent.CredentialSource = "tool_input"
		riskEvent.PathClass = pathClass(path)
		addSignal(&riskEvent, "credential_path")
	}
	if isWriteTool(lowerTool) && isCredentialPath(path) {
		riskEvent.Type = EventCredentialAccess
		riskEvent.CredentialObserved = true
		riskEvent.CredentialSource = "tool_input"
		riskEvent.PathClass = pathClass(path)
		addSignal(&riskEvent, "credential_path")
		addSignal(&riskEvent, "credential_file_write")
	}
	if lowerTool == "bash" || strings.Contains(lowerTool, "bash") || strings.Contains(lowerTool, "shell") {
		classifyBash(&riskEvent, lowerCommand, commandSignalText)
		classifyProviderCommand(&riskEvent, lowerCommand, commandSignalText)
	}
	if strings.Contains(lowerCommand, "curl") {
		classifyProvider(&riskEvent, lowerCommand)
	}
	if observesCredential(lowerCommand, riskEvent.Type) {
		riskEvent.CredentialObserved = true
		if riskEvent.CredentialSource == "" {
			riskEvent.CredentialSource = "tool_input"
		}
		addSignal(&riskEvent, "credential_observed")
	}
	if op := destructiveOperation(combined); op != "" {
		riskEvent.Operation = op
		riskEvent.OperationClass = "delete"
		addSignal(&riskEvent, "destructive_verb")
	}
	if resource := resourceClass(combined); resource != "" {
		riskEvent.ResourceClass = resource
		addSignal(&riskEvent, "persistent_resource")
	}
	if riskEvent.OperationClass == "delete" && isPersistentResource(riskEvent.ResourceClass) {
		riskEvent.Type = EventDestructiveProviderOperation
	}
	if riskEvent.Type == EventNormalToolCall && looksUnknownHighRisk(combined) {
		riskEvent.Type = EventUnknown
		addSignal(&riskEvent, "unknown_high_risk")
	}
	if explicitIntent(combined) {
		riskEvent.ExplicitUserIntent = true
		addSignal(&riskEvent, "explicit_user_intent")
	}
	if riskEvent.Provider == "" && riskEvent.Type == EventDirectProviderAPICall {
		riskEvent.Provider = "unknown"
		riskEvent.ProviderCategory = "infrastructure"
	}
	return riskEvent
}

func classifyBash(event *RiskEvent, command, combined string) {
	if strings.Contains(command, "cat .env") || strings.Contains(command, "printenv") {
		event.Type = EventCredentialAccess
		event.CredentialObserved = true
		event.CredentialSource = "command_output"
		if strings.Contains(command, ".env") {
			event.PathClass = "env_file"
		}
		addSignal(event, "shell_credential_access")
	}
	if strings.Contains(command, "curl") {
		classifyProvider(event, command)
	}
	if destructiveDatabaseText.MatchString(combined) || recursiveRemoveText.MatchString(combined) {
		event.Type = EventDestructiveProviderOperation
		event.ProviderCategory = "infrastructure"
		event.Operation = "destructive_database_operation"
		event.OperationClass = "delete"
		event.ResourceClass = "database"
		addSignal(event, "destructive_database")
		addSignal(event, "persistent_resource")
	}
}

func classifySourceControl(event *RiskEvent, command string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return
	}
	switch fields[0] {
	case "git":
		event.Provider = "git"
		event.ProviderCategory = "source_control"
		addSignal(event, "source_control")
		if len(fields) > 1 {
			event.Operation = fields[1]
			switch fields[1] {
			case "add", "commit", "merge", "rebase", "push", "tag":
				event.OperationClass = "write"
				if fields[1] == "push" {
					addSignal(event, "source_control_remote_write")
				}
			case "status", "diff", "log", "show", "branch":
				event.OperationClass = "read"
			}
		}
	case "gh":
		event.Provider = "github"
		event.ProviderCategory = "source_control"
		addSignal(event, "source_control")
		if len(fields) > 1 {
			event.Operation = strings.Join(fields[:min(len(fields), 3)], " ")
			event.OperationClass = "write"
			if fields[1] == "pr" && len(fields) > 2 {
				switch fields[2] {
				case "view", "list", "status", "checks", "diff":
					event.OperationClass = "read"
				case "merge", "close", "comment", "review":
					addSignal(event, "source_control_remote_write")
				}
			}
			if fields[1] == "repo" && len(fields) > 2 && fields[2] == "delete" {
				addSignal(event, "source_control_remote_write")
			}
			if fields[1] == "release" {
				addSignal(event, "source_control_remote_write")
			}
		}
	}
}

func classifyProvider(event *RiskEvent, text string) {
	providers := map[string]string{
		"api.railway.app":      "railway",
		"railway.app":          "railway",
		"api.vercel.com":       "vercel",
		"api.digitalocean.com": "digitalocean",
		"api.cloudflare.com":   "cloudflare",
		"googleapis.com":       "google_cloud",
		"amazonaws.com":        "aws",
		"api.github.com":       "github",
	}
	for host, provider := range providers {
		if strings.Contains(text, host) {
			event.Type = EventDirectProviderAPICall
			event.Provider = provider
			event.DirectAPICall = true
			event.OperationClass = httpOperationClass(text)
			if provider == "github" {
				event.ProviderCategory = "source_control"
			} else {
				event.ProviderCategory = "infrastructure"
			}
			if resource := resourceClass(text); resource != "" {
				event.ResourceClass = resource
			}
			addSignal(event, "direct_provider_api")
			return
		}
	}
}

func classifyProviderCommand(event *RiskEvent, command, actionText string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return
	}
	switch fields[0] {
	case "aws":
		event.Provider = "aws"
		event.ProviderCategory = "infrastructure"
		addSignal(event, "provider_cli")
		if len(fields) > 2 {
			event.Operation = strings.Join(fields[:3], " ")
			switch {
			case fields[1] == "s3" && fields[2] == "rm":
				event.OperationClass = "delete"
				event.ResourceClass = "bucket"
			case fields[1] == "rds" && strings.Contains(fields[2], "delete"):
				event.OperationClass = "delete"
				event.ResourceClass = "database"
			case strings.HasPrefix(fields[2], "delete") || strings.HasPrefix(fields[2], "remove"):
				event.OperationClass = "delete"
			case strings.HasPrefix(fields[2], "put") || strings.HasPrefix(fields[2], "update") || strings.HasPrefix(fields[2], "create"):
				event.OperationClass = "write"
			}
		}
	case "kubectl":
		event.Provider = "kubernetes"
		event.ProviderCategory = "infrastructure"
		addSignal(event, "provider_cli")
		if len(fields) > 1 {
			event.Operation = fields[1]
		}
		if len(fields) > 2 {
			event.ResourceClass = normalizeResourceClass(fields[2])
		}
		switch {
		case len(fields) > 1 && fields[1] == "delete":
			event.OperationClass = "delete"
		case len(fields) > 2 && fields[1] == "rollout" && fields[2] == "status":
			event.OperationClass = "read"
		case len(fields) > 1 && (fields[1] == "apply" || fields[1] == "rollout" || fields[1] == "scale"):
			event.OperationClass = "write"
		case len(fields) > 1 && (fields[1] == "get" || fields[1] == "describe" || fields[1] == "logs"):
			event.OperationClass = "read"
		}
	case "terraform":
		event.Provider = "terraform"
		event.ProviderCategory = "infrastructure"
		addSignal(event, "provider_cli")
		if len(fields) > 1 {
			event.Operation = fields[1]
			event.ResourceClass = "deployment"
			switch fields[1] {
			case "destroy":
				event.OperationClass = "delete"
			case "apply", "taint", "import":
				event.OperationClass = "write"
			case "plan", "show", "state":
				event.OperationClass = "read"
			}
		}
	case "railway":
		event.Provider = "railway"
		event.ProviderCategory = "infrastructure"
		addSignal(event, "provider_cli")
		if len(fields) > 2 {
			event.Operation = strings.Join(fields[:3], " ")
			if fields[1] == "volume" && fields[2] == "delete" {
				event.OperationClass = "delete"
				event.ResourceClass = "volume"
			}
			if fields[1] == "variables" && fields[2] == "set" {
				event.OperationClass = "write"
				event.ResourceClass = "secret"
			}
		}
	case "vercel":
		event.Provider = "vercel"
		event.ProviderCategory = "infrastructure"
		addSignal(event, "provider_cli")
		if len(fields) > 1 {
			event.Operation = fields[1]
			event.ResourceClass = "deployment"
			switch fields[1] {
			case "remove", "delete":
				event.OperationClass = "delete"
			case "deploy", "promote", "rollback":
				event.OperationClass = "write"
			case "ls", "inspect", "env":
				event.OperationClass = "read"
			}
		}
	case "docker":
		event.Provider = "docker"
		event.ProviderCategory = "infrastructure"
		addSignal(event, "provider_cli")
		event.ResourceClass = "deployment"
		if dockerComposeDownWithVolumes(fields) {
			event.Operation = "compose down --volumes"
			event.OperationClass = "delete"
			event.ResourceClass = "volume"
		} else if strings.Contains(command, " service update") || strings.Contains(command, " compose up") {
			event.OperationClass = "write"
		}
	case "psql", "mysql", "sqlite3", "dropdb", "mysqladmin", "redis-cli":
		event.Provider = databaseProvider(fields[0])
		event.ProviderCategory = "infrastructure"
		addSignal(event, "provider_cli")
		if destructiveDatabaseText.MatchString(actionText) {
			event.Type = EventDestructiveProviderOperation
			event.Operation = "destructive_database_operation"
			event.OperationClass = "delete"
			event.ResourceClass = "database"
			addSignal(event, "destructive_database")
		} else {
			event.ResourceClass = "database"
		}
	}
}

func classifyManagedTool(event *RiskEvent, tool, inputText string) {
	parts := strings.Split(tool, "__")
	if len(parts) < 3 {
		return
	}
	provider := parts[1]
	action := parts[2]
	event.Provider = provider
	event.Operation = action
	event.ProviderCategory = managedProviderCategory(provider)
	event.OperationClass = operationClassFromAction(action)
	event.ResourceClass = resourceClassFromText(action + " " + inputText)
	if event.ResourceClass == "unknown" {
		event.ResourceClass = "project"
	}
	if event.OperationClass != "read" {
		addSignal(event, "managed_tool_write")
	}
	if event.Environment == "production" {
		addSignal(event, "production")
	}
	if event.OperationClass == "delete" && isPersistentResource(event.ResourceClass) {
		event.Type = EventDestructiveProviderOperation
	}
}

func commandFromInput(input map[string]any) string {
	for _, key := range []string{"command", "cmd", "script"} {
		if value, ok := input[key].(string); ok {
			return value
		}
	}
	return ""
}

func pathFromInput(input map[string]any) string {
	for _, key := range []string{"file_path", "path", "filename"} {
		if value, ok := input[key].(string); ok {
			return value
		}
	}
	return ""
}

func isReadTool(tool string) bool {
	return tool == "read" || strings.Contains(tool, "read")
}

func isWriteTool(tool string) bool {
	switch tool {
	case "write", "edit", "multiedit", "notebookedit":
		return true
	default:
		return strings.Contains(tool, "write") || strings.Contains(tool, "edit")
	}
}

func isCredentialPath(path string) bool {
	clean := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(clean)
	switch base {
	case ".env", ".npmrc", ".pypirc", ".netrc":
		return true
	}
	return strings.Contains(clean, "/.aws/") ||
		strings.Contains(clean, "/.gcloud/") ||
		strings.Contains(clean, "/.config/railway/")
}

func pathClass(path string) string {
	clean := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(clean)
	if base == ".env" || base == ".npmrc" || base == ".pypirc" || base == ".netrc" {
		return "env_file"
	}
	if strings.Contains(clean, "/.aws/") || strings.Contains(clean, "/.gcloud/") || strings.Contains(clean, "/.config/railway/") {
		return "cloud_credentials"
	}
	return "unknown"
}

func destructiveOperation(text string) string {
	match := destructiveWord.FindStringSubmatch(text)
	if len(match) > 1 {
		return strings.ToLower(match[1])
	}
	return ""
}

func resourceClass(text string) string {
	match := resourceWord.FindStringSubmatch(text)
	if len(match) > 1 {
		return normalizeResourceClass(match[1])
	}
	return ""
}

func resourceClassFromText(text string) string {
	if resource := resourceClass(text); resource != "" {
		return resource
	}
	if strings.Contains(text, "service") {
		return "deployment"
	}
	if strings.Contains(text, "policy") && strings.Contains(text, "bucket") {
		return "bucket"
	}
	return "unknown"
}

func normalizeResourceClass(resource string) string {
	switch strings.TrimSpace(strings.ToLower(resource)) {
	case "ns":
		return "namespace"
	case "pvc", "pv":
		return "volume"
	case "repo":
		return "repository"
	default:
		return strings.TrimSpace(strings.ToLower(resource))
	}
}

func isPersistentResource(resource string) bool {
	switch resource {
	case "database", "volume", "backup", "bucket", "project", "repo", "repository", "branch", "deployment", "namespace", "secret":
		return true
	default:
		return false
	}
}

func environmentFromText(text string) string {
	switch {
	case productionEnvironment.MatchString(text):
		return "production"
	case strings.Contains(text, "staging"):
		return "staging"
	case strings.Contains(text, "development") || strings.Contains(text, " dev"):
		return "development"
	case strings.Contains(text, "local"):
		return "local"
	default:
		return "unknown"
	}
}

func explicitIntent(text string) bool {
	return strings.Contains(text, "explicit_user_intent") || strings.Contains(text, "user_approved") || strings.Contains(text, "approved_by_user")
}

func looksUnknownHighRisk(text string) bool {
	return strings.Contains(text, "sudo ") || strings.Contains(text, "rm -rf") || strings.Contains(text, "chmod 777")
}

func summarizeRequest(toolName, path, command string) string {
	switch {
	case command != "":
		return redact(command)
	case path != "":
		return fmt.Sprintf("%s %s", toolName, path)
	default:
		return toolName
	}
}

func redact(value string) string {
	value = credentialAssignment.ReplaceAllString(value, "$1=[redacted-credential]")
	value = credentialHeader.ReplaceAllString(value, "${1}${2}[redacted-credential]")
	value = credentialBearer.ReplaceAllString(value, "Bearer [redacted-credential]")
	value = credentialShape.ReplaceAllString(value, "[redacted-credential]")
	if len(value) > 240 {
		return value[:240] + "..."
	}
	return value
}

func observesCredential(command string, eventType EventType) bool {
	if eventType == EventCredentialAccess {
		return true
	}
	return credentialReference.MatchString(stripHereDocs(command))
}

func commandRiskText(command string) string {
	withoutDocs := stripHereDocs(command)
	return stripTextOnlyArguments(withoutDocs)
}

func stripTextOnlyArguments(command string) string {
	fields := strings.Fields(strings.ToLower(command))
	if len(fields) == 0 {
		return command
	}
	if isSearchCommand(fields[0]) {
		return fields[0]
	}
	if fields[0] == "git" && len(fields) > 1 && fields[1] == "commit" {
		return textValueOption.ReplaceAllString(command, "$1$2 [text]")
	}
	if fields[0] == "gh" && len(fields) > 2 && fields[1] == "pr" && fields[2] == "create" {
		return textValueOption.ReplaceAllString(command, "$1$2 [text]")
	}
	return command
}

func isSearchCommand(command string) bool {
	switch filepath.Base(command) {
	case "grep", "egrep", "fgrep", "rg", "ag":
		return true
	default:
		return false
	}
}

func httpOperationClass(text string) string {
	if strings.Contains(text, "-x delete") || strings.Contains(text, "--request delete") {
		return "delete"
	}
	if strings.Contains(text, "-x post") || strings.Contains(text, "-x put") || strings.Contains(text, "-x patch") ||
		strings.Contains(text, "--request post") || strings.Contains(text, "--request put") || strings.Contains(text, "--request patch") {
		return "write"
	}
	return "read"
}

func operationClassFromAction(action string) string {
	action = strings.ToLower(action)
	switch {
	case strings.HasPrefix(action, "list") || strings.HasPrefix(action, "get") ||
		strings.HasPrefix(action, "read") || strings.HasPrefix(action, "search") ||
		strings.HasPrefix(action, "describe") || strings.HasPrefix(action, "fetch"):
		return "read"
	case strings.HasPrefix(action, "delete") || strings.HasPrefix(action, "remove") ||
		strings.Contains(action, "delete") || strings.Contains(action, "remove"):
		return "delete"
	case strings.HasPrefix(action, "put") || strings.HasPrefix(action, "set") ||
		strings.HasPrefix(action, "update") || strings.HasPrefix(action, "create") ||
		strings.HasPrefix(action, "restart") || strings.HasPrefix(action, "deploy") ||
		strings.HasPrefix(action, "merge") || strings.HasPrefix(action, "push") ||
		strings.Contains(action, "policy") || strings.Contains(action, "restart"):
		return "write"
	default:
		return "unknown"
	}
}

func managedProviderCategory(provider string) string {
	switch provider {
	case "aws", "railway", "vercel", "kubernetes", "cloudflare", "digitalocean", "google_cloud", "gcp":
		return "infrastructure"
	case "github", "gitlab":
		return "source_control"
	default:
		return "unknown"
	}
}

func databaseProvider(command string) string {
	switch command {
	case "mysql", "mysqladmin":
		return "mysql"
	case "sqlite3":
		return "sqlite"
	case "redis-cli":
		return "redis"
	default:
		return "postgres"
	}
}

func dockerComposeDownWithVolumes(fields []string) bool {
	composeSeen := false
	downSeen := false
	volumeSeen := false
	for _, field := range fields {
		switch field {
		case "compose":
			composeSeen = true
		case "down":
			downSeen = true
		case "-v", "--volumes":
			volumeSeen = true
		}
	}
	return composeSeen && downSeen && volumeSeen
}

func stripHereDocs(command string) string {
	lines := strings.Split(command, "\n")
	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		out = append(out, line)
		marker := heredocMarker(line)
		if marker == "" {
			continue
		}
		for i+1 < len(lines) {
			i++
			if strings.TrimSpace(lines[i]) == marker {
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

func heredocMarker(line string) string {
	idx := strings.Index(line, "<<")
	if idx < 0 {
		return ""
	}
	marker := strings.TrimSpace(line[idx+2:])
	marker = strings.TrimPrefix(marker, "-")
	marker = strings.Trim(marker, `"'`)
	if marker == "" || strings.ContainsAny(marker, " \t") {
		return ""
	}
	return marker
}

func stripQuotedText(value string) string {
	var b strings.Builder
	inSingle := false
	inDouble := false
	escaped := false
	for _, r := range value {
		switch {
		case escaped:
			escaped = false
			if !inSingle && !inDouble {
				b.WriteRune(r)
			}
		case r == '\\':
			escaped = true
			if !inSingle && !inDouble {
				b.WriteRune(r)
			}
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			b.WriteRune(' ')
		case r == '"' && !inSingle:
			inDouble = !inDouble
			b.WriteRune(' ')
		case inSingle || inDouble:
			if r == '\n' {
				b.WriteRune('\n')
			} else {
				b.WriteRune(' ')
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func addSignal(event *RiskEvent, signal string) {
	for _, existing := range event.Signals {
		if existing == signal {
			return
		}
	}
	event.Signals = append(event.Signals, signal)
}
