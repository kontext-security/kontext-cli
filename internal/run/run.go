// Package run implements the `kontext start` orchestrator.
package run

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cli/browser"

	agentv1 "github.com/kontext-security/kontext-cli/gen/kontext/agent/v1"
	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/auth"
	"github.com/kontext-security/kontext-cli/internal/backend"
	"github.com/kontext-security/kontext-cli/internal/credential"
	"github.com/kontext-security/kontext-cli/internal/sidecar"
)

// Options configures a kontext start run.
type Options struct {
	Agent        string
	TemplateFile string
	IssuerURL    string
	ClientID     string
	Args         []string
}

// Start is the main entry point for `kontext start`.
func Start(ctx context.Context, opts Options) error {
	if _, ok := agent.Get(opts.Agent); !ok {
		return fmt.Errorf("unsupported agent %q (supported: %s)", opts.Agent, strings.Join(supportedAgents(), ", "))
	}

	// 1. Auth
	session, err := ensureSession(ctx, opts.IssuerURL, opts.ClientID)
	if err != nil {
		return err
	}
	identity := session.User.Email
	if identity == "" {
		identity = session.User.Name
	}
	if identity == "" {
		identity = "authenticated"
	}
	fmt.Fprintf(os.Stderr, "✓ Authenticated as %s\n", identity)

	// 2. Backend client — token source refreshes automatically on expiry
	client := backend.NewClient(backend.BaseURL(), newSessionTokenSource(ctx, session))

	// 3. Create session via ConnectRPC
	hostname, _ := os.Hostname()
	cwd, _ := os.Getwd()
	createResp, err := client.CreateSession(ctx, &agentv1.CreateSessionRequest{
		UserId:   identity,
		Agent:    opts.Agent,
		Hostname: hostname,
		Cwd:      cwd,
		ClientInfo: map[string]string{
			"name": "kontext-cli",
			"os":   runtime.GOOS,
		},
	})
	if err != nil {
		return fmt.Errorf("create managed session: %w", err)
	}

	sessionID := createResp.SessionId
	credentialClientID := resolveCredentialClientID(createResp.AgentId, opts.ClientID)
	fmt.Fprintf(os.Stderr, "✓ Session: %s (%s)\n", createResp.SessionName, truncateID(sessionID))

	var sessionDir string
	defer func() {
		endManagedSession(client, sessionID, os.Stderr)
		if sessionDir != "" {
			os.RemoveAll(sessionDir)
		}
	}()

	// 4. Bootstrap the shared CLI application and sync the local env file.
	templateExists := false
	if _, err := os.Stat(opts.TemplateFile); err == nil {
		templateExists = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat env template: %w", err)
	}

	bootstrapResp, bootstrapErr := client.BootstrapCli(ctx, &agentv1.BootstrapCliRequest{
		AgentId: createResp.AgentId,
	})
	if bootstrapErr != nil && !templateExists {
		return fmt.Errorf("bootstrap cli application: %w", bootstrapErr)
	}

	var templateDoc *credential.TemplateFile
	if bootstrapErr != nil {
		fmt.Fprintf(os.Stderr, "⚠ Provider sync skipped (%v)\n", bootstrapErr)
		templateDoc, err = credential.LoadTemplateFile(opts.TemplateFile)
		if err != nil {
			return fmt.Errorf("load env template: %w", err)
		}
	} else {
		syncResult, err := credential.EnsureManagedTemplate(
			opts.TemplateFile,
			managedProvidersFromBootstrap(bootstrapResp.ManagedProviders),
		)
		if err != nil {
			return fmt.Errorf("sync env template: %w", err)
		}
		templateDoc = syncResult.Template
		if syncResult.Created {
			fmt.Fprintf(
				os.Stderr,
				"✓ Created local %s automatically\n",
				opts.TemplateFile,
			)
		}
		if syncResult.Updated {
			fmt.Fprintf(
				os.Stderr,
				"✓ Updated %s with managed preset entries: %s\n",
				opts.TemplateFile,
				joinManagedEnvVars(syncResult.Added),
			)
		}
		for _, provider := range syncResult.CollisionSkipped {
			fmt.Fprintf(
				os.Stderr,
				"⚠ Skipped auto-adding %s because that key already exists in %s\n",
				provider.EnvVar,
				opts.TemplateFile,
			)
		}
		if templateDoc != nil && !templateDoc.SafeToMutate && templateDoc.MutationWarning != "" {
			fmt.Fprintf(os.Stderr, "⚠ %s\n", templateDoc.MutationWarning)
		}
	}

	for _, invalid := range templateDoc.InvalidPlaceholders {
		fmt.Fprintf(
			os.Stderr,
			"⚠ Invalid Kontext placeholder for %s: %s\n",
			invalid.EnvVar,
			invalid.Value,
		)
	}

	if len(templateDoc.Entries) == 0 {
		fmt.Fprintf(
			os.Stderr,
			"ℹ No provider credentials were requested from %s; continuing without managed provider env vars.\n",
			opts.TemplateFile,
		)
	}

	// 5. Resolve credentials (before sidecar starts — no background goroutines yet,
	//    so reading session fields is safe without synchronization)
	var resolved []credential.Resolved
	if len(templateDoc.Entries) > 0 {
		resolved, err = resolveCredentials(ctx, session, templateDoc.Entries, credentialClientID)
		if err != nil {
			return err
		}
	}

	// 6. Start sidecar
	// Use /tmp (not $TMPDIR) with a short ID to keep the Unix socket path
	// under macOS's 104-byte sun_path limit.
	sessionDir = filepath.Join("/tmp", "kontext", truncateID(sessionID))
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	sc, err := sidecar.New(sessionDir, client, sessionID, opts.Agent)
	if err != nil {
		return fmt.Errorf("sidecar: %w", err)
	}
	if err := sc.Start(ctx); err != nil {
		return fmt.Errorf("sidecar start: %w", err)
	}
	defer sc.Stop()

	// 7. Generate hook settings
	kontextBin, _ := os.Executable()
	settingsPath, err := GenerateSettings(sessionDir, kontextBin, opts.Agent)
	if err != nil {
		return fmt.Errorf("generate settings: %w", err)
	}

	// 8. Build env
	env := buildEnv(templateDoc, resolved)
	env = append(env, "KONTEXT_SOCKET="+sc.SocketPath())
	env = append(env, "KONTEXT_SESSION_ID="+sessionID)

	// 9. Launch agent with hooks
	fmt.Fprintf(os.Stderr, "\nLaunching %s...\n\n", opts.Agent)
	agentErr := launchAgentWithSettings(ctx, opts.Agent, env, opts.Args, settingsPath)

	return agentErr
}

type sessionEnder interface {
	EndSession(context.Context, string) error
}

func endManagedSession(client sessionEnder, sessionID string, out io.Writer) {
	endCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = client.EndSession(endCtx, sessionID)
	fmt.Fprintf(out, "\n✓ Session ended (%s)\n", truncateID(sessionID))
}

// ensureSession loads the session or triggers an interactive login.
func ensureSession(ctx context.Context, issuerURL, clientID string) (*auth.Session, error) {
	session, err := auth.Preflight(ctx)
	if err == nil {
		return session, nil
	}

	fmt.Fprintln(os.Stderr, "No session found. Opening browser to log in...")
	result, err := auth.Login(ctx, issuerURL, clientID)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	if err := auth.SaveSession(result.Session); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	return result.Session, nil
}

// resolveCredentials exchanges each template entry for a live credential.
func resolveCredentials(ctx context.Context, session *auth.Session, entries []credential.Entry, credentialClientID string) ([]credential.Resolved, error) {
	fmt.Fprintln(os.Stderr, "\nResolving credentials...")
	resolved := make([]credential.Resolved, 0, len(entries))
	failures := make(map[string]error)
	entryByEnvVar := make(map[string]credential.Entry, len(entries))

	for _, entry := range entries {
		entryByEnvVar[entry.EnvVar] = entry
		fmt.Fprintf(os.Stderr, "  %s (%s)... ", entry.EnvVar, entry.Target())
		value, err := exchangeCredential(ctx, session, entry, credentialClientID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ skipped (%v)\n", err)
			failures[entry.EnvVar] = err
			continue
		}
		fmt.Fprintln(os.Stderr, "✓")
		resolved = append(resolved, credential.Resolved{Entry: entry, Value: value})
	}

	connectable := unresolvedConnectableEntries(entryByEnvVar, failures)
	if len(connectable) == 0 {
		printLaunchWarnings(entryByEnvVar, failures)
		return resolved, nil
	}

	interactive := isInteractiveTerminal()
	connectURL, connectErr := fetchConnectURLForConnectFlow(
		ctx,
		session,
		credentialClientID,
		interactive,
		auth.Login,
	)
	if connectErr != nil {
		if !interactive && needsGatewayAccessReauthentication(connectErr) {
			fmt.Fprintln(os.Stderr, "⚠ Non-interactive session detected. Re-run `kontext start` in an interactive terminal to authorize hosted connect.")
		}
		fmt.Fprintf(os.Stderr, "⚠ Could not create hosted connect session (%v)\n", connectErr)
		printLaunchWarnings(entryByEnvVar, failures)
		return resolved, nil
	}

	providerList := joinEntryProviders(connectable)
	fmt.Fprintf(os.Stderr, "\nHosted connect is available for: %s\n", providerList)
	fmt.Fprintf(os.Stderr, "  %s\n", connectURL)

	if !interactive {
		fmt.Fprintln(os.Stderr, "⚠ Non-interactive session detected. Open this URL in a browser, then rerun `kontext start`.")
		printLaunchWarnings(entryByEnvVar, failures)
		return resolved, nil
	}

	fmt.Fprintf(os.Stderr, "  Opening browser to connect %s...\n", providerList)
	if err := browser.OpenURL(connectURL); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ Could not open browser automatically (%v)\n", err)
		fmt.Fprintln(os.Stderr, "  Open the URL above to continue.")
	}
	fmt.Fprint(os.Stderr, "  Press Enter after connecting...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	retriedResolved, remainingFailures := retryConnectableCredentials(
		ctx,
		session,
		connectable,
		credentialClientID,
	)
	resolved = append(resolved, retriedResolved...)
	for _, entry := range connectable {
		if err, ok := remainingFailures[entry.EnvVar]; ok {
			failures[entry.EnvVar] = err
			continue
		}
		delete(failures, entry.EnvVar)
	}

	printLaunchWarnings(entryByEnvVar, failures)
	return resolved, nil
}

func unresolvedConnectableEntries(entryByEnvVar map[string]credential.Entry, failures map[string]error) []credential.Entry {
	var entries []credential.Entry
	for envVar, err := range failures {
		resolutionErr, ok := err.(*credentialResolutionError)
		if !ok || resolutionErr.Reason != failureDisconnected {
			continue
		}
		entry, ok := entryByEnvVar[envVar]
		if !ok {
			continue
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b credential.Entry) int {
		return strings.Compare(a.EnvVar, b.EnvVar)
	})
	return entries
}

func retryConnectableCredentials(
	ctx context.Context,
	session *auth.Session,
	entries []credential.Entry,
	credentialClientID string,
) ([]credential.Resolved, map[string]error) {
	attemptDelays := []time.Duration{0, 3 * time.Second, 7 * time.Second}
	pending := make(map[string]credential.Entry, len(entries))
	for _, entry := range entries {
		pending[entry.EnvVar] = entry
	}
	failures := make(map[string]error, len(entries))
	resolved := make([]credential.Resolved, 0, len(entries))

	for attempt, delay := range attemptDelays {
		if len(pending) == 0 {
			break
		}
		if delay > 0 {
			time.Sleep(delay)
		}

		for envVar, entry := range pending {
			fmt.Fprintf(
				os.Stderr,
				"  Retrying %s (%d/%d)... ",
				entry.EnvVar,
				attempt+1,
				len(attemptDelays),
			)
			value, err := exchangeCredential(ctx, session, entry, credentialClientID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠ skipped (%v)\n", err)
				failures[envVar] = err
				continue
			}
			fmt.Fprintln(os.Stderr, "✓")
			resolved = append(resolved, credential.Resolved{Entry: entry, Value: value})
			delete(failures, envVar)
			delete(pending, envVar)
		}
	}

	return resolved, failures
}

func printLaunchWarnings(entryByEnvVar map[string]credential.Entry, failures map[string]error) {
	if len(failures) == 0 {
		return
	}

	var skipped []string
	for envVar, err := range failures {
		entry, ok := entryByEnvVar[envVar]
		if !ok {
			continue
		}
		if resolutionErr, ok := err.(*credentialResolutionError); ok {
			switch resolutionErr.Reason {
			case failureNotAttached:
				fmt.Fprintf(
					os.Stderr,
					"⚠ %s is not attached to the Kontext CLI application. Attach %s to kontext-cli in the dashboard or edit %s.\n",
					entry.Provider,
					entry.Provider,
					entry.EnvVar,
				)
			case failureUnknown:
				fmt.Fprintf(os.Stderr, "⚠ %s references an unknown provider handle.\n", entry.EnvVar)
			case failureTransient:
				fmt.Fprintf(os.Stderr, "⚠ %s could not be resolved because of a temporary exchange error.\n", entry.EnvVar)
			case failureInvalid:
				fmt.Fprintf(os.Stderr, "⚠ %s contains an invalid Kontext placeholder.\n", entry.EnvVar)
			case failureDisconnected:
				fmt.Fprintf(
					os.Stderr,
					"⚠ %s was not available for this launch. Connect it in hosted connect and rerun `kontext start`.\n",
					entry.EnvVar,
				)
				skipped = append(skipped, entry.Provider)
			default:
				fmt.Fprintf(os.Stderr, "⚠ %s was skipped (%v)\n", entry.EnvVar, err)
			}
			continue
		}

		fmt.Fprintf(os.Stderr, "⚠ %s was skipped (%v)\n", entry.EnvVar, err)
	}

	if len(skipped) > 0 {
		slices.Sort(skipped)
		fmt.Fprintf(os.Stderr, "⚠ Launching without these providers: %s\n", strings.Join(slices.Compact(skipped), ", "))
		fmt.Fprintln(os.Stderr, "⚠ Providers connected after launch become available on the next `kontext start`.")
	}
}

func joinEntryProviders(entries []credential.Entry) string {
	providers := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, ok := seen[entry.Provider]; ok {
			continue
		}
		seen[entry.Provider] = struct{}{}
		providers = append(providers, entry.Provider)
	}
	slices.Sort(providers)
	return strings.Join(providers, ", ")
}

func isInteractiveTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

type loginFunc func(context.Context, string, string, ...string) (*auth.LoginResult, error)

func fetchConnectURLForConnectFlow(
	ctx context.Context,
	session *auth.Session,
	credentialClientID string,
	interactive bool,
	login loginFunc,
) (string, error) {
	if !interactive {
		return fetchConnectURL(ctx, session, credentialClientID)
	}

	return fetchConnectURLWithGatewayLoginFallback(
		ctx,
		session,
		credentialClientID,
		login,
	)
}

func fetchConnectURLWithGatewayLoginFallback(
	ctx context.Context,
	session *auth.Session,
	credentialClientID string,
	login loginFunc,
) (string, error) {
	connectURL, err := fetchConnectURL(ctx, session, credentialClientID)
	if err == nil || !needsGatewayAccessReauthentication(err) {
		return connectURL, err
	}

	fmt.Fprintln(os.Stderr, "  Session missing gateway access. Opening browser to authorize this CLI session...")
	result, err := login(ctx, session.IssuerURL, credentialClientID, "gateway:access")
	if err != nil {
		return "", fmt.Errorf("authorize gateway access: %w", err)
	}

	gatewayToken, err := exchangeGatewayToken(ctx, result.Session, credentialClientID)
	if err != nil {
		return "", fmt.Errorf("exchange gateway token after authorize: %w", err)
	}

	return fetchConnectURLWithGatewayToken(ctx, result.Session.IssuerURL, gatewayToken)
}

func fetchConnectURL(ctx context.Context, session *auth.Session, clientID string) (string, error) {
	gatewayToken, err := exchangeGatewayToken(ctx, session, clientID)
	if err != nil {
		return "", err
	}

	return fetchConnectURLWithGatewayToken(ctx, session.IssuerURL, gatewayToken)
}

func fetchConnectURLWithGatewayToken(ctx context.Context, issuerURL, gatewayToken string) (string, error) {
	connectSessionURL := strings.TrimRight(issuerURL, "/") + "/mcp/connect-session"

	req, err := http.NewRequestWithContext(ctx, "POST", connectSessionURL, strings.NewReader("{}"))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gatewayToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connect session request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return "", fmt.Errorf("connect session request failed: %s", resp.Status)
		}

		msg := strings.TrimSpace(string(body))
		if msg == "" {
			return "", fmt.Errorf("connect session request failed: %s", resp.Status)
		}
		return "", fmt.Errorf("connect session request failed: %s: %s", resp.Status, msg)
	}

	var result struct {
		ConnectURL string `json:"connectUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode connect session response: %w", err)
	}
	if result.ConnectURL == "" {
		return "", fmt.Errorf("connect session response missing connectUrl")
	}

	return result.ConnectURL, nil
}

func agentOAuthClientID(agentID string) string {
	return "app_" + agentID
}

func resolveCredentialClientID(agentID, fallback string) string {
	if strings.TrimSpace(agentID) == "" {
		return fallback
	}
	return agentOAuthClientID(agentID)
}

type tokenExchangeResponse struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ProviderKind          string `json:"provider_kind"`
	Error                 string `json:"error"`
	ErrorDesc             string `json:"error_description"`
	FailureReason         string `json:"failure_reason"`
	ProviderName          string `json:"provider_name"`
	ProviderID            string `json:"provider_id"`
	ReauthorizationReason string `json:"reauthorization_reason"`
}

type credentialFailureReason string

const (
	failureDisconnected credentialFailureReason = "disconnected_or_reauth_required"
	failureNotAttached  credentialFailureReason = "not_attached_to_application"
	failureUnknown      credentialFailureReason = "unknown_provider_handle"
	failureInvalid      credentialFailureReason = "invalid_placeholder"
	failureTransient    credentialFailureReason = "transient_exchange_error"
)

type credentialResolutionError struct {
	Reason       credentialFailureReason
	Entry        credential.Entry
	ProviderName string
	ProviderID   string
	Message      string
}

func (e *credentialResolutionError) Error() string {
	return e.Message
}

func exchangeToken(ctx context.Context, session *auth.Session, clientID, resource string, scopes ...string) (*tokenExchangeResponse, error) {
	meta, err := auth.DiscoverEndpoints(ctx, session.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oauth discovery: %w", err)
	}

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {clientID},
		"subject_token":      {session.AccessToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {resource},
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	var result tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode token exchange response: %w", err)
	}

	return &result, nil
}

func exchangeGatewayToken(ctx context.Context, session *auth.Session, clientID string) (string, error) {
	result, err := exchangeToken(ctx, session, clientID, "mcp-gateway", "gateway:access")
	if err != nil {
		return "", err
	}
	if result.Error != "" {
		return "", fmt.Errorf("gateway token exchange failed: %s: %s", result.Error, result.ErrorDesc)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("gateway token exchange returned empty access_token")
	}

	return result.AccessToken, nil
}

// exchangeCredential calls POST /oauth2/token with RFC 8693 token exchange
// to resolve a provider credential. The user's access token serves as both
// the subject_token and the Bearer auth — no client secret needed.
func exchangeCredential(ctx context.Context, session *auth.Session, entry credential.Entry, clientID string) (string, error) {
	result, err := exchangeToken(ctx, session, clientID, entry.Target())
	if err != nil {
		return "", &credentialResolutionError{
			Reason:  failureTransient,
			Entry:   entry,
			Message: fmt.Sprintf("token exchange request failed: %v", err),
		}
	}
	if result.Error != "" {
		switch classifyCredentialFailure(result) {
		case failureDisconnected, failureNotAttached, failureUnknown, failureInvalid, failureTransient:
			return "", &credentialResolutionError{
				Reason:       classifyCredentialFailure(result),
				Entry:        entry,
				ProviderName: result.ProviderName,
				ProviderID:   result.ProviderID,
				Message:      fmt.Sprintf("%s: %s", result.Error, result.ErrorDesc),
			}
		}
		return "", fmt.Errorf("token exchange failed: %s: %s", result.Error, result.ErrorDesc)
	}

	if result.AccessToken == "" {
		return "", fmt.Errorf("token exchange returned empty access_token")
	}

	return result.AccessToken, nil
}

func classifyCredentialFailure(
	result *tokenExchangeResponse,
) credentialFailureReason {
	switch credentialFailureReason(result.FailureReason) {
	case failureDisconnected, failureNotAttached, failureUnknown, failureInvalid, failureTransient:
		return credentialFailureReason(result.FailureReason)
	}

	switch result.Error {
	case "provider_required", "provider_not_configured", "provider_reauthorization_required":
		return failureDisconnected
	case "invalid_target":
		if isLegacyDisconnectedInvalidTarget(result.ErrorDesc) {
			return failureDisconnected
		}
		return ""
	default:
		return ""
	}
}

func isLegacyDisconnectedInvalidTarget(desc string) bool {
	normalized := strings.ToLower(desc)
	return strings.Contains(normalized, "not connected") ||
		strings.Contains(normalized, "not allowed")
}

func needsGatewayAccessReauthentication(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()
	return strings.Contains(msg, "invalid_scope") &&
		strings.Contains(msg, "gateway:access")
}

func buildEnv(templateDoc *credential.TemplateFile, resolved []credential.Resolved) []string {
	env := append(os.Environ(), "KONTEXT_RUN=1")
	if templateDoc != nil {
		placeholderKeys := make(map[string]struct{}, len(templateDoc.Entries)+len(templateDoc.InvalidPlaceholders))
		for _, entry := range templateDoc.Entries {
			placeholderKeys[entry.EnvVar] = struct{}{}
		}
		for _, invalid := range templateDoc.InvalidPlaceholders {
			placeholderKeys[invalid.EnvVar] = struct{}{}
		}
		for envVar, value := range templateDoc.ExistingValues {
			if _, isPlaceholder := placeholderKeys[envVar]; isPlaceholder {
				continue
			}
			env = append(env, fmt.Sprintf("%s=%s", envVar, credential.NormalizeEnvValue(value)))
		}
	}
	return credential.BuildEnv(resolved, env)
}

func managedProvidersFromBootstrap(items []*agentv1.ManagedProvider) []credential.ManagedProvider {
	managed := make([]credential.ManagedProvider, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		managed = append(managed, credential.ManagedProvider{
			EnvVar:         item.EnvVar,
			Placeholder:    item.Placeholder,
			SeedOnFirstRun: item.SeedOnFirstRun,
		})
	}
	return managed
}

func joinManagedEnvVars(items []credential.ManagedProvider) string {
	if len(items) == 0 {
		return ""
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.EnvVar)
	}
	return strings.Join(names, ", ")
}

func supportedAgents() []string {
	names := agent.Names()
	slices.Sort(names)
	return names
}

// newSessionTokenSource returns a TokenSource that transparently refreshes
// the OIDC access token when it expires, so long-running sessions keep working.
func newSessionTokenSource(ctx context.Context, session *auth.Session) backend.TokenSource {
	mu := &sync.Mutex{}
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()

		if !session.IsExpired() {
			return session.AccessToken, nil
		}

		refreshed, err := auth.RefreshSession(ctx, session)
		if err != nil {
			return "", fmt.Errorf("token expired and refresh failed: %w", err)
		}

		// Persist so other processes (and the next `kontext start`) see the new token
		if saveErr := auth.SaveSession(refreshed); saveErr != nil {
			fmt.Fprintf(os.Stderr, "⚠ Could not persist refreshed session: %v\n", saveErr)
		}

		// Update the shared session pointer for subsequent calls
		*session = *refreshed
		return session.AccessToken, nil
	}
}

func launchAgentWithSettings(_ context.Context, agentName string, env, extraArgs []string, settingsPath string) error {
	binaryPath, err := exec.LookPath(agentName)
	if err != nil {
		return fmt.Errorf("agent %q not found in PATH: %w", agentName, err)
	}

	var args []string
	if settingsPath != "" {
		args = append(args, "--settings", settingsPath)
	}
	args = append(args, filterArgs(extraArgs)...)

	cmd := exec.Command(binaryPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch %s: %w", agentName, err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	return err
}

// flagName extracts the flag name from an arg, handling --flag=value syntax.
func flagName(arg string) string {
	if i := strings.Index(arg, "="); i != -1 {
		return arg[:i]
	}
	return arg
}

func filterArgs(args []string) []string {
	blocked := map[string]bool{
		"--bare":                         true,
		"--dangerously-skip-permissions": true,
	}
	// Flags that take a value argument — strip the flag AND the next arg.
	blockedWithValue := map[string]bool{
		"--settings":        true,
		"--setting-sources": true,
	}

	var filtered []string
	skip := false
	for _, arg := range args {
		if skip {
			skip = false
			continue
		}
		name := flagName(arg)
		if blocked[name] {
			fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s\n", arg)
			continue
		}
		if blockedWithValue[name] {
			fmt.Fprintf(os.Stderr, "⚠ Stripped blocked flag: %s\n", arg)
			if !strings.Contains(arg, "=") {
				skip = true // skip the next arg (the value)
			}
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

func truncateID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}
