package run

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cli/browser"

	"github.com/kontext-security/kontext-cli/internal/auth"
	"github.com/kontext-security/kontext-cli/internal/credential"
)

const (
	kontextScheme   = "kontext"
	bitwardenScheme = "bitwarden"
)

type credentialResolver interface {
	Resolve(context.Context, credential.Entry) (string, error)
	UnresolvedConnectableEntries(map[string]credential.Entry, map[string]error) []credential.Entry
	ConnectAndRetry(context.Context, []credential.Entry) ([]credential.Resolved, map[string]error)
	PrintLaunchWarnings(map[string]credential.Entry, map[string]error)
}

type credentialResolverSet struct {
	resolvers map[string]credentialResolver
}

func newCredentialResolverSet(
	session *auth.Session,
	credentialClientID string,
) *credentialResolverSet {
	return newCredentialResolverSetWithFetcher(session, credentialClientID, fetchConnectURLForConnectFlow)
}

func newCredentialResolverSetWithFetcher(
	session *auth.Session,
	credentialClientID string,
	fetchConnect connectURLFetcher,
) *credentialResolverSet {
	return &credentialResolverSet{
		resolvers: map[string]credentialResolver{
			kontextScheme: &kontextCredentialResolver{
				session:            session,
				credentialClientID: credentialClientID,
				fetchConnectURL:    fetchConnect,
			},
			bitwardenScheme: &bitwardenCredentialResolver{},
		},
	}
}

func (s *credentialResolverSet) resolve(
	ctx context.Context,
	entry credential.Entry,
) (string, error) {
	return s.resolverFor(entry).Resolve(ctx, entry)
}

func (s *credentialResolverSet) unresolvedConnectableEntries(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) []credential.Entry {
	var entries []credential.Entry
	for scheme, resolver := range s.resolvers {
		schemeEntries := filterEntriesByScheme(entryByEnvVar, scheme)
		schemeFailures := filterFailuresByScheme(entryByEnvVar, failures, scheme)
		entries = append(entries, resolver.UnresolvedConnectableEntries(schemeEntries, schemeFailures)...)
	}
	slices.SortFunc(entries, func(a, b credential.Entry) int {
		return strings.Compare(a.EnvVar, b.EnvVar)
	})
	return entries
}

func (s *credentialResolverSet) connectAndRetry(
	ctx context.Context,
	entries []credential.Entry,
) ([]credential.Resolved, map[string]error) {
	resolved := make([]credential.Resolved, 0, len(entries))
	failures := make(map[string]error)
	for scheme, grouped := range groupEntriesByScheme(entries) {
		groupResolved, groupFailures := s.resolverByScheme(scheme).ConnectAndRetry(ctx, grouped)
		resolved = append(resolved, groupResolved...)
		for envVar, err := range groupFailures {
			failures[envVar] = err
		}
	}
	return resolved, failures
}

func (s *credentialResolverSet) printLaunchWarnings(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) {
	for scheme, resolver := range s.resolvers {
		schemeEntries := filterEntriesByScheme(entryByEnvVar, scheme)
		schemeFailures := filterFailuresByScheme(entryByEnvVar, failures, scheme)
		resolver.PrintLaunchWarnings(schemeEntries, schemeFailures)
	}
	for envVar, err := range failures {
		entry, ok := entryByEnvVar[envVar]
		if !ok {
			continue
		}
		if _, known := s.resolvers[entry.Scheme]; known {
			continue
		}
		fmt.Fprintf(os.Stderr, "⚠ %s was skipped (%v)\n", envVar, err)
	}
}

func (s *credentialResolverSet) resolverFor(entry credential.Entry) credentialResolver {
	return s.resolverByScheme(entry.Scheme)
}

func (s *credentialResolverSet) resolverByScheme(scheme string) credentialResolver {
	if scheme == "" {
		scheme = kontextScheme
	}
	if resolver, ok := s.resolvers[scheme]; ok {
		return resolver
	}
	return &unknownCredentialResolver{scheme: scheme}
}

type kontextCredentialResolver struct {
	session            *auth.Session
	credentialClientID string
	fetchConnectURL    connectURLFetcher
}

func (r *kontextCredentialResolver) Resolve(
	ctx context.Context,
	entry credential.Entry,
) (string, error) {
	return exchangeCredential(ctx, r.session, entry, r.credentialClientID)
}

func (r *kontextCredentialResolver) UnresolvedConnectableEntries(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) []credential.Entry {
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

func (r *kontextCredentialResolver) ConnectAndRetry(
	ctx context.Context,
	entries []credential.Entry,
) ([]credential.Resolved, map[string]error) {
	interactive := isInteractiveTerminal()
	connectURL, connectErr := r.fetchConnectURL(
		ctx,
		r.session,
		r.credentialClientID,
		interactive,
		auth.Login,
	)
	if connectErr != nil {
		if !interactive && needsGatewayAccessReauthentication(connectErr) {
			fmt.Fprintln(os.Stderr, "⚠ Non-interactive session detected. Re-run `kontext start` in an interactive terminal to authorize hosted connect.")
		}
		fmt.Fprintf(os.Stderr, "⚠ Could not create hosted connect session (%s)\n", connectFailureSummary(connectErr))
		return nil, failureMap(entries, connectErr)
	}

	providerList := joinEntryProviders(entries)
	fmt.Fprintf(os.Stderr, "\nHosted connect is available for: %s\n", providerList)
	fmt.Fprintf(os.Stderr, "  %s\n", connectURL)

	if !interactive {
		fmt.Fprintln(os.Stderr, "⚠ Non-interactive session detected. Open this URL in a browser, then rerun `kontext start`.")
		return nil, failureMap(entries, fmt.Errorf("hosted connect requires browser completion"))
	}

	fmt.Fprintf(os.Stderr, "  Opening browser to connect %s...\n", providerList)
	if err := browser.OpenURL(connectURL); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ Could not open browser automatically (%v)\n", err)
		fmt.Fprintln(os.Stderr, "  Open the URL above to continue.")
	}
	fmt.Fprint(os.Stderr, "  Press Enter after connecting...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	return r.retryEntries(ctx, entries)
}

func (r *kontextCredentialResolver) retryEntries(
	ctx context.Context,
	entries []credential.Entry,
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
			value, err := r.Resolve(ctx, entry)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠ skipped (%s)\n", credentialFailureSummary(err))
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

func (r *kontextCredentialResolver) PrintLaunchWarnings(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) {
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

func failureMap(entries []credential.Entry, err error) map[string]error {
	failures := make(map[string]error, len(entries))
	for _, entry := range entries {
		failures[entry.EnvVar] = err
	}
	return failures
}

type unknownCredentialResolver struct {
	scheme string
}

func (r *unknownCredentialResolver) Resolve(_ context.Context, entry credential.Entry) (string, error) {
	return "", fmt.Errorf("unsupported credential scheme %q for %s", r.scheme, entry.EnvVar)
}

func (r *unknownCredentialResolver) UnresolvedConnectableEntries(
	_ map[string]credential.Entry,
	_ map[string]error,
) []credential.Entry {
	return nil
}

func (r *unknownCredentialResolver) ConnectAndRetry(
	_ context.Context,
	entries []credential.Entry,
) ([]credential.Resolved, map[string]error) {
	return nil, failureMap(entries, fmt.Errorf("unsupported credential scheme %q", r.scheme))
}

func (r *unknownCredentialResolver) PrintLaunchWarnings(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) {
	for envVar := range failures {
		entry, ok := entryByEnvVar[envVar]
		if !ok {
			continue
		}
		fmt.Fprintf(os.Stderr, "⚠ %s uses unsupported credential scheme %q.\n", entry.EnvVar, entry.Scheme)
	}
}

func filterEntriesByScheme(
	entryByEnvVar map[string]credential.Entry,
	scheme string,
) map[string]credential.Entry {
	filtered := make(map[string]credential.Entry)
	for envVar, entry := range entryByEnvVar {
		entryScheme := entry.Scheme
		if entryScheme == "" {
			entryScheme = kontextScheme
		}
		if entryScheme != scheme {
			continue
		}
		filtered[envVar] = entry
	}
	return filtered
}

func filterFailuresByScheme(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
	scheme string,
) map[string]error {
	filtered := make(map[string]error)
	for envVar, err := range failures {
		entry, ok := entryByEnvVar[envVar]
		if !ok {
			continue
		}
		entryScheme := entry.Scheme
		if entryScheme == "" {
			entryScheme = kontextScheme
		}
		if entryScheme != scheme {
			continue
		}
		filtered[envVar] = err
	}
	return filtered
}

func groupEntriesByScheme(entries []credential.Entry) map[string][]credential.Entry {
	grouped := make(map[string][]credential.Entry)
	for _, entry := range entries {
		scheme := entry.Scheme
		if scheme == "" {
			scheme = kontextScheme
		}
		grouped[scheme] = append(grouped[scheme], entry)
	}
	return grouped
}
