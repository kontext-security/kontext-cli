package setup

import (
	"context"
	"fmt"
	"strings"
)

// writeKeychainToken stores the raw token as a login-keychain generic
// password, symmetric with the daemon's read path
// (`security find-generic-password -s <service> -w`). The write happens in
// two phases:
//
//  1. delete every existing item with our service name — find-generic-password
//     matches by service only, so a stale item (different account, previous
//     org) could otherwise win the read;
//  2. add the new item, feeding the command through `security -i` STDIN so
//     the token never appears in the process argument list.
//
// go-keyring is deliberately NOT used: its darwin Set() stores
// "go-keyring-base64:<encoded>" which the daemon's raw read would return
// verbatim.
func writeKeychainToken(ctx context.Context, token string) error {
	if err := deleteKeychainTokens(ctx); err != nil {
		return err
	}
	command := fmt.Sprintf(
		"add-generic-password -U -s %s -a %s -w %s\n",
		KeychainItemName, keychainAccount, securityQuote(token),
	)
	if out, err := execCommand(ctx, command, "security", "-i"); err != nil {
		return fmt.Errorf("store install token in keychain: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

// maxKeychainDeletions is a runaway guard, not an expected count — the loop
// normally ends on the first "not found" (0 or 1 items).
const maxKeychainDeletions = 32

// deleteKeychainTokens removes ALL items with our service name (delete only
// removes one match per invocation). Only the explicit "not found" outcome
// ends the loop as success — a locked keychain or denied access must surface,
// otherwise uninstall would report the token removed while it still exists
// (and a rotation could proceed on top of a stale item).
func deleteKeychainTokens(ctx context.Context) error {
	for attempt := 0; attempt < maxKeychainDeletions; attempt++ {
		out, err := execCommand(ctx, "", "security", "delete-generic-password", "-s", KeychainItemName)
		if err == nil {
			continue // one item deleted; loop for more
		}
		if isSecurityNotFound(out) {
			return nil // no (more) matching items
		}
		return fmt.Errorf("delete keychain item %s: %w (%s)", KeychainItemName, err, strings.TrimSpace(out))
	}
	return fmt.Errorf("more than %d keychain items named %s; clean them up in Keychain Access and retry", maxKeychainDeletions, KeychainItemName)
}

func isSecurityNotFound(output string) bool {
	normalized := strings.ToLower(output)
	return strings.Contains(normalized, "could not be found") ||
		strings.Contains(normalized, "not found") ||
		strings.Contains(normalized, "specified item could not be found")
}

// securityQuote wraps a value for the `security -i` command parser, which
// accepts double-quoted strings with backslash escapes.
func securityQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
