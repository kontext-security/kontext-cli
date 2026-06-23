package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
)

// Uninstall reverses Run in reverse order. Every step tolerates
// already-removed state so a partially-failed uninstall can simply be re-run.
//
// Deliberately KEPT:
//   - installation.json — it holds only the random ins_* device identity; a
//     later re-setup then reports the same endpoint to the dashboard instead
//     of spawning a phantom second device.
//   - local data (guard.db, stream state) and logs — they are the user's
//     records; locations are printed instead.
//   - the binary — brew owns it (`brew uninstall kontext`).
func Uninstall(ctx context.Context, opts Options) error {
	if goos != "darwin" {
		return errors.New("kontext setup is currently macOS-only")
	}

	organizationManaged, err := organizationManagedInstall()
	if err != nil {
		return err
	}
	if organizationManaged {
		fmt.Fprintln(opts.Stderr, "warning: an organization-managed (MDM) Kontext install remains active on this Mac and is not affected by this command")
	}

	plistPath, err := removeLaunchAgent(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "✓ Background agent removed (%s)\n", plistPath)

	if organizationManaged {
		fmt.Fprintf(opts.Stdout, "· Kept Claude Code managed hooks because an organization-managed install is active (%s)\n", managedSettingsPath)
	} else {
		removed, err := removeManagedSettings(ctx)
		if err != nil {
			return err
		}
		if removed {
			fmt.Fprintf(opts.Stdout, "✓ Claude Code managed hooks removed (%s)\n", managedSettingsPath)
		} else {
			fmt.Fprintf(opts.Stdout, "· Kept Claude Code managed hooks because ownership is unknown (%s)\n", managedSettingsPath)
		}
	}

	settingsPath, err := userSettingsPathNoCreate()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(settingsPath); errors.Is(err, os.ErrNotExist) {
		// A removal must never CREATE settings: on a machine without Claude
		// settings (or after the user deleted them) there is nothing to do.
		fmt.Fprintln(opts.Stdout, "· No Claude Code settings file — no hooks to remove")
	} else if err != nil {
		return err
	} else {
		settings, err := claudemanaged.ReadUserSettings(settingsPath)
		if err != nil {
			return err
		}
		if err := claudemanaged.BackupUserSettings(settingsPath, settingsBackupLabel); err != nil {
			return err
		}
		if err := claudemanaged.RemoveManagedHooks(settings); err != nil {
			return err
		}
		if err := claudemanaged.WriteUserSettings(settingsPath, settings); err != nil {
			return err
		}
		fmt.Fprintln(opts.Stdout, "✓ Claude Code hooks removed from ~/.claude/settings.json")
	}

	if err := deleteKeychainTokens(ctx); err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "✓ Install token removed from your keychain (%s)\n", KeychainItemName)

	if path := managedconfig.UserPath(); path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Fprintf(opts.Stdout, "✓ Managed config removed (%s)\n", path)
	}

	if identity := installation.UserPath(); identity != "" {
		if _, err := os.Lstat(identity); err == nil {
			fmt.Fprintf(opts.Stdout, "· Kept installation identity %s (re-running setup reuses the same endpoint)\n", identity)
		}
	}
	fmt.Fprintln(opts.Stdout, "· Kept local observe data and logs under ~/Library/Application Support/Kontext and ~/Library/Logs/Kontext")
	fmt.Fprintln(opts.Stdout, "· The kontext binary is managed by Homebrew (`brew uninstall kontext` to remove)")
	return nil
}

// removeManagedSettings removes the drop-in only when it is ours by content
// (mirroring setup's ownership check), so uninstall never deletes an enterprise
// or foreign managed-settings file. Returns whether the file was removed.
func removeManagedSettings(ctx context.Context) (bool, error) {
	existing, err := os.ReadFile(managedSettingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if !claudemanaged.IsManagedSettingsDropIn(existing) {
		return false, nil
	}
	if geteuid() == 0 {
		if err := os.Remove(managedSettingsPath); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		return true, nil
	}
	if err := runPrivilegedCommand(ctx, "sudo", "rm", "-f", managedSettingsPath); err != nil {
		return false, fmt.Errorf("remove Claude managed settings: %w", err)
	}
	return true, nil
}

func organizationManagedInstall() (bool, error) {
	if _, err := os.Lstat(systemConfigPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("cannot determine whether this Mac is organization-managed: %w", err)
	}
	if _, err := managedconfig.LoadFile(systemConfigPath); err != nil {
		return false, fmt.Errorf("cannot determine whether this Mac is organization-managed: %w", err)
	}
	return true, nil
}

func userSettingsPathNoCreate() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}
