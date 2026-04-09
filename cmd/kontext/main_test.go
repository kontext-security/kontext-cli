package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestLogoutCmdSuccess(t *testing.T) {
	cmd := newLogoutCmd(func() error { return nil })

	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}

	if got, want := stderr.String(), "Logged out successfully.\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestLogoutCmdAlreadyLoggedOut(t *testing.T) {
	cmd := newLogoutCmd(func() error { return keyring.ErrNotFound })

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() error = nil, want non-nil")
	}
	if got, want := err.Error(), "already logged out"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestLogoutCmdWrapsUnexpectedErrors(t *testing.T) {
	boom := errors.New("boom")
	cmd := newLogoutCmd(func() error { return boom })

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() error = nil, want non-nil")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("errors.Is(err, boom) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "logout failed: boom") {
		t.Fatalf("error = %q, want wrapped logout failure", err.Error())
	}
}
