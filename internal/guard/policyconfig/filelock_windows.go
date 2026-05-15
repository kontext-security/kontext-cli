//go:build windows

package policyconfig

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockFileAt(ctx context.Context, path string) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, fileMode)
		if err != nil {
			return nil, err
		}
		var overlapped windows.Overlapped
		err = windows.LockFileEx(
			windows.Handle(file.Fd()),
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			&overlapped,
		)
		if err != nil {
			_ = file.Close()
			if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
				if err := waitForLockRetry(ctx); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		return func() {
			_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
			_ = file.Close()
		}, nil
	}
}
