//go:build !windows

package policyconfig

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
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
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			_ = file.Close()
			if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
				if err := waitForLockRetry(ctx); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		return func() {
			_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			_ = file.Close()
		}, nil
	}
}
