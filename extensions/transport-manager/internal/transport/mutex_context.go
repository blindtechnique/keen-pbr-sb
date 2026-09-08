package transport

import (
	"context"
	"sync"
	"time"
)

// lockMutexContext bounds waits on an existing lifecycle mutex. The caller
// owns the lock only on success and remains responsible for unlocking it.
func lockMutexContext(ctx context.Context, mutex *sync.Mutex) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tryLock := func() (bool, error) {
		if !mutex.TryLock() {
			return false, nil
		}
		if err := ctx.Err(); err != nil {
			mutex.Unlock()
			return false, err
		}
		return true, nil
	}
	if locked, err := tryLock(); locked || err != nil {
		return err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if locked, err := tryLock(); locked || err != nil {
				return err
			}
		}
	}
}
