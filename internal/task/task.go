package task

import (
	"sync"
	"time"
)

type PeriodicTask struct {
	stop      chan struct{}
	closeOnce sync.Once
}

func NewPeriodicTask(interval time.Duration, callback func()) *PeriodicTask {
	stop := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				callback()
			case <-stop:
				return
			}
		}
	}()

	return &PeriodicTask{
		stop: stop,
	}
}

func (t *PeriodicTask) Close() {
	t.closeOnce.Do(func() {
		close(t.stop)
	})
}
