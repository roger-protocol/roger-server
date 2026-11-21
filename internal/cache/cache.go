package cache

import (
	"sync"
	"time"

	"github.com/roger-protocol/roger-server/internal/task"
)

type Entry[V any] struct {
	value     V
	expiresAt time.Time
}

type Cache[K comparable, V any] struct {
	items map[K]Entry[V]
	mux   sync.RWMutex
	task  *task.PeriodicTask
}

func New[K comparable, V any](cleanupInterval time.Duration) *Cache[K, V] {
	c := &Cache[K, V]{
		items: make(map[K]Entry[V]),
	}

	c.task = task.NewPeriodicTask(cleanupInterval, c.doCleanup)

	return c
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mux.RLock()
	item, exists := c.items[key]
	c.mux.RUnlock()

	if !exists || time.Now().After(item.expiresAt) {
		c.Delete(key)
		var zero V
		return zero, false
	}

	return item.value, true
}

func (c *Cache[K, V]) Set(key K, value V, lifetime time.Duration) {
	if lifetime <= 0 {
		return
	}
	c.SetUntil(key, value, time.Now().Add(lifetime))
}

func (c *Cache[K, V]) SetUntil(key K, value V, expiresAt time.Time) {
	if !expiresAt.After(time.Now()) {
		return
	}

	c.mux.Lock()
	defer c.mux.Unlock()
	c.items[key] = Entry[V]{
		value:     value,
		expiresAt: expiresAt,
	}
}

func (c *Cache[K, V]) Len() int {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return len(c.items)
}

func (c *Cache[K, V]) Has(key K) bool {
	_, ok := c.Get(key)
	return ok
}

func (c *Cache[K, V]) Delete(key K) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.items, key)
}

func (c *Cache[K, V]) Close() {
	c.task.Close()
}

func (c *Cache[K, V]) doCleanup() {
	now := time.Now()
	c.mux.Lock()
	defer c.mux.Unlock()
	for k, item := range c.items {
		if !now.Before(item.expiresAt) {
			delete(c.items, k)
		}
	}
}
