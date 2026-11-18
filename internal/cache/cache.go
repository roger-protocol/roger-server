package cache

import (
	"sync"
	"time"
)

type Entry[V any] struct {
	value     V
	expiresAt time.Time
}

type Cache[K comparable, V any] struct {
	items     map[K]Entry[V]
	stop      chan string
	mux       sync.RWMutex
	closeOnce sync.Once
}

func New[K comparable, V any](cleanupInterval time.Duration) *Cache[K, V] {
	c := &Cache[K, V]{
		items: make(map[K]Entry[V]),
		stop:  make(chan string),
	}

	go c.cleanupLoop(cleanupInterval)

	return c
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mux.RLock()
	item, exists := c.items[key]
	c.mux.RUnlock()

	if !exists || time.Now().After(item.expiresAt) {
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
	if expiresAt.Before(time.Now()) || expiresAt.Equal(time.Now()) {
		return
	}

	c.mux.Lock()
	c.items[key] = Entry[V]{
		value:     value,
		expiresAt: expiresAt,
	}
	c.mux.Unlock()
}

func (c *Cache[K, V]) Len() int {
	c.mux.RLock()
	defer c.mux.Unlock()
	return len(c.items)
}

func (c *Cache[K, V]) Has(key K) bool {
	_, ok := c.Get(key)
	return ok
}

func (c *Cache[K, V]) Delete(key K) {
	c.mux.Lock()
	delete(c.items, key)
	c.mux.Unlock()
}

func (c *Cache[K, V]) Close() {
	c.closeOnce.Do(func() {
		close(c.stop)
	})
}

func (c *Cache[K, V]) cleanupLoop(cleanupInterval time.Duration) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			c.mux.Lock()
			for k, item := range c.items {
				if now.After(item.expiresAt) {
					delete(c.items, k)
				}
			}
			c.mux.Unlock()
		case <-c.stop:
			return
		}
	}
}
