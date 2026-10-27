package auth

import (
	"sync"
	"time"
)

// Limiter slows down password guessing. Failures are counted per client
// address, so one hostile device cannot lock the admin out from another;
// a global counter backstops attackers who rotate addresses. After a few
// failures every attempt must wait, and the wait doubles.
type Limiter struct {
	mu      sync.Mutex
	clients map[string]*counter
	global  counter
	now     func() time.Time
}

type counter struct {
	failures int
	until    time.Time
	seen     time.Time
}

const (
	freeAttempts       = 5
	globalFreeAttempts = 50
	firstDelay         = 2 * time.Second
	maxDelay           = 5 * time.Minute
	forget             = time.Hour
)

// NewLimiter returns an open limiter.
func NewLimiter() *Limiter { return &Limiter{clients: map[string]*counter{}, now: time.Now} }

// Wait returns how long client must wait before another attempt is
// accepted; zero means go ahead.
func (l *Limiter) Wait(client string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	d := l.global.until.Sub(now)
	if c, ok := l.clients[client]; ok {
		if cd := c.until.Sub(now); cd > d {
			d = cd
		}
	}
	if d < 0 {
		return 0
	}
	return d
}

// Fail records a failed attempt by client.
func (l *Limiter) Fail(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	c, ok := l.clients[client]
	if !ok {
		c = &counter{}
		l.clients[client] = c
	}
	c.seen = now
	c.failures++
	if c.failures >= freeAttempts {
		c.until = now.Add(delay(c.failures - freeAttempts))
	}
	l.global.failures++
	l.global.seen = now
	if l.global.failures >= globalFreeAttempts {
		l.global.until = now.Add(delay(l.global.failures - globalFreeAttempts))
	}
}

// Succeed clears the client's counter (the global one decays on its own).
func (l *Limiter) Succeed(client string) {
	l.mu.Lock()
	delete(l.clients, client)
	l.mu.Unlock()
}

func delay(n int) time.Duration {
	d := firstDelay << uint(n)
	if d > maxDelay || d <= 0 {
		return maxDelay
	}
	return d
}

// sweep forgets clients not seen for an hour, and the global counter
// once an hour has passed without a failure.
func (l *Limiter) sweep(now time.Time) {
	for k, c := range l.clients {
		if now.Sub(c.seen) > forget {
			delete(l.clients, k)
		}
	}
	if l.global.failures > 0 && now.Sub(l.global.seen) > forget {
		l.global = counter{}
	}
}
