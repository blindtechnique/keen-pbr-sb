package transport

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type State string

const (
	StateDown     State = "down"
	StateStarting State = "starting"
	StateUp       State = "up"
	StateDegraded State = "degraded"
)

type Status struct {
	Tag         string     `json:"tag"`
	Type        string     `json:"type"`
	Interface   string     `json:"interface"`
	Server      string     `json:"server,omitempty"`
	State       State      `json:"state"`
	PID         int        `json:"pid,omitempty"`
	Error       string     `json:"error,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DesiredUp   bool       `json:"desired_up"`
	RetryCount  int        `json:"retry_count,omitempty"`
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`
}

type Transport interface {
	Tag() string
	Up(context.Context) error
	Down(context.Context) error
	Status(context.Context) Status
}

type Manager struct {
	mu         sync.RWMutex
	transports map[string]Transport
}

func NewManager() *Manager { return &Manager{transports: make(map[string]Transport)} }

func (m *Manager) Add(t Transport) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t == nil {
		return errors.New("transport must not be nil")
	}
	if t.Tag() == "" {
		return errors.New("transport tag must not be empty")
	}
	if _, exists := m.transports[t.Tag()]; exists {
		return fmt.Errorf("transport %q already exists", t.Tag())
	}
	m.transports[t.Tag()] = t
	return nil
}

func (m *Manager) get(tag string) (Transport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.transports[tag]
	if !ok {
		return nil, fmt.Errorf("transport %q not found", tag)
	}
	return t, nil
}

// Get returns the live transport object so callers can reach behaviour that is
// not part of the minimal Transport interface.
func (m *Manager) Get(tag string) (Transport, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.transports[tag]
	return t, ok
}

func (m *Manager) Statuses(ctx context.Context) []Status {
	m.mu.RLock()
	items := make([]Transport, 0, len(m.transports))
	for _, t := range m.transports {
		items = append(items, t)
	}
	m.mu.RUnlock()
	result := make([]Status, 0, len(items))
	for _, t := range items {
		result = append(result, t.Status(ctx))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Tag < result[j].Tag })
	return result
}

func (m *Manager) Status(ctx context.Context, tag string) (Status, error) {
	t, err := m.get(tag)
	if err != nil {
		return Status{}, err
	}
	return t.Status(ctx), nil
}

func (m *Manager) Start(ctx context.Context, tags []string) error {
	var wg sync.WaitGroup
	errorsChannel := make(chan error, len(tags))
	for _, tag := range tags {
		tag := tag
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Up(ctx, tag); err != nil {
				errorsChannel <- fmt.Errorf("%s: %w", tag, err)
			}
		}()
	}
	wg.Wait()
	close(errorsChannel)
	var errs []error
	for err := range errorsChannel {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) Up(ctx context.Context, tag string) error {
	t, err := m.get(tag)
	if err != nil {
		return err
	}
	return t.Up(ctx)
}

func (m *Manager) Down(ctx context.Context, tag string) error {
	t, err := m.get(tag)
	if err != nil {
		return err
	}
	return t.Down(ctx)
}

func (m *Manager) Remove(ctx context.Context, tag string) error {
	t, err := m.get(tag)
	if err != nil {
		return err
	}
	if err := t.Down(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, exists := m.transports[tag]; exists && current == t {
		delete(m.transports, tag)
	}
	return nil
}

func (m *Manager) Close(ctx context.Context) error {
	m.mu.RLock()
	items := make([]Transport, 0, len(m.transports))
	for _, t := range m.transports {
		items = append(items, t)
	}
	m.mu.RUnlock()
	var errs []error
	for _, t := range items {
		if err := t.Down(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Tag(), err))
		}
	}
	return errors.Join(errs...)
}
