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

type WireTransport string

const (
	WireTransportTCP     WireTransport = "tcp"
	WireTransportUDP     WireTransport = "udp"
	WireTransportTCPUDP  WireTransport = "tcp_udp"
	WireTransportUnknown WireTransport = "unknown"
)

type TransportFraming string

const (
	TransportFramingRaw         TransportFraming = "raw"
	TransportFramingWebSocket   TransportFraming = "websocket"
	TransportFramingHTTP        TransportFraming = "http"
	TransportFramingHTTP2       TransportFraming = "http2"
	TransportFramingGRPC        TransportFraming = "grpc"
	TransportFramingHTTPUpgrade TransportFraming = "http_upgrade"
	TransportFramingQUIC        TransportFraming = "quic"
	TransportFramingWireGuard   TransportFraming = "wireguard"
	TransportFramingUnknown     TransportFraming = "unknown"
)

type TransportPathConfidence string

const (
	TransportPathDeclared  TransportPathConfidence = "declared"
	TransportPathDerived   TransportPathConfidence = "derived"
	TransportPathAmbiguous TransportPathConfidence = "ambiguous"
	TransportPathUnknown   TransportPathConfidence = "unknown"
)

// TransportPath deliberately separates the IP carrier from application
// framing. A QUIC-based protocol is UDP on the wire even when it carries TCP
// streams, while WebSocket is framing over TCP. Keeping those dimensions
// separate prevents the UI from labelling Hysteria2/TUIC as TCP.
type TransportPath struct {
	WireTransport   WireTransport           `json:"wire_transport"`
	Framing         TransportFraming        `json:"framing"`
	PayloadNetworks []string                `json:"payload_networks,omitempty"`
	Confidence      TransportPathConfidence `json:"confidence"`
}

func UnknownTransportPath() TransportPath {
	return TransportPath{
		WireTransport: WireTransportUnknown,
		Framing:       TransportFramingUnknown,
		Confidence:    TransportPathUnknown,
	}
}

type Status struct {
	Tag         string `json:"tag"`
	DisplayName string `json:"display_name,omitempty"`
	Type        string `json:"type"`
	Interface   string `json:"interface"`
	Server      string `json:"server,omitempty"`
	// Не секреты: порт, вид защиты, SNI и вид транспорта видны любому
	// наблюдателю на линии, зато без них по карточке невозможно понять,
	// куда и как именно уходит соединение.
	ServerPort int `json:"server_port,omitempty"`
	// Протокол самого туннеля - vless, trojan, hysteria2 и прочие. Тип
	// транспорта ("sing-box") говорит, кто его запускает, а не что внутри.
	Protocol string        `json:"protocol,omitempty"`
	Security string        `json:"security,omitempty"`
	SNI      string        `json:"sni,omitempty"`
	Path     TransportPath `json:"path"`
	// Network is retained for one compatibility release. New clients must use
	// Path because this legacy field historically mixed TCP/UDP and framing.
	Network     string     `json:"network,omitempty"`
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

type transportRestarter interface {
	Restart(context.Context) error
}

type groupedTransport interface {
	SupervisorGroup() supervisorGroup
}

// localRuntimeReadiness deliberately excludes external routing and server
// health. A lifecycle transaction only needs proof that the local process,
// TUN device and owned runtime rules were installed.
type localRuntimeReadiness interface {
	LocalRuntimeReady() bool
}

type Manager struct {
	mu         sync.RWMutex
	transports map[string]Transport
	shared     *SharedSingBoxGroup
}

func NewManager() *Manager { return &Manager{transports: make(map[string]Transport)} }

func (m *Manager) SetSharedGroup(group *SharedSingBoxGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shared != nil && m.shared != group {
		return errors.New("shared sing-box group is already registered")
	}
	m.shared = group
	return nil
}

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

// RuntimeReady verifies only the requested live transport objects. An empty
// set is ready by definition for installations without autostart proxies.
func (m *Manager) RuntimeReady(tags []string) bool {
	if len(tags) == 0 {
		return true
	}
	m.mu.RLock()
	items := make([]Transport, 0, len(tags))
	for _, tag := range tags {
		item, exists := m.transports[tag]
		if !exists {
			m.mu.RUnlock()
			return false
		}
		items = append(items, item)
	}
	m.mu.RUnlock()
	for _, item := range items {
		ready, ok := item.(localRuntimeReadiness)
		if !ok || !ready.LocalRuntimeReady() {
			return false
		}
	}
	return true
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

// Restart gives transports with a coordinated lifecycle one atomic restart
// operation. Falling back to Down+Up keeps the isolated and native behaviour
// unchanged, while shared sing-box avoids two complete group rebuilds.
func (m *Manager) Restart(ctx context.Context, tag string) error {
	t, err := m.get(tag)
	if err != nil {
		return err
	}
	if restarter, ok := t.(transportRestarter); ok {
		return restarter.Restart(ctx)
	}
	if err := t.Down(ctx); err != nil {
		return err
	}
	return t.Up(ctx)
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

// Forget removes only the logical registry entry. It is used after a shared
// group has already applied a whole-inventory deletion transaction.
func (m *Manager) Forget(tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.transports[tag]; !exists {
		return fmt.Errorf("transport %q not found", tag)
	}
	delete(m.transports, tag)
	return nil
}

func (m *Manager) SharedGroup() *SharedSingBoxGroup {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shared != nil {
		return m.shared
	}
	for _, item := range m.transports {
		member, ok := item.(*SharedSingBoxMember)
		if ok {
			return member.group
		}
	}
	return nil
}

func (m *Manager) Close(ctx context.Context) error {
	m.mu.RLock()
	items := make([]Transport, 0, len(m.transports))
	for _, t := range m.transports {
		items = append(items, t)
	}
	shared := m.shared
	m.mu.RUnlock()
	var errs []error
	closedGroups := make(map[supervisorGroup]bool)
	for _, t := range items {
		if grouped, ok := t.(groupedTransport); ok {
			group := grouped.SupervisorGroup()
			if closedGroups[group] {
				continue
			}
			closedGroups[group] = true
			if closer, ok := group.(interface{ Close(context.Context) error }); ok {
				if err := closer.Close(ctx); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", group.Key(), err))
				}
				continue
			}
		}
		if err := t.Down(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Tag(), err))
		}
	}
	if shared != nil && !closedGroups[shared] {
		if err := shared.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", shared.Key(), err))
		}
	}
	return errors.Join(errs...)
}
