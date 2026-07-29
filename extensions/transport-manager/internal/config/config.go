package config

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

type Config struct {
	Listen             string                    `json:"listen"`
	APIKey             string                    `json:"api_key"`
	SingBoxBinary      string                    `json:"sing_box_binary"`
	SingBoxProcessMode SingBoxProcessMode        `json:"sing_box_process_mode"`
	RuntimeDir         string                    `json:"runtime_dir"`
	KeenPBRAPI         string                    `json:"keen_pbr_api"`
	Transports         []transport.TransportSpec `json:"transports"`
}

type SingBoxProcessMode string

const (
	SingBoxProcessModeIsolated SingBoxProcessMode = "isolated"
	SingBoxProcessModeShared   SingBoxProcessMode = "shared"
)

type saveResult struct {
	visible bool
	durable bool
}

type saveOperations struct {
	rename        func(string, string) error
	remove        func(string) error
	syncDirectory func(string) error
}

var defaultSaveOperations = saveOperations{
	rename: os.Rename,
	remove: os.Remove,
	syncDirectory: func(path string) error {
		if runtime.GOOS == "windows" {
			return nil
		}
		directory, err := os.Open(path)
		if err != nil {
			return err
		}
		if err := directory.Sync(); err != nil {
			_ = directory.Close()
			return err
		}
		return directory.Close()
	},
}

type saveError struct {
	result saveResult
	err    error
}

func (e *saveError) Error() string {
	return e.err.Error()
}

func (e *saveError) Unwrap() error {
	return e.err
}

func configRevision(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func saveData(path string, data []byte, operations saveOperations) (saveResult, error) {
	var result saveResult
	directoryPath := filepath.Dir(path)
	if err := os.MkdirAll(directoryPath, 0700); err != nil {
		return result, err
	}
	temporary, err := os.CreateTemp(directoryPath, ".transports-*.json")
	if err != nil {
		return result, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return result, err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return result, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return result, err
	}
	if err := temporary.Close(); err != nil {
		return result, err
	}
	if err := operations.rename(temporaryPath, path); err != nil {
		if runtime.GOOS != "windows" {
			return result, err
		}
		if removeErr := operations.remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return result, err
		}
		if renameErr := operations.rename(temporaryPath, path); renameErr != nil {
			return result, renameErr
		}
	}
	result.visible = true
	if err := operations.syncDirectory(directoryPath); err != nil {
		return result, &saveError{
			result: result,
			err:    fmt.Errorf("sync transports config directory: %w", err),
		}
	}
	result.durable = true
	return result, nil
}

func save(path string, cfg Config, operations saveOperations) (saveResult, error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return saveResult{}, fmt.Errorf("encode JSON: %w", err)
	}
	return saveData(path, data, operations)
}

func Save(path string, cfg Config) error {
	_, err := save(path, cfg, defaultSaveOperations)
	return err
}

func saveAdminConfig(path string, next Config) (string, error) {
	previousData, readErr := os.ReadFile(path)
	previousExisted := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return "", fmt.Errorf("snapshot previous transports config: %w", readErr)
	}

	nextData, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode JSON: %w", err)
	}
	result, err := saveData(path, nextData, defaultSaveOperations)
	if err == nil {
		return configRevision(nextData), nil
	}
	if !result.visible {
		return "", err
	}

	var rollbackErr error
	if previousExisted {
		_, rollbackErr = saveData(path, previousData, defaultSaveOperations)
	} else {
		rollbackErr = defaultSaveOperations.remove(path)
		if rollbackErr == nil || os.IsNotExist(rollbackErr) {
			rollbackErr = defaultSaveOperations.syncDirectory(filepath.Dir(path))
		}
	}
	if rollbackErr != nil {
		return "", errors.Join(
			err,
			fmt.Errorf("restore previous transports config: %w", rollbackErr),
		)
	}
	return "", err
}

type Admin struct {
	mu                      sync.Mutex
	path                    string
	config                  Config
	revision                string
	manager                 *transport.Manager
	supervisor              *transport.Supervisor
	shared                  *transport.SharedSingBoxGroup
	rollbackSharedInventory func([]transport.TransportSpec) error
}

func (c Config) HealthEndpoint() transport.RoutingHealthEndpoint {
	return transport.RoutingHealthEndpoint{URL: c.KeenPBRAPI, APIKey: c.APIKey}
}

func NewAdmin(path string, cfg Config, manager *transport.Manager, supervisor *transport.Supervisor) *Admin {
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return NewAdminWithRevision(
		path,
		cfg,
		configRevision(data),
		manager,
		supervisor,
	)
}

func NewAdminWithRevision(
	path string,
	cfg Config,
	revision string,
	manager *transport.Manager,
	supervisor *transport.Supervisor,
) *Admin {
	return &Admin{
		path:       path,
		config:     cfg,
		revision:   revision,
		manager:    manager,
		supervisor: supervisor,
		shared: func() *transport.SharedSingBoxGroup {
			if manager == nil {
				return nil
			}
			return manager.SharedGroup()
		}(),
	}
}

type RuntimeSettings struct {
	SingBoxProcessMode        SingBoxProcessMode `json:"sing_box_process_mode"`
	RunningSingBoxProcessMode SingBoxProcessMode `json:"running_sing_box_process_mode"`
	RestartRequired           bool               `json:"restart_required"`
	RuntimeReady              bool               `json:"runtime_ready"`
}

func (a *Admin) Settings() RuntimeSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.runtimeSettingsLocked()
}

func (a *Admin) runtimeSettingsLocked() RuntimeSettings {
	running := SingBoxProcessModeIsolated
	if a.shared != nil {
		running = SingBoxProcessModeShared
	}
	autoStartTags := make([]string, 0, len(a.config.Transports))
	for _, spec := range a.config.Transports {
		if spec.AutoStart &&
			(spec.Type == "sing-box" ||
				spec.Type == "sing-box-vless-reality") {
			autoStartTags = append(autoStartTags, spec.Tag)
		}
	}
	runtimeReady := len(autoStartTags) == 0
	if !runtimeReady && a.manager != nil {
		runtimeReady = a.manager.RuntimeReady(autoStartTags)
	}
	return RuntimeSettings{
		SingBoxProcessMode:        a.config.SingBoxProcessMode,
		RunningSingBoxProcessMode: running,
		RestartRequired:           a.config.SingBoxProcessMode != running,
		RuntimeReady:              runtimeReady,
	}
}

// SetSingBoxProcessMode durably stages a lifecycle-mode switch. A manager
// restart is deliberately required: swapping every live transport object under
// concurrent API requests would create a wider failure window than restarting
// this small companion service. The next startup constructs the complete new
// runtime only after config validation succeeds.
func (a *Admin) SetSingBoxProcessMode(
	ctx context.Context,
	mode SingBoxProcessMode,
) (RuntimeSettings, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if mode != SingBoxProcessModeIsolated && mode != SingBoxProcessModeShared {
		return RuntimeSettings{}, fmt.Errorf("unsupported sing_box_process_mode %q", mode)
	}
	if mode == SingBoxProcessModeShared {
		group, err := transport.NewSharedSingBoxGroup(
			a.config.Transports,
			a.config.SingBoxBinary,
			a.config.RuntimeDir,
			a.config.HealthEndpoint(),
		)
		if err != nil {
			return RuntimeSettings{}, err
		}
		if err := group.ValidateInventory(ctx, a.config.Transports); err != nil {
			return RuntimeSettings{}, err
		}
	} else if err := transport.ValidateIsolatedSingBoxInventory(
		ctx,
		a.config.Transports,
		a.config.SingBoxBinary,
		a.config.RuntimeDir,
		a.config.HealthEndpoint(),
	); err != nil {
		return RuntimeSettings{}, err
	}
	if a.config.SingBoxProcessMode != mode {
		next := a.config
		next.SingBoxProcessMode = mode
		revision, err := saveAdminConfig(a.path, next)
		if err != nil {
			return RuntimeSettings{}, err
		}
		a.config = next
		a.revision = revision
	}
	return a.runtimeSettingsLocked(), nil
}

func (a *Admin) Revision() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.revision
}

func (a *Admin) Specs() []transport.TransportSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.redactedSpecsLocked()
}

// State returns one lock-consistent view of the redacted configuration and
// its durable revision. It prevents a client from pairing transports from one
// generation with the revision of another generation.
func (a *Admin) State() ([]transport.TransportSpec, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.redactedSpecsLocked(), a.revision
}

func (a *Admin) redactedSpecsLocked() []transport.TransportSpec {
	result := make([]transport.TransportSpec, len(a.config.Transports))
	copy(result, a.config.Transports)
	for i := range result {
		result[i].BootstrapDNS = append([]string(nil), result[i].BootstrapDNS...)
		result[i].Link = ""
		result[i].OutboundJSON = ""
		if result[i].VLESS != nil {
			copyVLESS := *result[i].VLESS
			copyVLESS.UUID = ""
			result[i].VLESS = &copyVLESS
		}
	}
	return result
}

// ExportSpecs returns a deep copy including connection credentials. The
// regular Specs method stays redacted because it feeds everyday UI reads.
func (a *Admin) ExportSpecs() []transport.TransportSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]transport.TransportSpec, len(a.config.Transports))
	for i, spec := range a.config.Transports {
		result[i] = spec
		result[i].BootstrapDNS = append([]string(nil), spec.BootstrapDNS...)
		if spec.VLESS != nil {
			copyVLESS := *spec.VLESS
			result[i].VLESS = &copyVLESS
		}
	}
	return result
}

func (a *Admin) Create(ctx context.Context, spec transport.TransportSpec) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.createLocked(ctx, spec)
}

// CreateIfRevision creates a transport only while expectedRevision still
// identifies the durable configuration loaded by this Admin. Revision
// comparison and mutation share the same lock, so two writers using the same
// revision cannot both commit.
func (a *Admin) CreateIfRevision(
	ctx context.Context,
	spec transport.TransportSpec,
	expectedRevision string,
) (string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if expectedRevision != a.revision {
		return a.revision, false, nil
	}
	err := a.createLocked(ctx, spec)
	return a.revision, true, err
}

// ValidateCreateAtRevision performs the complete create validation without
// changing the durable configuration, manager, or supervisor.
func (a *Admin) ValidateCreateAtRevision(
	spec transport.TransportSpec,
	expectedRevision string,
) (string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if expectedRevision != "" && expectedRevision != a.revision {
		return a.revision, false, nil
	}
	nextSpecs, _, err := a.prepareCreateLocked(spec)
	if err == nil && a.shared != nil && isSharedSpec(spec) {
		err = a.validateSharedInventoryLocked(nextSpecs)
	}
	return a.revision, true, err
}

func (a *Admin) prepareCreateLocked(
	spec transport.TransportSpec,
) ([]transport.TransportSpec, transport.Transport, error) {
	if a.index(spec.Tag) >= 0 {
		return nil, nil, fmt.Errorf("transport %q already exists", spec.Tag)
	}
	nextSpecs := append(append([]transport.TransportSpec{}, a.config.Transports...), spec)
	if err := transport.ValidateUniqueTunAddresses(nextSpecs); err != nil {
		return nil, nil, err
	}
	if a.shared != nil && (spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality") {
		if _, err := transport.NewSingBox(
			spec,
			a.config.SingBoxBinary,
			a.config.RuntimeDir,
			a.config.HealthEndpoint(),
		); err != nil {
			return nil, nil, err
		}
		return nextSpecs, nil, nil
	}
	managed, err := transport.NewFromSpec(spec, a.config.SingBoxBinary, a.config.RuntimeDir, a.config.HealthEndpoint())
	if err != nil {
		return nil, nil, err
	}
	return nextSpecs, managed, nil
}

func (a *Admin) createLocked(ctx context.Context, spec transport.TransportSpec) error {
	nextSpecs, managed, err := a.prepareCreateLocked(spec)
	if err != nil {
		return err
	}
	if a.shared != nil && (spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality") {
		return a.createSharedLocked(ctx, spec, nextSpecs)
	}
	if err := a.manager.Add(managed); err != nil {
		return err
	}
	a.supervisor.Register(spec)
	next := a.config
	next.Transports = nextSpecs
	revision, err := saveAdminConfig(a.path, next)
	if err != nil {
		a.supervisor.Forget(spec.Tag)
		_ = a.manager.Remove(ctx, spec.Tag)
		return err
	}
	a.config = next
	a.revision = revision
	return nil
}

func (a *Admin) createSharedLocked(
	ctx context.Context,
	spec transport.TransportSpec,
	nextSpecs []transport.TransportSpec,
) error {
	previous := append([]transport.TransportSpec(nil), a.config.Transports...)
	if err := a.shared.ApplyInventory(ctx, nextSpecs); err != nil {
		return err
	}
	managed, err := a.shared.Member(spec.Tag)
	if err != nil {
		rollbackErr := a.rollbackSharedInventoryLocked(previous)
		return errors.Join(err, rollbackErr)
	}
	if err := a.manager.Add(managed); err != nil {
		rollbackErr := a.rollbackSharedInventoryLocked(previous)
		return errors.Join(err, rollbackErr)
	}
	a.supervisor.Register(spec)
	next := a.config
	next.Transports = nextSpecs
	revision, err := saveAdminConfig(a.path, next)
	if err != nil {
		a.supervisor.Forget(spec.Tag)
		forgetErr := a.manager.Forget(spec.Tag)
		rollbackErr := a.rollbackSharedInventoryLocked(previous)
		return errors.Join(err, forgetErr, rollbackErr)
	}
	a.config = next
	a.revision = revision
	return nil
}

func (a *Admin) Update(ctx context.Context, tag string, spec transport.TransportSpec) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.updateLocked(ctx, tag, spec)
}

// UpdateIfRevision updates a transport only while expectedRevision still
// identifies the durable configuration loaded by this Admin.
func (a *Admin) UpdateIfRevision(
	ctx context.Context,
	tag string,
	spec transport.TransportSpec,
	expectedRevision string,
) (string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if expectedRevision != a.revision {
		return a.revision, false, nil
	}
	err := a.updateLocked(ctx, tag, spec)
	return a.revision, true, err
}

// ValidateUpdateAtRevision performs the complete update validation and secret
// preservation logic without changing durable or runtime state.
func (a *Admin) ValidateUpdateAtRevision(
	tag string,
	spec transport.TransportSpec,
	expectedRevision string,
) (string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if expectedRevision != "" && expectedRevision != a.revision {
		return a.revision, false, nil
	}
	_, prepared, nextSpecs, _, err := a.prepareUpdateLocked(tag, spec)
	if err == nil && a.shared != nil && isSharedSpec(prepared) {
		err = a.validateSharedInventoryLocked(nextSpecs)
	}
	return a.revision, true, err
}

func (a *Admin) prepareUpdateLocked(
	tag string,
	spec transport.TransportSpec,
) (transport.TransportSpec, transport.TransportSpec, []transport.TransportSpec, transport.Transport, error) {
	index := a.index(tag)
	if index < 0 {
		return transport.TransportSpec{}, transport.TransportSpec{}, nil, nil,
			fmt.Errorf("transport %q not found", tag)
	}
	if spec.Tag != tag {
		return transport.TransportSpec{}, transport.TransportSpec{}, nil, nil,
			fmt.Errorf("transport tag cannot be changed")
	}
	oldSpec := a.config.Transports[index]
	if a.shared != nil && spec.Type != oldSpec.Type {
		return transport.TransportSpec{}, transport.TransportSpec{}, nil, nil,
			fmt.Errorf("transport type cannot be changed")
	}
	if (spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality") &&
		spec.Link == "" && spec.OutboundJSON == "" && spec.VLESS == nil {
		spec.Link = oldSpec.Link
		spec.OutboundJSON = oldSpec.OutboundJSON
		spec.VLESS = oldSpec.VLESS
	}
	if spec.VLESS != nil && spec.VLESS.UUID == "" && oldSpec.VLESS != nil {
		spec.VLESS.UUID = oldSpec.VLESS.UUID
	}
	nextSpecs := append([]transport.TransportSpec{}, a.config.Transports...)
	nextSpecs[index] = spec
	if err := transport.ValidateUniqueTunAddresses(nextSpecs); err != nil {
		return transport.TransportSpec{}, transport.TransportSpec{}, nil, nil, err
	}
	if a.shared != nil && (spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality") {
		if _, err := transport.NewSingBox(
			spec,
			a.config.SingBoxBinary,
			a.config.RuntimeDir,
			a.config.HealthEndpoint(),
		); err != nil {
			return transport.TransportSpec{}, transport.TransportSpec{}, nil, nil, err
		}
		return oldSpec, spec, nextSpecs, nil, nil
	}
	managed, err := transport.NewFromSpec(spec, a.config.SingBoxBinary, a.config.RuntimeDir, a.config.HealthEndpoint())
	if err != nil {
		return transport.TransportSpec{}, transport.TransportSpec{}, nil, nil, err
	}
	return oldSpec, spec, nextSpecs, managed, nil
}

func (a *Admin) validateSharedInventoryLocked(specs []transport.TransportSpec) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return a.shared.ValidateInventory(ctx, specs)
}

func (a *Admin) rollbackSharedInventoryLocked(specs []transport.TransportSpec) error {
	if a.rollbackSharedInventory != nil {
		return a.rollbackSharedInventory(specs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return a.shared.ApplyInventory(ctx, specs)
}

func (a *Admin) updateLocked(ctx context.Context, tag string, spec transport.TransportSpec) error {
	oldSpec, spec, nextSpecs, managed, err := a.prepareUpdateLocked(tag, spec)
	if err != nil {
		return err
	}
	if a.shared != nil && isSharedSpec(oldSpec, spec) {
		return a.updateSharedLocked(ctx, oldSpec, spec, nextSpecs)
	}
	if transport.RuntimeEquivalent(oldSpec, spec) {
		next := a.config
		next.Transports = nextSpecs
		revision, err := saveAdminConfig(a.path, next)
		if err != nil {
			return err
		}
		a.config = next
		a.revision = revision
		return nil
	}
	a.supervisor.Forget(tag)
	if err := a.manager.Remove(ctx, tag); err != nil {
		a.supervisor.Register(oldSpec)
		return err
	}
	if err := a.manager.Add(managed); err != nil {
		oldManaged, _ := transport.NewFromSpec(oldSpec, a.config.SingBoxBinary, a.config.RuntimeDir, a.config.HealthEndpoint())
		_ = a.manager.Add(oldManaged)
		a.supervisor.Register(oldSpec)
		return err
	}
	a.supervisor.Register(spec)
	next := a.config
	next.Transports = nextSpecs
	revision, err := saveAdminConfig(a.path, next)
	if err != nil {
		a.supervisor.Forget(tag)
		_ = a.manager.Remove(ctx, tag)
		oldManaged, _ := transport.NewFromSpec(oldSpec, a.config.SingBoxBinary, a.config.RuntimeDir, a.config.HealthEndpoint())
		_ = a.manager.Add(oldManaged)
		a.supervisor.Register(oldSpec)
		return err
	}
	a.config = next
	a.revision = revision
	return nil
}

func isSharedSpec(specs ...transport.TransportSpec) bool {
	for _, spec := range specs {
		if spec.Type == "sing-box" || spec.Type == "sing-box-vless-reality" {
			return true
		}
	}
	return false
}

func (a *Admin) updateSharedLocked(
	ctx context.Context,
	oldSpec transport.TransportSpec,
	spec transport.TransportSpec,
	nextSpecs []transport.TransportSpec,
) error {
	previous := append([]transport.TransportSpec(nil), a.config.Transports...)
	if err := a.shared.ApplyInventory(ctx, nextSpecs); err != nil {
		return err
	}
	a.supervisor.Register(spec)
	next := a.config
	next.Transports = nextSpecs
	revision, err := saveAdminConfig(a.path, next)
	if err != nil {
		rollbackErr := a.rollbackSharedInventoryLocked(previous)
		a.supervisor.Register(oldSpec)
		return errors.Join(err, rollbackErr)
	}
	a.config = next
	a.revision = revision
	return nil
}

func (a *Admin) Delete(ctx context.Context, tag string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	index := a.index(tag)
	if index < 0 {
		return fmt.Errorf("transport %q not found", tag)
	}
	oldSpec := a.config.Transports[index]
	if a.shared != nil && isSharedSpec(oldSpec) {
		return a.deleteSharedLocked(ctx, index, oldSpec)
	}
	a.supervisor.Forget(tag)
	if err := a.manager.Remove(ctx, tag); err != nil {
		a.supervisor.Register(oldSpec)
		return err
	}
	next := a.config
	next.Transports = append([]transport.TransportSpec{}, a.config.Transports[:index]...)
	next.Transports = append(next.Transports, a.config.Transports[index+1:]...)
	revision, err := saveAdminConfig(a.path, next)
	if err != nil {
		oldManaged, _ := transport.NewFromSpec(oldSpec, a.config.SingBoxBinary, a.config.RuntimeDir, a.config.HealthEndpoint())
		_ = a.manager.Add(oldManaged)
		a.supervisor.Register(oldSpec)
		return err
	}
	a.config = next
	a.revision = revision
	return nil
}

func (a *Admin) deleteSharedLocked(
	ctx context.Context,
	index int,
	oldSpec transport.TransportSpec,
) error {
	previous := append([]transport.TransportSpec(nil), a.config.Transports...)
	nextSpecs := append([]transport.TransportSpec{}, previous[:index]...)
	nextSpecs = append(nextSpecs, previous[index+1:]...)
	if err := a.shared.ApplyInventory(ctx, nextSpecs); err != nil {
		return err
	}
	a.supervisor.Forget(oldSpec.Tag)
	if err := a.manager.Forget(oldSpec.Tag); err != nil {
		rollbackErr := a.rollbackSharedInventoryLocked(previous)
		if managed, memberErr := a.shared.Member(oldSpec.Tag); memberErr == nil {
			var addErr error
			if _, exists := a.manager.Get(oldSpec.Tag); !exists {
				addErr = a.manager.Add(managed)
			}
			if addErr == nil {
				a.supervisor.Register(oldSpec)
			}
			rollbackErr = errors.Join(rollbackErr, addErr)
		} else {
			rollbackErr = errors.Join(rollbackErr, memberErr)
		}
		return errors.Join(err, rollbackErr)
	}
	next := a.config
	next.Transports = nextSpecs
	revision, err := saveAdminConfig(a.path, next)
	if err != nil {
		rollbackErr := a.rollbackSharedInventoryLocked(previous)
		if managed, memberErr := a.shared.Member(oldSpec.Tag); memberErr == nil {
			addErr := a.manager.Add(managed)
			if addErr == nil {
				a.supervisor.Register(oldSpec)
			}
			rollbackErr = errors.Join(rollbackErr, addErr)
		} else {
			rollbackErr = errors.Join(rollbackErr, memberErr)
		}
		return errors.Join(err, rollbackErr)
	}
	a.config = next
	a.revision = revision
	return nil
}

func (a *Admin) index(tag string) int {
	for i := range a.config.Transports {
		if a.config.Transports[i].Tag == tag {
			return i
		}
	}
	return -1
}

func Load(path string) (Config, error) {
	cfg, _, err := LoadWithRevision(path)
	return cfg, err
}

func LoadWithRevision(path string) (Config, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, "", err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, "", fmt.Errorf("decode JSON: %w", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:12122"
	}
	if cfg.SingBoxBinary == "" {
		cfg.SingBoxBinary = "/opt/bin/sing-box"
	}
	cfg.SingBoxBinary = availableSingBoxBinary(cfg.SingBoxBinary)
	if cfg.SingBoxProcessMode == "" {
		cfg.SingBoxProcessMode = SingBoxProcessModeIsolated
	}
	switch cfg.SingBoxProcessMode {
	case SingBoxProcessModeIsolated:
	case SingBoxProcessModeShared:
	default:
		return Config{}, "", fmt.Errorf("unsupported sing_box_process_mode %q", cfg.SingBoxProcessMode)
	}
	if cfg.RuntimeDir == "" {
		cfg.RuntimeDir = "/opt/var/run/keen-pbr/transports"
	}
	if cfg.KeenPBRAPI == "" {
		cfg.KeenPBRAPI = "http://127.0.0.1:12121/api/runtime/outbounds"
	}
	if cfg.APIKey == "" {
		return Config{}, "", fmt.Errorf("api_key must not be empty")
	}
	if err := transport.ValidateUniqueTunAddresses(cfg.Transports); err != nil {
		return Config{}, "", err
	}
	return cfg, configRevision(data), nil
}

func availableSingBoxBinary(configured string) string {
	candidates := []string{
		configured,
		"/opt/bin/sing-box",
		"/opt/sbin/sing-box",
		"/opt/usr/bin/sing-box",
		"/opt/etc/awg-manager/singbox/sing-box",
	}
	seen := make(map[string]bool)
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0111 != 0 {
			return candidate
		}
	}
	return configured
}
