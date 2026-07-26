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

	"github.com/infaprim/mykeenpbr/internal/transport"
)

type Config struct {
	Listen        string                    `json:"listen"`
	APIKey        string                    `json:"api_key"`
	SingBoxBinary string                    `json:"sing_box_binary"`
	RuntimeDir    string                    `json:"runtime_dir"`
	KeenPBRAPI    string                    `json:"keen_pbr_api"`
	Transports    []transport.TransportSpec `json:"transports"`
}

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
	mu         sync.Mutex
	path       string
	config     Config
	revision   string
	manager    *transport.Manager
	supervisor *transport.Supervisor
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
	}
}

func (a *Admin) Revision() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.revision
}

func (a *Admin) Specs() []transport.TransportSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]transport.TransportSpec, len(a.config.Transports))
	copy(result, a.config.Transports)
	for i := range result {
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
	nextSpecs := append(append([]transport.TransportSpec{}, a.config.Transports...), spec)
	if err := transport.ValidateUniqueTunAddresses(nextSpecs); err != nil {
		return err
	}
	managed, err := transport.NewFromSpec(spec, a.config.SingBoxBinary, a.config.RuntimeDir, a.config.HealthEndpoint())
	if err != nil {
		return err
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

func (a *Admin) Update(ctx context.Context, tag string, spec transport.TransportSpec) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	index := a.index(tag)
	if index < 0 {
		return fmt.Errorf("transport %q not found", tag)
	}
	if spec.Tag != tag {
		return fmt.Errorf("transport tag cannot be changed")
	}
	oldSpec := a.config.Transports[index]
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
		return err
	}
	managed, err := transport.NewFromSpec(spec, a.config.SingBoxBinary, a.config.RuntimeDir, a.config.HealthEndpoint())
	if err != nil {
		return err
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

func (a *Admin) Delete(ctx context.Context, tag string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	index := a.index(tag)
	if index < 0 {
		return fmt.Errorf("transport %q not found", tag)
	}
	oldSpec := a.config.Transports[index]
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
