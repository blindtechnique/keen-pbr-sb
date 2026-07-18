package config

import (
	"context"
	"encoding/json"
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
	Transports    []transport.TransportSpec `json:"transports"`
}

func Save(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".transports-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return err
		}
		if renameErr := os.Rename(temporaryPath, path); renameErr != nil {
			return renameErr
		}
	}
	return nil
}

type Admin struct {
	mu         sync.Mutex
	path       string
	config     Config
	manager    *transport.Manager
	supervisor *transport.Supervisor
}

func NewAdmin(path string, cfg Config, manager *transport.Manager, supervisor *transport.Supervisor) *Admin {
	return &Admin{path: path, config: cfg, manager: manager, supervisor: supervisor}
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

func (a *Admin) Create(ctx context.Context, spec transport.TransportSpec) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	managed, err := transport.NewFromSpec(spec, a.config.SingBoxBinary, a.config.RuntimeDir)
	if err != nil {
		return err
	}
	if err := a.manager.Add(managed); err != nil {
		return err
	}
	a.supervisor.Register(spec)
	next := a.config
	next.Transports = append(append([]transport.TransportSpec{}, a.config.Transports...), spec)
	if err := Save(a.path, next); err != nil {
		a.supervisor.Forget(spec.Tag)
		_ = a.manager.Remove(ctx, spec.Tag)
		return err
	}
	a.config = next
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
	managed, err := transport.NewFromSpec(spec, a.config.SingBoxBinary, a.config.RuntimeDir)
	if err != nil {
		return err
	}
	a.supervisor.Forget(tag)
	if err := a.manager.Remove(ctx, tag); err != nil {
		a.supervisor.Register(oldSpec)
		return err
	}
	if err := a.manager.Add(managed); err != nil {
		oldManaged, _ := transport.NewFromSpec(oldSpec, a.config.SingBoxBinary, a.config.RuntimeDir)
		_ = a.manager.Add(oldManaged)
		a.supervisor.Register(oldSpec)
		return err
	}
	a.supervisor.Register(spec)
	next := a.config
	next.Transports = append([]transport.TransportSpec{}, a.config.Transports...)
	next.Transports[index] = spec
	if err := Save(a.path, next); err != nil {
		a.supervisor.Forget(tag)
		_ = a.manager.Remove(ctx, tag)
		oldManaged, _ := transport.NewFromSpec(oldSpec, a.config.SingBoxBinary, a.config.RuntimeDir)
		_ = a.manager.Add(oldManaged)
		a.supervisor.Register(oldSpec)
		return err
	}
	a.config = next
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
	if err := Save(a.path, next); err != nil {
		oldManaged, _ := transport.NewFromSpec(oldSpec, a.config.SingBoxBinary, a.config.RuntimeDir)
		_ = a.manager.Add(oldManaged)
		a.supervisor.Register(oldSpec)
		return err
	}
	a.config = next
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
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode JSON: %w", err)
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
	if cfg.APIKey == "" {
		return Config{}, fmt.Errorf("api_key must not be empty")
	}
	return cfg, nil
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
