package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Upgrade state is a temporary package-transaction handoff, not a replacement
// for auto_start. Ordinary starts never read it.
type upgradeState struct {
	ConfigRevision string          `json:"config_revision"`
	Desired        map[string]bool `json:"desired_up"`
}

func CaptureUpgradeState(ctx context.Context, cfg Config, revision, path string) error {
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("transport manager listen address: %w", err)
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	} else if host == "::" {
		host = "::1"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+net.JoinHostPort(host, port)+"/v1/transports", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("read transport upgrade state: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("read transport upgrade state: HTTP %d", response.StatusCode)
	}
	var statuses []struct {
		Tag     string `json:"tag"`
		Desired *bool  `json:"desired_up"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<20))
	if err := decoder.Decode(&statuses); err != nil {
		return fmt.Errorf("decode transport upgrade state: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("transport upgrade state contains trailing data")
	}
	state := upgradeState{ConfigRevision: revision, Desired: make(map[string]bool)}
	for _, status := range statuses {
		if status.Tag == "" || status.Desired == nil {
			return fmt.Errorf("transport upgrade state is incomplete")
		}
		if _, duplicate := state.Desired[status.Tag]; duplicate {
			return fmt.Errorf("transport upgrade state contains duplicate tags")
		}
		state.Desired[status.Tag] = *status.Desired
	}
	for _, spec := range cfg.Transports {
		if spec.Type != "native" {
			if _, exists := state.Desired[spec.Tag]; !exists {
				return fmt.Errorf("transport upgrade state is missing a configured transport")
			}
		}
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = saveData(path, data, defaultSaveOperations)
	return err
}

func ReadUpgradeState(path, revision string) (map[string]bool, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var state upgradeState
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("transport upgrade state contains trailing data")
	}
	if state.ConfigRevision != revision || state.Desired == nil {
		return nil, fmt.Errorf("transport upgrade state does not match the installed configuration")
	}
	return state.Desired, nil
}
