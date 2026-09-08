package config

import (
	"context"
	"errors"
	"strings"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

type NativeGeoUpdate struct {
	Tag               string `json:"tag"`
	ExpectedInterface string `json:"expected_interface"`
	CountryCode       string `json:"country_code"`
	Country           string `json:"country"`
}

// UpdateNativeGeo merges only lookup results into the current native spec.
// Delayed callbacks cannot replay aliases, secrets or a user's manual mode.
// Interface matching discards results for a tracker that was repointed while
// the lookup was pending; the companion does not own the Keenetic endpoint.
func (a *Admin) UpdateNativeGeo(ctx context.Context, request NativeGeoUpdate) (bool, string, error) {
	if request.Tag == "" || request.ExpectedInterface == "" {
		return false, "", errors.New("native geo requires tag and expected_interface")
	}
	validation := transport.TransportSpec{Tag: request.Tag, Type: "native", Interface: request.ExpectedInterface, GeoMode: "manual", CountryCode: request.CountryCode, Country: request.Country}
	if err := transport.ValidateTransportSpec(validation); err != nil {
		return false, "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, a.revision, err
	}
	index := a.index(request.Tag)
	if index < 0 {
		return false, a.revision, nil
	}
	current := a.config.Transports[index]
	if current.Type != "native" || current.GeoMode != "auto" || current.Interface != request.ExpectedInterface {
		return false, a.revision, nil
	}
	code := strings.ToUpper(request.CountryCode)
	if current.CountryCode == code && current.Country == request.Country {
		return false, a.revision, nil
	}
	current.CountryCode, current.Country = code, request.Country
	next := a.config
	next.Transports = append([]transport.TransportSpec(nil), a.config.Transports...)
	next.Transports[index] = current
	revision, err := saveAdminConfig(a.path, next)
	if err != nil {
		return false, a.revision, err
	}
	a.config, a.revision = next, revision
	return true, revision, nil
}
