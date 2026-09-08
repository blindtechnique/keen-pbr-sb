package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	configpkg "github.com/infaprim/mykeenpbr/internal/config"
)

type TransportNativeGeoAdmin interface {
	UpdateNativeGeo(context.Context, configpkg.NativeGeoUpdate) (bool, string, error)
}

func (a *API) updateNativeGeo(w http.ResponseWriter, r *http.Request) {
	admin, ok := a.admin.(TransportNativeGeoAdmin)
	if !ok {
		write(w, http.StatusServiceUnavailable, map[string]string{"error": "native geo metadata unavailable"})
		return
	}
	var request configpkg.NativeGeoUpdate
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		write(w, http.StatusBadRequest, map[string]string{"error": "invalid native geo JSON"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		write(w, http.StatusBadRequest, map[string]string{"error": "invalid native geo JSON"})
		return
	}
	updated, revision, err := admin.UpdateNativeGeo(r.Context(), request)
	if err != nil {
		writeRevisionError(w, http.StatusBadRequest, revision, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	setRevisionHeader(w, revision)
	write(w, http.StatusOK, map[string]any{"updated": updated, "config_revision": revision})
}
