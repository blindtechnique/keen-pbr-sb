package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

type API struct {
	manager TransportRuntime
	key     string
	admin   TransportAdmin
}

type TransportRuntime interface {
	Statuses(context.Context) []transport.Status
	Status(context.Context, string) (transport.Status, error)
	Up(context.Context, string) error
	Down(context.Context, string) error
}

type TransportAdmin interface {
	Specs() []transport.TransportSpec
	Create(context.Context, transport.TransportSpec) error
	Update(context.Context, string, transport.TransportSpec) error
	Delete(context.Context, string) error
}

func New(manager TransportRuntime, key string, admins ...TransportAdmin) http.Handler {
	var admin TransportAdmin
	if len(admins) > 0 {
		admin = admins[0]
	}
	a := &API{manager: manager, key: key, admin: admin}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /v1/transports", a.list)
	mux.HandleFunc("GET /v1/transports/{tag}", a.status)
	mux.HandleFunc("POST /v1/transports/{tag}/{action}", a.action)
	mux.HandleFunc("GET /v1/config/transports", a.listConfig)
	mux.HandleFunc("POST /v1/config/transports", a.createConfig)
	mux.HandleFunc("PUT /v1/config/transports/{tag}", a.updateConfig)
	mux.HandleFunc("DELETE /v1/config/transports/{tag}", a.deleteConfig)
	return a.auth(mux)
}

func (a *API) listConfig(w http.ResponseWriter, _ *http.Request) {
	if a.admin == nil {
		write(w, http.StatusServiceUnavailable, map[string]string{"error": "transport admin unavailable"})
		return
	}
	write(w, http.StatusOK, a.admin.Specs())
}

func (a *API) createConfig(w http.ResponseWriter, r *http.Request) {
	if a.admin == nil {
		write(w, http.StatusServiceUnavailable, map[string]string{"error": "transport admin unavailable"})
		return
	}
	var spec transport.TransportSpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&spec); err != nil {
		write(w, http.StatusBadRequest, map[string]string{"error": "invalid transport JSON"})
		return
	}
	if err := a.admin.Create(r.Context(), spec); err != nil {
		write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	write(w, http.StatusCreated, map[string]string{"status": "created", "tag": spec.Tag})
}

func (a *API) updateConfig(w http.ResponseWriter, r *http.Request) {
	if a.admin == nil {
		write(w, http.StatusServiceUnavailable, map[string]string{"error": "transport admin unavailable"})
		return
	}
	var spec transport.TransportSpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&spec); err != nil {
		write(w, http.StatusBadRequest, map[string]string{"error": "invalid transport JSON"})
		return
	}
	if err := a.admin.Update(r.Context(), r.PathValue("tag"), spec); err != nil {
		write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	write(w, http.StatusOK, map[string]string{"status": "updated", "tag": spec.Tag})
}

func (a *API) deleteConfig(w http.ResponseWriter, r *http.Request) {
	if a.admin == nil {
		write(w, http.StatusServiceUnavailable, map[string]string{"error": "transport admin unavailable"})
		return
	}
	if err := a.admin.Delete(r.Context(), r.PathValue("tag")); err != nil {
		write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	write(w, http.StatusOK, map[string]string{"status": "deleted", "tag": r.PathValue("tag")})
}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(a.key)) != 1 {
			write(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	write(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (a *API) list(w http.ResponseWriter, r *http.Request) {
	write(w, http.StatusOK, a.manager.Statuses(r.Context()))
}
func (a *API) status(w http.ResponseWriter, r *http.Request) {
	status, err := a.manager.Status(r.Context(), r.PathValue("tag"))
	if err != nil {
		write(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	write(w, http.StatusOK, status)
}
func (a *API) action(w http.ResponseWriter, r *http.Request) {
	var err error
	switch r.PathValue("action") {
	case "up":
		err = a.manager.Up(r.Context(), r.PathValue("tag"))
	case "down":
		err = a.manager.Down(r.Context(), r.PathValue("tag"))
	default:
		write(w, http.StatusNotFound, map[string]string{"error": "unknown action"})
		return
	}
	if err != nil {
		write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	write(w, http.StatusAccepted, map[string]any{"status": "accepted", "at": time.Now().UTC()})
}
func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
