package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/infaprim/mykeenpbr/internal/api"
	"github.com/infaprim/mykeenpbr/internal/config"
	"github.com/infaprim/mykeenpbr/internal/transport"
)

func main() {
	configPath := flag.String("config", "/opt/etc/keen-pbr/transports.json", "manager configuration file")
	flag.Parse()

	cfg, configRevision, err := config.LoadWithRevision(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	manager := transport.NewManager()
	supervisor := transport.NewSupervisor(manager)
	if err := transport.CleanupOrphanProcessesForMode(
		cfg.Transports,
		cfg.RuntimeDir,
		cfg.SingBoxProcessMode == config.SingBoxProcessModeShared,
	); err != nil {
		log.Fatalf("clean up orphan sing-box processes: %v", err)
	}
	transport.CleanupForwardingRules(cfg.Transports)
	var sharedGroup *transport.SharedSingBoxGroup
	if cfg.SingBoxProcessMode == config.SingBoxProcessModeShared {
		sharedGroup, err = transport.NewSharedSingBoxGroup(
			cfg.Transports,
			cfg.SingBoxBinary,
			cfg.RuntimeDir,
			cfg.HealthEndpoint(),
		)
		if err != nil {
			log.Fatalf("create shared sing-box runtime: %v", err)
		}
		if err := manager.SetSharedGroup(sharedGroup); err != nil {
			log.Fatalf("register shared sing-box runtime: %v", err)
		}
	}
	for _, item := range cfg.Transports {
		var managed transport.Transport
		if sharedGroup != nil && (item.Type == "sing-box" || item.Type == "sing-box-vless-reality") {
			managed, err = sharedGroup.Member(item.Tag)
		} else {
			managed, err = transport.NewFromSpec(
				item,
				cfg.SingBoxBinary,
				cfg.RuntimeDir,
				cfg.HealthEndpoint(),
			)
		}
		if err != nil {
			log.Fatalf("transport %q: %v", item.Tag, err)
		}
		if err := manager.Add(managed); err != nil {
			log.Fatalf("register transport %q: %v", item.Tag, err)
		}
		supervisor.Register(item)
	}

	admin := config.NewAdminWithRevision(
		*configPath,
		cfg,
		configRevision,
		manager,
		supervisor,
	)
	handler := api.New(supervisor, cfg.APIKey, admin)
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go supervisor.Run(ctx)

	go func() {
		log.Printf("transport-manager listening on %s", cfg.Listen)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server: %v", err)
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := supervisor.Close(shutdownCtx); err != nil {
		encoded, _ := json.Marshal(map[string]string{"shutdown_error": err.Error()})
		log.Print(string(encoded))
	}
	_ = server.Shutdown(shutdownCtx)
}
