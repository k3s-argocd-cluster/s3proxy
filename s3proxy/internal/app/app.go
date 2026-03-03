package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/k3s-argocd-cluster/s3proxy/internal/config"
	"github.com/k3s-argocd-cluster/s3proxy/internal/router"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	logger "github.com/sirupsen/logrus"
)

const shutdownTimeout = 10 * time.Second

type Config struct {
	NoTLS        bool
	IP           string
	DataPort     int
	OpsPort      int
	Region       string
	CertLocation string
	NoTagging    bool
	CacheType    string
}

func Run(ctx context.Context, cfg Config, log *logger.Logger) error {
	routerInstance, err := router.New(cfg.Region, !cfg.NoTagging, cfg.CacheType, log)
	if err != nil {
		return fmt.Errorf("creating router: %w", err)
	}

	dataHandler := http.HandlerFunc(routerInstance.Serve)
	throttling := config.GetThrottlingRequestsMax()
	if throttling != 0 {
		log.WithField("throttling_requestsmax", throttling).Info("throttling is enabled")
		throttler := router.NewThrottlingMiddleware(throttling, 10*time.Second)
		dataHandler = throttler.Throttle(dataHandler).ServeHTTP
	}

	opsMux := http.NewServeMux()
	opsMux.Handle("/metrics", promhttp.Handler())
	opsMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			log.WithError(err).Error("failed to write healthz response")
		}
	})
	opsMux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			log.WithError(err).Error("failed to write readyz response")
		}
	})

	dataServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.IP, cfg.DataPort),
		Handler:      dataHandler,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}

	if !cfg.NoTLS {
		cert, err := tls.LoadX509KeyPair(cfg.CertLocation+"/s3proxy.crt", cfg.CertLocation+"/s3proxy.key")
		if err != nil {
			return fmt.Errorf("loading TLS certificate: %w", err)
		}

		dataServer.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	} else {
		log.Warn("TLS is disabled on data listener")
	}

	opsServer := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.IP, cfg.OpsPort),
		Handler: opsMux,
	}

	runCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		if cfg.NoTLS {
			errCh <- serveAndWrap("data", dataServer.ListenAndServe())
			return
		}
		errCh <- serveAndWrap("data", dataServer.ListenAndServeTLS("", ""))
	}()
	go func() {
		errCh <- serveAndWrap("ops", opsServer.ListenAndServe())
	}()

	select {
	case <-runCtx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil {
			cancel()
			if shutdownErr := shutdownServers(log, dataServer, opsServer); shutdownErr != nil {
				log.WithError(shutdownErr).Error("shutdown failed after server error")
			}
			return err
		}
	}

	if err := shutdownServers(log, dataServer, opsServer); err != nil {
		return err
	}

	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
	default:
	}

	return nil
}

func serveAndWrap(name string, err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("%s server: %w", name, err)
}

func shutdownServers(log *logger.Logger, servers ...*http.Server) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var retErr error
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Error("server shutdown failed")
			retErr = err
		}
	}
	return retErr
}
