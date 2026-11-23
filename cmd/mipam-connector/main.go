package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/service"
	"mipam/internal/logging"
	"mipam/internal/providers"
)

type program struct {
	config config
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
}

func (p *program) Start(s service.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel, p.done = cancel, make(chan struct{})
	go func() {
		err := serve(ctx, p.config)
		close(p.done)
		if err != nil {
			slog.Error("connector stopped", "error", err)
			_ = s.Stop()
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(55 * time.Second):
			return errors.New("connector shutdown timeout")
		}
	}
	return nil
}

type config struct {
	Listen             string   `json:"listen"`
	Server             string   `json:"server"`
	Cert               string   `json:"cert_file"`
	Key                string   `json:"key_file"`
	ClientCA           string   `json:"client_ca_file"`
	ClientFingerprints []string `json:"client_fingerprints"`
	Zones              []string `json:"zones"`
	Scopes             []string `json:"scopes"`
	AllowWrites        bool     `json:"allow_writes"`
	AllowDirectory     bool     `json:"allow_directory"`
	LogFile            string   `json:"log_file"`
}

func authorized(c config, r providers.Request) bool {
	if r.Action != "read" && !c.AllowWrites {
		return false
	}
	switch r.Kind {
	case "dns":
		for _, z := range c.Zones {
			if strings.EqualFold(strings.TrimSuffix(z, "."), strings.TrimSuffix(r.Zone, ".")) {
				return true
			}
		}
	case "scope", "reservation", "lease":
		return r.ScopeID != "" && slices.Contains(c.Scopes, r.ScopeID)
	case "ad-computer":
		return c.AllowDirectory && r.Action == "read"
	}
	return false
}
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		slog.Error("connector stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "connector.json", "connector configuration")
	flag.Parse()
	if runtime.GOOS != "windows" {
		return errors.New("connector execution requires Windows")
	}
	absolute, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	f, err := os.Open(absolute)
	if err != nil {
		return err
	}
	defer f.Close()
	var c config
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return err
	}
	if c.Listen == "" || c.Server == "" || len(c.ClientFingerprints) == 0 {
		return errors.New("listen, fixed target server and allowed client certificate fingerprints are required")
	}
	for _, path := range []*string{&c.Cert, &c.Key, &c.ClientCA, &c.LogFile} {
		if *path != "" && !filepath.IsAbs(*path) {
			*path = filepath.Join(filepath.Dir(absolute), *path)
		}
	}
	if c.LogFile != "" {
		log, err := logging.File(c.LogFile)
		if err != nil {
			return err
		}
		defer log.Close()
	}
	action := "serve"
	if flag.NArg() > 0 {
		action = flag.Arg(0)
	}
	switch action {
	case "service-install", "service-uninstall", "service-start", "service-stop", "service-run":
		p := &program{config: c}
		s, err := service.New(p, &service.Config{
			Name: "MIPAMConnector", DisplayName: "MIPAM Windows Connector",
			Description: "Allowlisted MIPAM DNS, DHCP and directory management",
			Arguments:   []string{"-config", absolute, "service-run"},
			Option:      service.KeyValue{"StartType": "manual"},
		})
		if err != nil {
			return err
		}
		if action == "service-run" {
			return s.Run()
		}
		return service.Control(s, strings.TrimPrefix(action, "service-"))
	case "serve":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return serve(ctx, c)
	default:
		return errors.New("unknown connector command")
	}
}

func serve(ctx context.Context, c config) error {
	pem, err := os.ReadFile(c.ClientCA)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("invalid client CA")
	}
	var serial sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("POST /execute", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", 403)
			return
		}
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		if !slices.Contains(c.ClientFingerprints, hex.EncodeToString(sum[:])) {
			http.Error(w, "certificate not enrolled", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		var req providers.Request
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || dec.Decode(&struct{}{}) != io.EOF || req.Validate() != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		if !authorized(c, req) {
			http.Error(w, "operation outside connector allowlist", 403)
			return
		}
		// One management operation at a time per connector; PowerShell is bounded.
		if !serial.TryLock() {
			http.Error(w, "connector busy", 429)
			return
		}
		defer serial.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		slog.Info("management operation", "kind", req.Kind, "action", req.Action, "client", hex.EncodeToString(sum[:]))
		data, err := providers.WindowsExecute(ctx, c.Server, req)
		if err != nil {
			slog.Error("management operation failed", "kind", req.Kind, "action", req.Action)
			http.Error(w, err.Error(), 502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
	server := &http.Server{Addr: c.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 50 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 45*time.Second)
		defer done()
		_ = server.Shutdown(c)
	}()
	err = server.ListenAndServeTLS(c.Cert, c.Key)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
