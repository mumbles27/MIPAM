package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/term"
	"mipam/internal/app"
	"mipam/internal/logging"
)

type program struct {
	config app.Config
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
}

func (p *program) Start(s service.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		err := serve(ctx, p.config)
		close(p.done)
		if err != nil {
			slog.Error("server stopped", "error", err)
			_ = s.Stop()
		}
	}()
	return nil
}
func (p *program) Stop(s service.Service) error {
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			return errors.New("shutdown timeout")
		}
	}
	return nil
}
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		slog.Error("MIPAM stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	configPath := flag.String("config", "", "JSON configuration file (default: loopback development configuration)")
	user := flag.String("user", "admin", "bootstrap administrator username")
	dest := flag.String("destination", "", "new restore staging directory")
	file := flag.String("file", "", "backup file to restore")
	flag.Parse()
	action := "serve"
	if flag.NArg() > 0 {
		action = flag.Arg(0)
	}
	if action == "version" {
		fmt.Println("MIPAM 0.1.0")
		return nil
	}
	c, err := app.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *configPath != "" {
		absolute, err := filepath.Abs(*configPath)
		if err != nil {
			return err
		}
		resolvePaths(&c, filepath.Dir(absolute))
	}
	if c.LogFile != "" {
		log, err := logging.File(c.LogFile)
		if err != nil {
			return err
		}
		defer log.Close()
	}
	switch action {
	case "init-key":
		return app.InitBackupKey(c.BackupKeyFile)
	case "restore":
		if *file == "" || *dest == "" {
			return errors.New("-file and -destination required before restore")
		}
		return app.Restore(*file, c.BackupKeyFile, *dest)
	case "bootstrap":
		s, err := app.OpenStore(c.Database)
		if err != nil {
			return err
		}
		defer s.Close()
		var password []byte
		if value := os.Getenv("MIPAM_BOOTSTRAP_PASSWORD"); value != "" {
			password = []byte(value)
		} else {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New("use a terminal password prompt or MIPAM_BOOTSTRAP_PASSWORD environment variable")
			}
			fmt.Fprint(os.Stderr, "Administrator password (14–72 bytes): ")
			password, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}
		}
		err = app.Bootstrap(s, *user, string(password))
		clear(password)
		if err != nil {
			return err
		}
		if _, err = os.Stat(c.BackupKeyFile); os.IsNotExist(err) {
			return app.InitBackupKey(c.BackupKeyFile)
		}
		return nil
	case "backup":
		s, err := app.OpenStore(c.Database)
		if err != nil {
			return err
		}
		defer s.Close()
		a := &app.Server{C: c, S: s}
		path, err := a.Backup(context.Background())
		if err == nil {
			slog.Info("backup created", "path", path)
		}
		return err
	case "service-install", "service-uninstall", "service-start", "service-stop", "service-run":
		if *configPath == "" {
			return errors.New("service mode requires an absolute -config path")
		}
		absolute, err := filepath.Abs(*configPath)
		if err != nil {
			return err
		}
		p := &program{config: c}
		s, err := service.New(p, &service.Config{Name: "MIPAM", DisplayName: "MIPAM IP Address Management", Description: "MIPAM web and network management service", Arguments: []string{"-config", absolute, "service-run"}, Option: service.KeyValue{"StartType": "automatic"}})
		if err != nil {
			return err
		}
		if action == "service-run" {
			return s.Run()
		}
		return service.Control(s, strings.TrimPrefix(action, "service-"))
	case "serve":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return serve(ctx, c)
	default:
		return errors.New("commands: serve, bootstrap, init-key, backup, restore, version, service-install, service-uninstall, service-start, service-stop, service-run")
	}
}
func resolvePaths(c *app.Config, base string) {
	resolve := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	for _, p := range []*string{&c.Database, &c.BackupDir, &c.BackupKeyFile, &c.TLSCert, &c.TLSKey, &c.LogFile, &c.SAML.MetadataFile, &c.SAML.CertificateFile, &c.SAML.KeyFile} {
		resolve(p)
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		resolve(&p.CAFile)
		resolve(&p.CertFile)
		resolve(&p.KeyFile)
	}
}
func serve(ctx context.Context, c app.Config) error {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if (ip == nil || !ip.IsLoopback()) && (c.TLSCert == "" || c.TLSKey == "") {
		return errors.New("non-loopback listeners require TLS certificate and key; use loopback behind a TLS reverse proxy")
	}
	s, err := app.OpenStore(c.Database)
	if err != nil {
		return err
	}
	defer s.Close()
	a, err := app.NewServer(c, s)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: c.Listen, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	done := make(chan struct{})
	go func() { defer close(done); a.RunWorkers(workerCtx) }()
	go func() {
		<-workerCtx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("MIPAM listening", "address", c.Listen, "public_url", c.PublicURL)
	if c.TLSCert != "" {
		err = server.ListenAndServeTLS(c.TLSCert, c.TLSKey)
	} else {
		err = server.ListenAndServe()
	}
	cancelWorkers()
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
