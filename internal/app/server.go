package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed web/*
var assets embed.FS

type Server struct {
	C        Config
	S        *Store
	mux      *http.ServeMux
	loginMu  sync.Mutex
	attempts map[string]attempt
	backupMu sync.Mutex
}
type attempt struct {
	Count int
	Until time.Time
}
type principalKey struct{}
type csrfKey struct{}

func principal(r *http.Request) User { return r.Context().Value(principalKey{}).(User) }
func digest(s string) string         { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 415, "application/json required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "invalid JSON: "+err.Error())
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		fail(w, 400, "one JSON value required")
		return false
	}
	return true
}
func NewServer(c Config, s *Store) (*Server, error) {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("public_url must be an absolute origin")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		host, _, e := net.SplitHostPort(c.Listen)
		listenIP := net.ParseIP(host)
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || e != nil || listenIP == nil || !listenIP.IsLoopback() {
			return nil, errors.New("HTTPS public_url is required except for a loopback-only HTTP deployment")
		}
	}
	a := &Server{C: c, S: s, mux: http.NewServeMux(), attempts: map[string]attempt{}}
	a.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	a.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.DB.PingContext(r.Context()) != nil {
			fail(w, 503, "database unavailable")
			return
		}
		respond(w, 200, map[string]string{"status": "ready"})
	})
	a.mux.HandleFunc("GET /api/auth", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]bool{"oidc": c.OIDC.Issuer != "", "ldap": c.LDAP.URL != "", "saml": c.SAML.MetadataFile != ""})
	})
	a.mux.HandleFunc("POST /api/login", a.login)
	a.route("POST /api/logout", a.logout)
	a.route("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"user": principal(r), "csrf": r.Context().Value(csrfKey{})})
	})
	a.route("GET /api/subnets", a.getSubnets)
	a.route("POST /api/subnets", a.saveSubnet)
	a.route("PUT /api/subnets/{id}", a.saveSubnet)
	a.route("DELETE /api/subnets/{id}", a.deleteSubnet)
	a.route("GET /api/subnets/{id}/addresses", a.getAddresses)
	a.route("PUT /api/subnets/{id}/addresses/{ip}", a.saveAddress)
	a.route("DELETE /api/subnets/{id}/addresses/{ip}", a.deleteAddress)
	a.route("POST /api/import/subnets", a.importSubnets)
	a.route("GET /api/export", a.export)
	a.route("GET /api/users", a.getUsers)
	a.route("POST /api/users", a.saveUser)
	a.route("PUT /api/users/{id}", a.saveUser)
	a.route("GET /api/audit", a.getAudit)
	a.route("POST /api/backups", a.createBackup)
	a.route("GET /api/jobs", a.getJobs)
	a.route("POST /api/subnets/{id}/scan", a.queueScan)
	a.route("GET /api/providers", a.getProviders)
	a.route("POST /api/providers/{id}/read", a.readProvider)
	a.route("POST /api/providers/{id}/preview", a.previewProvider)
	a.route("POST /api/jobs/{id}/confirm", a.confirmJob)
	a.route("POST /api/jobs/{id}/cancel", a.cancelJob)
	a.route("GET /api/observations", a.getObservations)
	a.route("POST /api/discovery/neighbors", a.discoverNeighbors)
	a.route("GET /api/status", a.status)
	if err := a.setupIdentity(); err != nil {
		return nil, err
	}
	sub, _ := fs.Sub(assets, "web")
	a.mux.Handle("GET /", http.FileServer(http.FS(sub)))
	return a, nil
}
func (a *Server) route(pattern string, h http.HandlerFunc) { a.mux.Handle(pattern, a.auth(h)) }
func (a *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Request-ID", newID())
		if strings.HasPrefix(a.C.PublicURL, "https:") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		// Never trust forwarded headers to bypass browser-origin checks.
		if r.Method != "GET" && r.Method != "HEAD" && r.URL.Path != "/saml/acs" {
			if origin := r.Header.Get("Origin"); origin != "" && origin != strings.TrimRight(a.C.PublicURL, "/") {
				fail(w, 403, "origin rejected")
				return
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				fail(w, 403, "cross-site request rejected")
				return
			}
		}
		a.mux.ServeHTTP(w, r)
	})
}
func (a *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("mipam_session")
		if err != nil {
			fail(w, 401, "login required")
			return
		}
		var id, csrf string
		err = a.S.DB.QueryRowContext(r.Context(), "SELECT user_id,csrf FROM sessions WHERE token=? AND expires>?", digest(c.Value), time.Now().Unix()).Scan(&id, &csrf)
		if err != nil {
			fail(w, 401, "session expired")
			return
		}
		u, err := a.S.userByID(r.Context(), id)
		if err != nil || u.Disabled {
			fail(w, 401, "account unavailable")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(csrf), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
			fail(w, 403, "CSRF token required")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, u)
		ctx = context.WithValue(ctx, csrfKey{}, csrf)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (a *Server) admin(w http.ResponseWriter, r *http.Request) bool {
	if principal(r).Role != "admin" {
		_ = a.audit(r.Context(), principal(r).ID, "authorization.denied", r.URL.Path, "administrator required")
		fail(w, 403, "administrator required")
		return false
	}
	return true
}
func (a *Server) audit(ctx context.Context, actor, action, target, detail string) error {
	tx, err := a.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = a.auditIn(ctx, tx, actor, action, target, detail); err != nil {
		return err
	}
	return tx.Commit()
}
func (a *Server) auditIn(ctx context.Context, tx *sql.Tx, actor, action, target, detail string) error {
	return auditTx(ctx, tx, actor, action, target, detail, a.C.SIEMURL != "", a.C.SIEMQueueLimit)
}
func (a *Server) internal(w http.ResponseWriter, err error) {
	slog.Error("request failed", "error", err)
	fail(w, 500, "operation failed; consult server logs")
}
func (a *Server) throttled(key string) bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	t := time.Now()
	for k, v := range a.attempts {
		if t.After(v.Until) {
			delete(a.attempts, k)
		}
	}
	v := a.attempts[key]
	if v.Count >= 10 || len(a.attempts) > 10000 {
		return true
	}
	if v.Count == 0 {
		v.Until = t.Add(15 * time.Minute)
	}
	v.Count++
	a.attempts[key] = v
	return false
}
func (a *Server) login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if a.throttled(ip) {
		fail(w, 429, "too many attempts; retry in 15 minutes")
		return
	}
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Method   string `json:"method"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Name) > 256 || len(req.Password) > 1024 || req.Password == "" {
		fail(w, 401, "invalid credentials")
		return
	}
	if req.Method == "ldap" {
		a.ldapLogin(w, r, req.Name, req.Password)
		return
	}
	var id, hash string
	err := a.S.DB.QueryRowContext(r.Context(), "SELECT id,password FROM users WHERE name=? AND disabled=0", req.Name).Scan(&id, &hash)
	if err != nil || hash == "" {
		// Match the cost of a real failed login to reduce account enumeration.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"), []byte(req.Password))
	} else {
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password))
	}
	if err != nil || hash == "" {
		_ = a.audit(r.Context(), "anonymous", "login.failed", "local", "")
		fail(w, 401, "invalid credentials")
		return
	}
	u, err := a.S.userByID(r.Context(), id)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.issueSession(w, r, u)
}
func (a *Server) issueSession(w http.ResponseWriter, r *http.Request, u User) bool {
	token, csrf := newID()+newID(), newID()+newID()
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return false
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE expires<=?", time.Now().Unix())
	if err != nil {
		a.internal(w, err)
		return false
	}
	_, err = tx.ExecContext(r.Context(), "INSERT INTO sessions VALUES(?,?,?,?)", digest(token), u.ID, csrf, time.Now().Add(a.C.sessionDuration()).Unix())
	if err == nil {
		err = a.auditIn(r.Context(), tx, u.ID, "login.success", u.ID, "")
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return false
	}
	http.SetCookie(w, &http.Cookie{Name: "mipam_session", Value: token, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.C.PublicURL, "https:"), SameSite: http.SameSiteLaxMode, MaxAge: int(a.C.sessionDuration().Seconds())})
	return true
}
func (a *Server) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("mipam_session")
	_, err := a.S.DB.ExecContext(r.Context(), "DELETE FROM sessions WHERE token=?", digest(c.Value))
	if err != nil {
		a.internal(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "mipam_session", Value: "", Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.C.PublicURL, "https:"), SameSite: http.SameSiteLaxMode, MaxAge: -1})
	_ = a.audit(r.Context(), principal(r).ID, "logout", principal(r).ID, "")
	respond(w, 200, map[string]bool{"ok": true})
}
func Bootstrap(s *Store, name, password string) error {
	if strings.TrimSpace(name) == "" || len(name) > 200 || strings.Contains(name, ":") {
		return errors.New("invalid local username")
	}
	if len(password) < 14 || len(password) > 72 {
		return errors.New("password must be 14..72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow("SELECT count(*) FROM users").Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return errors.New("bootstrap disabled: users already exist")
	}
	id := newID()
	if _, err = tx.Exec("INSERT INTO users(id,name,password,role) VALUES(?,?,?,'admin')", id, name, string(hash)); err != nil {
		return err
	}
	if err = auditTx(context.Background(), tx, id, "bootstrap", id, "", false, 0); err != nil {
		return err
	}
	return tx.Commit()
}
