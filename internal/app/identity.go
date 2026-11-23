package app

import (
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/oauth2"
)

func groupGrants(groups []string, roles map[string]string, sites map[string][]string) (string, []string) {
	role := ""
	rank := map[string]int{"viewer": 1, "auditor": 2, "operator": 3, "admin": 4}
	out := []string{}
	for _, g := range groups {
		if rank[roles[g]] > rank[role] {
			role = roles[g]
		}
	}
	// Do not combine an operator role from one group with viewer-only sites
	// from another group, which would elevate access to those sites.
	for _, g := range groups {
		if roles[g] == role && validRole(role) {
			out = append(out, sites[g]...)
		}
	}
	slices.Sort(out)
	return role, slices.Compact(out)
}
func (a *Server) externalUser(ctx context.Context, provider, subject string, groups []string, roles map[string]string, sites map[string][]string) (User, error) {
	role, grants := groupGrants(groups, roles, sites)
	if role == "" || subject == "" || len(subject) > 1024 {
		return User{}, errors.New("no configured group grants")
	}
	name := provider + ":" + subject
	tx, err := a.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var id string
	var disabled bool
	err = tx.QueryRowContext(ctx, "SELECT id,disabled FROM users WHERE name=?", name).Scan(&id, &disabled)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return User{}, err
	}
	if disabled {
		return User{}, errors.New("account disabled")
	}
	raw, _ := json.Marshal(grants)
	if id == "" {
		id = newID()
		_, err = tx.ExecContext(ctx, "INSERT INTO users VALUES(?,?,'',?,?,0)", id, name, role, string(raw))
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE users SET role=?,sites=? WHERE id=?", role, string(raw), id)
		// Re-evaluate all sessions against the newly mapped identity on every login.
		if err == nil {
			_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", id)
		}
	}
	if err == nil {
		err = a.auditIn(ctx, tx, id, "identity.sync", id, "group grants refreshed")
	}
	if err == nil {
		err = tx.Commit()
	}
	return User{ID: id, Name: name, Role: role, Sites: grants}, err
}
func (a *Server) setupIdentity() error {
	if a.C.LDAP.URL != "" {
		u, err := url.Parse(a.C.LDAP.URL)
		if err != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil {
			return errors.New("LDAP requires ldaps:// and a valid certificate")
		}
		if a.C.LDAP.BindDN == "" || a.C.LDAP.BaseDN == "" || os.Getenv(a.C.LDAP.PasswordEnv) == "" {
			return errors.New("LDAP service bind DN, base DN, and password environment variable required")
		}
	}
	if a.C.OIDC.Issuer != "" {
		if !strings.HasPrefix(a.C.PublicURL, "https://") || !strings.HasPrefix(a.C.OIDC.Issuer, "https://") {
			return errors.New("OIDC requires HTTPS public URL and issuer")
		}
		if a.C.OIDC.ClientID == "" {
			return errors.New("OIDC client_id required")
		}
		client := &http.Client{Timeout: 15 * time.Second}
		ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), oauth2.HTTPClient, client), 20*time.Second)
		p, err := oidc.NewProvider(ctx, a.C.OIDC.Issuer)
		cancel()
		if err != nil {
			return errors.New("OIDC discovery failed; verify issuer and connectivity")
		}
		cfg := oauth2.Config{ClientID: a.C.OIDC.ClientID, ClientSecret: os.Getenv(a.C.OIDC.SecretEnv), Endpoint: p.Endpoint(), RedirectURL: strings.TrimRight(a.C.PublicURL, "/") + "/auth/oidc/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"}}
		verifier := p.Verifier(&oidc.Config{ClientID: cfg.ClientID})
		a.mux.HandleFunc("GET /auth/oidc/login", func(w http.ResponseWriter, r *http.Request) {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if a.throttled("oidc:" + ip) {
				fail(w, 429, "too many attempts")
				return
			}
			state, nonce, pkce := newID()+newID(), newID(), oauth2.GenerateVerifier()
			_, err := a.S.DB.ExecContext(r.Context(), "DELETE FROM auth_flows WHERE expires<=?", time.Now().Unix())
			if err != nil {
				a.internal(w, err)
				return
			}
			_, err = a.S.DB.ExecContext(r.Context(), "INSERT INTO auth_flows VALUES(?,?,?,?)", digest(state), nonce, pkce, time.Now().Add(5*time.Minute).Unix())
			if err != nil {
				a.internal(w, err)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "mipam_oidc", Value: state, Path: "/auth/oidc", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
			http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)), 302)
		})
		a.mux.HandleFunc("GET /auth/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie("mipam_oidc")
			state := r.URL.Query().Get("state")
			if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
				fail(w, 401, "invalid login state")
				return
			}
			var nonce, pkce string
			err = a.S.DB.QueryRowContext(r.Context(), "DELETE FROM auth_flows WHERE state=? AND expires>? RETURNING nonce,verifier", digest(state), time.Now().Unix()).Scan(&nonce, &pkce)
			http.SetCookie(w, &http.Cookie{Name: "mipam_oidc", Path: "/auth/oidc", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
			if err != nil {
				fail(w, 401, "login expired or already used")
				return
			}
			ctx := context.WithValue(r.Context(), oauth2.HTTPClient, client)
			token, err := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pkce))
			if err != nil {
				fail(w, 401, "token exchange failed")
				return
			}
			raw, _ := token.Extra("id_token").(string)
			id, err := verifier.Verify(ctx, raw)
			if err != nil || id.Nonce != nonce {
				fail(w, 401, "invalid identity token")
				return
			}
			var claims map[string]json.RawMessage
			if err = id.Claims(&claims); err != nil {
				fail(w, 401, "invalid claims")
				return
			}
			groupClaim := a.C.OIDC.GroupClaim
			if groupClaim == "" {
				groupClaim = "groups"
			}
			var groups []string
			_ = json.Unmarshal(claims[groupClaim], &groups)
			u, err := a.externalUser(r.Context(), "oidc", a.C.OIDC.Issuer+"|"+id.Subject, groups, a.C.OIDC.GroupRoles, a.C.OIDC.GroupSites)
			if err != nil {
				fail(w, 403, "no authorized account or group mapping")
				return
			}
			if a.issueSession(w, r, u) {
				http.Redirect(w, r, "/", 303)
			}
		})
	}
	if a.C.SAML.MetadataFile != "" {
		return a.setupSAML()
	}
	return nil
}
func (a *Server) ldapLogin(w http.ResponseWriter, r *http.Request, name, password string) {
	c := a.C.LDAP
	if c.URL == "" {
		fail(w, 400, "LDAP is not configured")
		return
	}
	u, _ := url.Parse(c.URL)
	conn, err := ldap.DialURL(c.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}), ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}))
	if err != nil {
		fail(w, 503, "directory unavailable")
		return
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)
	if err = conn.Bind(c.BindDN, os.Getenv(c.PasswordEnv)); err != nil {
		fail(w, 503, "directory service bind failed")
		return
	}
	result, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, "(&(objectClass=user)(sAMAccountName="+ldap.EscapeFilter(name)+"))", []string{"objectGUID", "memberOf", "displayName", "userPrincipalName"}, nil))
	if err != nil || len(result.Entries) != 1 {
		fail(w, 401, "invalid directory credentials")
		return
	}
	e := result.Entries[0]
	if err = conn.Bind(e.DN, password); err != nil {
		_ = a.audit(r.Context(), "anonymous", "login.failed", "ldap", "")
		fail(w, 401, "invalid directory credentials")
		return
	}
	id := e.GetRawAttributeValue("objectGUID")
	if len(id) == 0 {
		fail(w, 401, "directory user has no stable identifier")
		return
	}
	// Membership is direct memberOf; nested groups are not silently inferred.
	user, err := a.externalUser(r.Context(), "ldap", digest(c.URL+c.BaseDN+string(id)), e.GetAttributeValues("memberOf"), c.GroupRoles, c.GroupSites)
	if err != nil {
		fail(w, 403, "no authorized account or group mapping")
		return
	}
	a.issueSession(w, r, user)
}

type replayStore struct{ s *Store }

func (c replayStore) Consume(id string, expires time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := c.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM saml_replay WHERE expires<?", time.Now().Unix()); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO saml_replay VALUES(?,?)", digest(id), expires.Unix())
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return saml.ErrAssertionReplayed
	}
	return tx.Commit()
}

type samlSession struct{ a *Server }

func (s samlSession) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return errors.New("missing subject")
	}
	groups := []string{}
	c := s.a.C.SAML
	for _, st := range assertion.AttributeStatements {
		for _, attr := range st.Attributes {
			if attr.Name == c.GroupAttribute {
				for _, v := range attr.Values {
					groups = append(groups, v.Value)
				}
			}
		}
	}
	u, err := s.a.externalUser(r.Context(), "saml", assertion.Issuer.Value+"|"+assertion.Subject.NameID.Value, groups, c.GroupRoles, c.GroupSites)
	if err != nil {
		return err
	}
	if !s.a.issueSession(w, r, u) {
		return errors.New("session creation failed")
	}
	return nil
}
func (s samlSession) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	return errors.New("SAML single logout is not enabled; use application logout")
}
func (s samlSession) GetSession(r *http.Request) (samlsp.Session, error) {
	return nil, samlsp.ErrNoSession
}
func (a *Server) setupSAML() error {
	if !strings.HasPrefix(a.C.PublicURL, "https://") {
		return errors.New("SAML requires HTTPS public URL")
	}
	c := a.C.SAML
	cert, err := tls.LoadX509KeyPair(c.CertificateFile, c.KeyFile)
	if err != nil {
		return errors.New("cannot load SAML signing certificate/key")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("invalid SAML signing key")
	}
	data, err := os.ReadFile(c.MetadataFile)
	if err != nil {
		return err
	}
	metadata, err := samlsp.ParseMetadata(data)
	if err != nil {
		return err
	}
	u, _ := url.Parse(strings.TrimRight(a.C.PublicURL, "/") + "/")
	m, err := samlsp.New(samlsp.Options{URL: *u, Key: key, Certificate: leaf, IDPMetadata: metadata, SignRequest: true, AllowIDPInitiated: false, DefaultRedirectURI: "/", RejectUnknownConditions: true, RequireSignedResponseForCBC: true, RejectExpiredIDPMetadata: true, ReplayCache: replayStore{a.S}, Binding: saml.HTTPRedirectBinding, AssertionConsumerServiceBindings: []string{saml.HTTPPostBinding}})
	if err != nil {
		return err
	}
	m.Session = samlSession{a}
	m.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
		_ = a.audit(r.Context(), "anonymous", "login.failed", "saml", "assertion or authorization rejected")
		fail(w, 401, "SAML authentication rejected")
	}
	a.mux.HandleFunc("GET /saml/metadata", m.ServeMetadata)
	a.mux.HandleFunc("POST /saml/acs", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		m.ServeACS(w, r)
	})
	a.mux.HandleFunc("GET /auth/saml/login", func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if a.throttled("saml:" + ip) {
			fail(w, 429, "too many attempts")
			return
		}
		clone := r.Clone(r.Context())
		copyURL := *r.URL
		copyURL.Path = "/"
		copyURL.RawQuery = ""
		clone.URL = &copyURL
		m.HandleStartAuthFlow(w, clone)
	})
	return nil
}
