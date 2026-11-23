package app

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"mipam/internal/providers"
)

type testApp struct {
	a                 *Server
	h                 http.Handler
	token, csrf, user string
}

func newTest(t *testing.T) *testApp {
	t.Helper()
	dir := t.TempDir()
	c, _ := LoadConfig("")
	c.Database = filepath.Join(dir, "test.db")
	c.BackupDir = filepath.Join(dir, "backups")
	c.BackupKeyFile = filepath.Join(dir, "key")
	s, err := OpenStore(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	a, err := NewServer(c, s)
	if err != nil {
		t.Fatal(err)
	}
	x := &testApp{a: a, h: a.Handler()}
	x.loginAs(t, "admin", nil)
	return x
}
func (x *testApp) loginAs(t *testing.T, role string, sites []string) {
	t.Helper()
	x.token = newID()
	x.csrf = newID()
	x.user = newID()
	raw, _ := json.Marshal(sites)
	if _, err := x.a.S.DB.Exec("INSERT INTO users VALUES(?,?,'',?,?,0)", x.user, x.user, role, string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := x.a.S.DB.Exec("INSERT INTO sessions VALUES(?,?,?,?)", digest(x.token), x.user, x.csrf, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
}
func (x *testApp) call(method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", x.csrf)
	r.AddCookie(&http.Cookie{Name: "mipam_session", Value: x.token})
	w := httptest.NewRecorder()
	x.h.ServeHTTP(w, r)
	return w
}
func status(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
}
func (x *testApp) subnet(t *testing.T, cidr, site string) Subnet {
	t.Helper()
	w := x.call("POST", "/api/subnets", Subnet{Name: "Test", CIDR: cidr, Site: site})
	status(t, w, 200)
	var s Subnet
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestInventoryLifecycle(t *testing.T) {
	x := newTest(t)
	s := x.subnet(t, "192.0.2.17/24", "HQ")
	if s.CIDR != "192.0.2.0/24" {
		t.Fatal(s)
	}
	status(t, x.call("POST", "/api/subnets", Subnet{Name: "Overlap", CIDR: "192.0.2.0/25", Site: "HQ"}), 400)
	status(t, x.call("POST", "/api/subnets", Subnet{Name: "VRF", CIDR: s.CIDR, Site: "HQ", VRF: "other"}), 200)
	path := "/api/subnets/" + s.ID + "/addresses/192.0.2.7"
	w := x.call("PUT", path, Address{State: "static", Hostname: "test"})
	status(t, w, 200)
	status(t, x.call("PUT", path, Address{State: "available"}), 409)
	status(t, x.call("PUT", path, Address{State: "reserved", Version: 1}), 200)
	status(t, x.call("PUT", path, Address{State: "available", Version: 1}), 409)
	status(t, x.call("PUT", "/api/subnets/"+s.ID+"/addresses/192.0.2.0", Address{State: "static"}), 400)
	status(t, x.call("PUT", "/api/subnets/"+s.ID+"/addresses/192.0.3.1", Address{State: "static"}), 400)
	w = x.call("GET", "/api/subnets/"+s.ID+"/addresses?limit=8", nil)
	status(t, w, 200)
	var grid struct {
		Addresses []Address `json:"addresses"`
		Next      string    `json:"next"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &grid)
	if len(grid.Addresses) != 8 || grid.Next != "192.0.2.8" || grid.Addresses[0].State != "network" || grid.Addresses[1].State != "unknown" {
		t.Fatal(w.Body.String())
	}
	status(t, x.call("DELETE", path+"?version=2", nil), 200)
	status(t, x.call("DELETE", "/api/subnets/"+s.ID+"?version=1&confirm=192.0.2.0/24", nil), 200)
}
func TestAuthorizationAndCSRF(t *testing.T) {
	x := newTest(t)
	s := x.subnet(t, "192.0.2.0/24", "HQ")
	x.loginAs(t, "operator", []string{"Branch"})
	status(t, x.call("GET", "/api/subnets/"+s.ID+"/addresses", nil), 403)
	status(t, x.call("PUT", "/api/subnets/"+s.ID+"/addresses/192.0.2.1", Address{State: "static"}), 403)
	status(t, x.call("POST", "/api/users", User{Name: "elevated", Role: "admin"}), 403)
	status(t, x.call("GET", "/api/audit", nil), 403)
	x.loginAs(t, "viewer", []string{"HQ"})
	status(t, x.call("GET", "/api/subnets/"+s.ID+"/addresses", nil), 200)
	status(t, x.call("PUT", "/api/subnets/"+s.ID+"/addresses/192.0.2.1", Address{State: "static"}), 403)
	x.loginAs(t, "admin", nil)
	x.csrf = "wrong"
	status(t, x.call("POST", "/api/subnets", Subnet{Name: "X", CIDR: "203.0.113.0/24", Site: "HQ"}), 403)
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"name":"x","password":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	x.h.ServeHTTP(w, r)
	status(t, w, 403)
}
func TestImportAtomicity(t *testing.T) {
	x := newTest(t)
	csv := "name,cidr,site\none,192.0.2.0/24,HQ\ntwo,192.0.2.0/25,HQ\n"
	status(t, x.call("POST", "/api/import/subnets", subnetImport{CSV: csv, Apply: true}), 400)
	var count int
	_ = x.a.S.DB.QueryRow("SELECT count(*) FROM subnets").Scan(&count)
	if count != 0 {
		t.Fatal("partial import")
	}
	csv = "name,cidr,site\none,192.0.2.0/24,HQ\ntwo,203.0.113.0/24,HQ\n"
	status(t, x.call("POST", "/api/import/subnets", subnetImport{CSV: csv}), 200)
	_ = x.a.S.DB.QueryRow("SELECT count(*) FROM subnets").Scan(&count)
	if count != 0 {
		t.Fatal("preview mutated")
	}
	status(t, x.call("POST", "/api/import/subnets", subnetImport{CSV: csv, Apply: true}), 200)
	status(t, x.call("POST", "/api/import/subnets", subnetImport{CSV: csv, Apply: true}), 400)
	_ = x.a.S.DB.QueryRow("SELECT count(*) FROM subnets").Scan(&count)
	if count != 2 {
		t.Fatal(count)
	}
}
func TestConcurrentAllocation(t *testing.T) {
	x := newTest(t)
	s := x.subnet(t, "192.0.2.0/24", "HQ")
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- x.call("PUT", "/api/subnets/"+s.ID+"/addresses/192.0.2.2", Address{State: "static"}).Code
		}()
	}
	wg.Wait()
	close(codes)
	success, conflict := 0, 0
	for c := range codes {
		if c == 200 {
			success++
		}
		if c == 409 {
			conflict++
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}
func TestAuditBackpressureRollsBack(t *testing.T) {
	x := newTest(t)
	x.a.C.SIEMURL = "https://siem.invalid"
	x.a.C.SIEMQueueLimit = 1
	_ = x.subnet(t, "192.0.2.0/24", "HQ")
	status(t, x.call("POST", "/api/subnets", Subnet{Name: "Blocked", CIDR: "203.0.113.0/24", Site: "HQ"}), 500)
	var n int
	_ = x.a.S.DB.QueryRow("SELECT count(*) FROM subnets").Scan(&n)
	if n != 1 {
		t.Fatal("mutation escaped audit transaction")
	}
}
func TestBackupRestoreAndTamper(t *testing.T) {
	x := newTest(t)
	s := x.subnet(t, "192.0.2.0/24", "HQ")
	if err := InitBackupKey(x.a.C.BackupKeyFile); err != nil {
		t.Fatal(err)
	}
	path, err := x.a.Backup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	if err = Restore(path, x.a.C.BackupKeyFile, dest); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenStore(filepath.Join(dest, "mipam.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err = restored.subnet(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	_ = restored.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&count)
	if count != 0 {
		t.Fatal("restored active sessions")
	}
	if err = Restore(path, x.a.C.BackupKeyFile, dest); err == nil {
		t.Fatal("overwrite allowed")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	tampered := filepath.Join(t.TempDir(), "tampered")
	_ = os.WriteFile(tampered, raw, 0600)
	if err = Restore(tampered, x.a.C.BackupKeyFile, filepath.Join(t.TempDir(), "bad")); err == nil {
		t.Fatal("tampered backup accepted")
	}
}
func TestIdentityAndReplay(t *testing.T) {
	x := newTest(t)
	role, sites := groupGrants([]string{"readHQ", "writeBranch"}, map[string]string{"readHQ": "viewer", "writeBranch": "operator"}, map[string][]string{"readHQ": {"HQ"}, "writeBranch": {"Branch"}})
	if role != "operator" || len(sites) != 1 || sites[0] != "Branch" {
		t.Fatal("cross-group privilege escalation", role, sites)
	}
	if _, err := x.a.externalUser(context.Background(), "oidc", "subject", nil, nil, nil); err == nil {
		t.Fatal("unmapped identity accepted")
	}
	replay := replayStore{x.a.S}
	if err := replay.Consume("assertion", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := replay.Consume("assertion", time.Now().Add(time.Hour)); err != saml.ErrAssertionReplayed {
		t.Fatal("replay allowed", err)
	}
}
func TestBootstrapAndLogin(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	password := "test-only-long-password"
	if err = Bootstrap(s, "admin", password); err != nil {
		t.Fatal(err)
	}
	if err = Bootstrap(s, "another", password); err == nil {
		t.Fatal("second bootstrap allowed")
	}
	c, _ := LoadConfig("")
	a, err := NewServer(c, s)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(fmt.Sprintf(`{"name":"admin","password":%q}`, password)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	status(t, w, 200)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("invalid session cookie")
	}
	var stored string
	if err = s.DB.QueryRow("SELECT token FROM sessions").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == cookies[0].Value {
		t.Fatal("raw session stored")
	}
}
func TestScanBoundsAndSmallSubnets(t *testing.T) {
	for _, cidr := range []string{"192.0.2.0/31", "192.0.2.1/32"} {
		p := netip.MustParsePrefix(cidr)
		if reservedIP(p, p.Addr()) {
			t.Fatal("valid host rejected")
		}
	}
	n := Subnet{CIDR: "192.0.2.0/24"}
	ips, err := scanTargets(n, scanRequest{Limit: 1024})
	if err != nil || len(ips) != 254 {
		t.Fatal(len(ips), err)
	}
	if _, err = scanTargets(n, scanRequest{Limit: 2048}); err == nil {
		t.Fatal("scan bound bypass")
	}
	if _, err = scanTargets(n, scanRequest{Start: "203.0.113.1", Limit: 1}); err == nil {
		t.Fatal("scope escape")
	}
	if _, err = scanTargets(Subnet{CIDR: "2001:db8::/64"}, scanRequest{Limit: 10}); err == nil {
		t.Fatal("unbounded IPv6 scan")
	}
}
func TestDHCPOverlay(t *testing.T) {
	x := newTest(t)
	n := x.subnet(t, "192.0.2.0/24", "HQ")
	tx, err := x.a.S.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(`[{"ip":"192.0.2.2","state":"Active","hostname":"dhcp-host","expires":"2099-01-01T00:00:00Z"}]`)
	if err = syncDHCP(context.Background(), tx, "windows", "windows", n, providers.Request{Kind: "lease", ScopeID: "192.0.2.0"}, raw); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	out := []Address{{IP: "192.0.2.2", State: "unknown"}, {IP: "192.0.2.3", State: "unknown"}}
	if err = x.a.overlayDHCP(context.Background(), n.ID, out); err != nil {
		t.Fatal(err)
	}
	if out[0].DisplayState != "leased" || out[1].DisplayState != "unknown" || out[0].State != "unknown" {
		t.Fatal(out)
	}
	out[0].State = "static"
	_ = x.a.overlayDHCP(context.Background(), n.ID, out)
	if out[0].DisplayState != "conflict" {
		t.Fatal(out)
	}
	_, _ = x.a.S.DB.Exec("UPDATE dhcp_state SET observed=?", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	out[0].State = "unknown"
	_ = x.a.overlayDHCP(context.Background(), n.ID, out)
	if out[0].DisplayState != "stale" {
		t.Fatal(out)
	}
}

// GO-2026-6909 remains a release-review item even with this parser regression.
func TestSAMLRejectsForeignNamespaceNameID(t *testing.T) {
	var subject saml.Subject
	payload := `<Subject xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><NameID xmlns="urn:attacker">administrator</NameID></Subject>`
	if err := xml.Unmarshal([]byte(payload), &subject); err != nil {
		t.Fatal(err)
	}
	if subject.NameID != nil {
		t.Fatal("foreign namespace NameID accepted")
	}
	var assertion saml.Assertion
	if err := xml.Unmarshal([]byte(`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"/>`), &assertion); err != nil {
		t.Fatal(err)
	}
	if assertion.Issuer.Value != "" {
		t.Fatal("missing issuer was populated")
	}
}

func TestStoreLock(t *testing.T) {
	x := newTest(t)
	if other, err := OpenStore(x.a.C.Database); err == nil {
		other.Close()
		t.Fatal("second process allowed")
	}
}
func TestJobConfirmationAndPermissionRevocation(t *testing.T) {
	x := newTest(t)
	id, err := x.a.enqueue(context.Background(), x.user, "provider", "missing", "preview", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	status(t, x.call("POST", "/api/jobs/"+id+"/confirm", map[string]string{"confirm": "wrong"}), 400)
	status(t, x.call("POST", "/api/jobs/"+id+"/confirm", map[string]string{"confirm": id}), 200)
	status(t, x.call("POST", "/api/jobs/"+id+"/confirm", map[string]string{"confirm": id}), 409)
	_, _ = x.a.S.DB.Exec("UPDATE users SET disabled=1 WHERE id=?", x.user)
	if err = x.a.runJob(context.Background()); err != nil {
		t.Fatal(err)
	}
	var state string
	_ = x.a.S.DB.QueryRow("SELECT status FROM jobs WHERE id=?", id).Scan(&state)
	if state != "failed" {
		t.Fatal(state)
	}
}
