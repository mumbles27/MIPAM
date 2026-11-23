package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	_ "modernc.org/sqlite"
)

type Store struct {
	DB   *sql.DB
	lock *flock.Flock
}

func (s *Store) Close() error {
	err := s.DB.Close()
	if s.lock != nil {
		if unlockErr := s.lock.Close(); err == nil {
			err = unlockErr
		}
	}
	return err
}

type User struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	Sites    []string `json:"sites"`
	Disabled bool     `json:"disabled"`
}
type Subnet struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CIDR        string `json:"cidr"`
	Site        string `json:"site"`
	VRF         string `json:"vrf"`
	VLAN        int    `json:"vlan"`
	Description string `json:"description"`
	ScanEnabled bool   `json:"scan_enabled"`
	Version     int    `json:"version"`
}
type Address struct {
	SubnetID     string      `json:"subnet_id"`
	IP           string      `json:"ip"`
	Hostname     string      `json:"hostname"`
	MAC          string      `json:"mac"`
	State        string      `json:"state"`
	Note         string      `json:"note"`
	Reachability string      `json:"reachability"`
	LastSeen     string      `json:"last_seen"`
	Version      int         `json:"version"`
	DisplayState string      `json:"display_state,omitempty"`
	DHCP         []DHCPState `json:"dhcp,omitempty"`
}
type Audit struct {
	ID     string `json:"id"`
	Time   string `json:"time"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}
type Job struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Actor   string `json:"actor"`
	Target  string `json:"target"`
	Status  string `json:"status"`
	Payload string `json:"payload"`
	Result  string `json:"result"`
	Created string `json:"created"`
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func now() string { return time.Now().UTC().Format(time.RFC3339) }

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock := flock.New(path + ".lock")
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, errors.New("database is already in use; use the web UI for online backups or stop the service before offline commands")
	}
	keepLock := false
	defer func() {
		if !keepLock {
			_ = lock.Close()
		}
	}()
	// Create with restrictive permissions before SQLite opens the database.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
	CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
	INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
	CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL,sites TEXT NOT NULL DEFAULT '[]',disabled INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
	CREATE TABLE IF NOT EXISTS subnets(id TEXT PRIMARY KEY,name TEXT NOT NULL,cidr TEXT NOT NULL,site TEXT NOT NULL,vrf TEXT NOT NULL,vlan INTEGER NOT NULL,description TEXT NOT NULL,scan_enabled INTEGER NOT NULL DEFAULT 0,version INTEGER NOT NULL DEFAULT 1,UNIQUE(cidr,vrf));
	CREATE TABLE IF NOT EXISTS addresses(subnet_id TEXT NOT NULL REFERENCES subnets(id) ON DELETE CASCADE,ip TEXT NOT NULL,hostname TEXT NOT NULL DEFAULT '',mac TEXT NOT NULL DEFAULT '',state TEXT NOT NULL DEFAULT 'unknown',note TEXT NOT NULL DEFAULT '',reachability TEXT NOT NULL DEFAULT 'unknown',last_seen TEXT NOT NULL DEFAULT '',version INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(subnet_id,ip));
	CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,time TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,detail TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY REFERENCES audit(id),attempts INTEGER NOT NULL DEFAULT 0,next_try INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,kind TEXT NOT NULL,actor TEXT NOT NULL,target TEXT NOT NULL,status TEXT NOT NULL,payload TEXT NOT NULL,result TEXT NOT NULL DEFAULT '',created TEXT NOT NULL);
	CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status,created);
	CREATE TABLE IF NOT EXISTS observations(provider TEXT NOT NULL,kind TEXT NOT NULL,object_key TEXT NOT NULL,subnet_id TEXT NOT NULL DEFAULT '',ip TEXT NOT NULL DEFAULT '',data TEXT NOT NULL,observed_at TEXT NOT NULL,PRIMARY KEY(provider,kind,object_key));
	CREATE TABLE IF NOT EXISTS auth_flows(state TEXT PRIMARY KEY,nonce TEXT NOT NULL,verifier TEXT NOT NULL,expires INTEGER NOT NULL);
	CREATE TABLE IF NOT EXISTS saml_replay(id TEXT PRIMARY KEY,expires INTEGER NOT NULL);
	CREATE TABLE IF NOT EXISTS dhcp_state(provider TEXT NOT NULL,subnet_id TEXT NOT NULL REFERENCES subnets(id) ON DELETE CASCADE,kind TEXT NOT NULL,ip TEXT NOT NULL,state TEXT NOT NULL,mac TEXT NOT NULL,hostname TEXT NOT NULL,observed TEXT NOT NULL,expires TEXT NOT NULL,PRIMARY KEY(provider,subnet_id,kind,ip));
	`); err != nil {
		db.Close()
		return nil, err
	}
	var version int
	if err = db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 1 {
		db.Close()
		return nil, errors.New("unsupported database schema")
	}
	// Never blindly replay an external change whose outcome is uncertain.
	_, err = db.Exec("UPDATE jobs SET status='interrupted',result='Process stopped during execution; verify external state before creating another job' WHERE status='running'")
	if err != nil {
		db.Close()
		return nil, err
	}
	keepLock = true
	return &Store{DB: db, lock: lock}, nil
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func listSubnets(ctx context.Context, q queryer) ([]Subnet, error) {
	rows, err := q.QueryContext(ctx, "SELECT id,name,cidr,site,vrf,vlan,description,scan_enabled,version FROM subnets ORDER BY site,cidr")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Subnet{}
	for rows.Next() {
		var s Subnet
		if err = rows.Scan(&s.ID, &s.Name, &s.CIDR, &s.Site, &s.VRF, &s.VLAN, &s.Description, &s.ScanEnabled, &s.Version); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func (s *Store) subnet(ctx context.Context, id string) (Subnet, error) {
	var n Subnet
	err := s.DB.QueryRowContext(ctx, "SELECT id,name,cidr,site,vrf,vlan,description,scan_enabled,version FROM subnets WHERE id=?", id).Scan(&n.ID, &n.Name, &n.CIDR, &n.Site, &n.VRF, &n.VLAN, &n.Description, &n.ScanEnabled, &n.Version)
	return n, err
}
func validateSubnet(n *Subnet, existing []Subnet) error {
	p, err := netip.ParsePrefix(n.CIDR)
	if err != nil {
		return errors.New("invalid CIDR")
	}
	if p.Addr().Is4In6() {
		return errors.New("IPv4-mapped IPv6 prefixes are not supported")
	}
	n.CIDR = p.Masked().String()
	n.Name = strings.TrimSpace(n.Name)
	n.Site = strings.TrimSpace(n.Site)
	if n.Name == "" || n.Site == "" || len(n.Name) > 200 || len(n.Site) > 200 || len(n.VRF) > 200 || len(n.Description) > 4000 {
		return errors.New("name and site required; field length exceeded")
	}
	if n.VLAN < 0 || n.VLAN > 4094 {
		return errors.New("VLAN must be 0..4094")
	}
	for _, x := range existing {
		if x.ID == n.ID || x.VRF != n.VRF {
			continue
		}
		xp, _ := netip.ParsePrefix(x.CIDR)
		if p.Overlaps(xp) {
			return fmt.Errorf("overlaps subnet %s in routing domain %s", x.Name, n.VRF)
		}
	}
	return nil
}
func allowed(u User, site string, write bool) bool {
	if u.Disabled {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	if write && u.Role != "operator" {
		return false
	}
	if u.Role != "operator" && u.Role != "viewer" && u.Role != "auditor" {
		return false
	}
	for _, x := range u.Sites {
		if x == site {
			return true
		}
	}
	return false
}
func validRole(s string) bool {
	return s == "admin" || s == "operator" || s == "viewer" || s == "auditor"
}
func auditTx(ctx context.Context, tx *sql.Tx, u, action, target, detail string, siem bool, limit int) error {
	id := newID()
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit VALUES(?,?,?,?,?,?)", id, now(), u, action, target, detail); err != nil {
		return err
	}
	if siem {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM outbox").Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return errors.New("SIEM queue full: restore delivery before making changes")
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO outbox(id) VALUES(?)", id)
		return err
	}
	return nil
}
func (s *Store) userByID(ctx context.Context, id string) (User, error) {
	var u User
	var sites string
	err := s.DB.QueryRowContext(ctx, "SELECT id,name,role,sites,disabled FROM users WHERE id=?", id).Scan(&u.ID, &u.Name, &u.Role, &sites, &u.Disabled)
	if err == nil {
		err = json.Unmarshal([]byte(sites), &u.Sites)
	}
	return u, err
}
