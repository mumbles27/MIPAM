package app

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func sortAddresses(a []Address) {
	slices.SortFunc(a, func(x, y Address) int {
		xx, _ := netip.ParseAddr(x.IP)
		yy, _ := netip.ParseAddr(y.IP)
		return xx.Compare(yy)
	})
}

type subnetImport struct {
	Subnets []Subnet `json:"subnets"`
	CSV     string   `json:"csv"`
	Apply   bool     `json:"apply"`
}

func parseCSV(text string) ([]Subnet, error) {
	reader := csv.NewReader(strings.NewReader(text))
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	index := map[string]int{}
	for i, h := range header {
		if _, ok := index[h]; ok {
			return nil, errors.New("duplicate CSV column")
		}
		index[h] = i
	}
	for _, k := range []string{"name", "cidr", "site"} {
		if _, ok := index[k]; !ok {
			return nil, fmt.Errorf("missing CSV column %s", k)
		}
	}
	for k := range index {
		switch k {
		case "name", "cidr", "site", "vrf", "vlan", "description":
		default:
			return nil, fmt.Errorf("unknown CSV column %s", k)
		}
	}
	out := []Subnet{}
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		get := func(k string) string {
			i, ok := index[k]
			if !ok {
				return ""
			}
			return row[i]
		}
		n := Subnet{Name: get("name"), CIDR: get("cidr"), Site: get("site"), VRF: get("vrf"), Description: get("description")}
		if get("vlan") != "" {
			n.VLAN, err = strconv.Atoi(get("vlan"))
			if err != nil {
				return nil, errors.New("invalid VLAN")
			}
		}
		out = append(out, n)
		if len(out) > 1000 {
			return nil, errors.New("maximum 1000 subnets per import")
		}
	}
	return out, nil
}
func (a *Server) importSubnets(w http.ResponseWriter, r *http.Request) {
	var req subnetImport
	if !decode(w, r, &req) {
		return
	}
	if req.CSV != "" {
		if len(req.Subnets) != 0 {
			fail(w, 400, "provide CSV or subnets, not both")
			return
		}
		var err error
		req.Subnets, err = parseCSV(req.CSV)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	if len(req.Subnets) == 0 || len(req.Subnets) > 1000 {
		fail(w, 400, "provide 1..1000 subnets")
		return
	}
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer tx.Rollback()
	all, err := listSubnets(r.Context(), tx)
	if err != nil {
		a.internal(w, err)
		return
	}
	problems := []string{}
	for i := range req.Subnets {
		n := &req.Subnets[i]
		n.ID = ""
		n.Version = 1
		if !allowed(principal(r), n.Site, true) {
			fail(w, 403, "write permission required for every imported site")
			return
		}
		if e := validateSubnet(n, all); e != nil {
			problems = append(problems, fmt.Sprintf("row %d: %s", i+1, e))
			continue
		}
		n.ID = newID()
		all = append(all, *n)
	}
	if len(problems) > 0 {
		respond(w, 400, map[string]any{"error": "import rejected; nothing changed", "problems": problems})
		return
	}
	if !req.Apply {
		respond(w, 200, map[string]any{"preview": req.Subnets, "count": len(req.Subnets), "message": "Create-only import. Apply revalidates the entire batch atomically; no external DNS/DHCP changes."})
		return
	}
	for _, n := range req.Subnets {
		_, err = tx.ExecContext(r.Context(), "INSERT INTO subnets VALUES(?,?,?,?,?,?,?,?,?)", n.ID, n.Name, n.CIDR, n.Site, n.VRF, n.VLAN, n.Description, n.ScanEnabled, n.Version)
		if err != nil {
			a.internal(w, err)
			return
		}
	}
	detail, _ := json.Marshal(req.Subnets)
	if err = a.auditIn(r.Context(), tx, principal(r).ID, "subnet.import", "inventory", string(detail)); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, map[string]any{"created": len(req.Subnets)})
}
func (a *Server) export(w http.ResponseWriter, r *http.Request) {
	all, err := listSubnets(r.Context(), a.S.DB)
	if err != nil {
		a.internal(w, err)
		return
	}
	subnets := []Subnet{}
	addrs := []Address{}
	for _, n := range all {
		if !allowed(principal(r), n.Site, false) {
			continue
		}
		subnets = append(subnets, n)
		rows, e := a.S.DB.QueryContext(r.Context(), "SELECT subnet_id,ip,hostname,mac,state,note,reachability,last_seen,version FROM addresses WHERE subnet_id=?", n.ID)
		if e != nil {
			a.internal(w, e)
			return
		}
		x, e := addresses(rows)
		if e != nil {
			a.internal(w, e)
			return
		}
		addrs = append(addrs, x...)
	}
	if err = a.audit(r.Context(), principal(r).ID, "inventory.export", "inventory", ""); err != nil {
		a.internal(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="mipam-inventory.json"`)
	respond(w, 200, map[string]any{"schema": 1, "exported_at": now(), "subnets": subnets, "addresses": addrs})
}
func (a *Server) getUsers(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	rows, err := a.S.DB.QueryContext(r.Context(), "SELECT id,name,role,sites,disabled FROM users ORDER BY name")
	if err != nil {
		a.internal(w, err)
		return
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		var sites string
		if err = rows.Scan(&u.ID, &u.Name, &u.Role, &sites, &u.Disabled); err != nil {
			a.internal(w, err)
			return
		}
		if err = json.Unmarshal([]byte(sites), &u.Sites); err != nil {
			a.internal(w, err)
			return
		}
		out = append(out, u)
	}
	if err = rows.Err(); err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, out)
}
func (a *Server) saveUser(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req struct {
		User
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !validRole(req.Role) || len(req.Name) > 200 || strings.TrimSpace(req.Name) == "" {
		fail(w, 400, "valid name and role required")
		return
	}
	if len(req.Sites) > 1000 {
		fail(w, 400, "too many sites")
		return
	}
	req.ID = r.PathValue("id")
	if req.ID == principal(r).ID && (req.Disabled || req.Role != "admin") {
		fail(w, 400, "cannot disable or demote your own admin account")
		return
	}
	hash := ""
	if req.Password != "" {
		if len(req.Password) < 14 || len(req.Password) > 72 {
			fail(w, 400, "password must be 14..72 bytes")
			return
		}
		h, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		if err != nil {
			a.internal(w, err)
			return
		}
		hash = string(h)
	}
	sites, _ := json.Marshal(req.Sites)
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer tx.Rollback()
	if req.ID == "" {
		if hash == "" || strings.Contains(req.Name, ":") {
			fail(w, 400, "local username and password required")
			return
		}
		req.ID = newID()
		_, err = tx.ExecContext(r.Context(), "INSERT INTO users VALUES(?,?,?,?,?,?)", req.ID, req.Name, hash, req.Role, string(sites), req.Disabled)
	} else {
		var existing string
		if e := tx.QueryRowContext(r.Context(), "SELECT name FROM users WHERE id=?", req.ID).Scan(&existing); e != nil {
			fail(w, 404, "user not found")
			return
		}
		if existing != req.Name {
			fail(w, 400, "usernames are immutable")
			return
		}
		if strings.Contains(existing, ":") && hash != "" {
			fail(w, 400, "external identity cannot have a local password")
			return
		}
		_, err = tx.ExecContext(r.Context(), "UPDATE users SET role=?,sites=?,disabled=? WHERE id=?", req.Role, string(sites), req.Disabled, req.ID)
		if err == nil && hash != "" {
			_, err = tx.ExecContext(r.Context(), "UPDATE users SET password=? WHERE id=?", hash, req.ID)
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=?", req.ID)
		}
	}
	detail, _ := json.Marshal(req.User)
	if err == nil {
		err = a.auditIn(r.Context(), tx, principal(r).ID, "user.save", req.ID, string(detail))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, req.User)
}
func (a *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	// Global audit contains cross-site metadata; only global admins may read it.
	if !a.admin(w, r) {
		return
	}
	rows, err := a.S.DB.QueryContext(r.Context(), "SELECT id,time,actor,action,target,detail FROM audit ORDER BY rowid DESC LIMIT 500")
	if err != nil {
		a.internal(w, err)
		return
	}
	defer rows.Close()
	out := []Audit{}
	for rows.Next() {
		var x Audit
		if err = rows.Scan(&x.ID, &x.Time, &x.Actor, &x.Action, &x.Target, &x.Detail); err != nil {
			a.internal(w, err)
			return
		}
		out = append(out, x)
	}
	if err = rows.Err(); err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, out)
}
func (a *Server) status(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var queue, jobs int
	if err := a.S.DB.QueryRowContext(r.Context(), "SELECT count(*) FROM outbox").Scan(&queue); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.S.DB.QueryRowContext(r.Context(), "SELECT count(*) FROM jobs WHERE status='queued'").Scan(&jobs); err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, map[string]any{"siem_pending": queue, "jobs_pending": jobs, "backup_hours": a.C.BackupHours, "version": "0.1.0", "storage": "SQLite", "provider_writes": "admin-only, explicit preview and confirmation"})
}
