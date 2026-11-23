package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"mipam/internal/providers"
)

func (a *Server) provider(id string) (providers.Config, error) {
	for _, c := range a.C.Providers {
		if c.ID == id {
			return providers.Config{Kind: c.Kind, URL: c.URL, Server: c.Server, Secret: os.Getenv(c.SecretEnv), AllowWrites: c.AllowWrites, CAFile: c.CAFile, CertFile: c.CertFile, KeyFile: c.KeyFile}, nil
		}
	}
	return providers.Config{}, errors.New("provider not configured")
}
func (a *Server) getProviders(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	out := []map[string]any{}
	for _, p := range a.C.Providers {
		out = append(out, map[string]any{"id": p.ID, "kind": p.Kind, "writes": p.AllowWrites, "capabilities": map[string]string{
			"windows":  "DNS A/AAAA/CNAME/PTR CRUD; DHCPv4 scope create/read/rename/delete and reservation CRUD; leases and AD computers read-only",
			"kea":      "DHCP configuration and paged leases read; reservation CRUD (required hooks)",
			"powerdns": "DNS record CRUD; multi-record RRsets read-only",
			"bind":     "Explicit DNS record lookup and RFC2136/TSIG CRUD; multi-record RRsets read-only",
		}[p.Kind]})
	}
	respond(w, 200, out)
}

type changePayload struct {
	Request     providers.Request `json:"request"`
	Before      json.RawMessage   `json:"before"`
	Fingerprint string            `json:"fingerprint"`
}

func canonical(raw json.RawMessage) string {
	var x any
	if json.Unmarshal(raw, &x) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(x)
	return string(b)
}
func (a *Server) readProvider(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	c, err := a.provider(r.PathValue("id"))
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	var req providers.Request
	if !decode(w, r, &req) {
		return
	}
	req.Action = "read"
	linkID := r.URL.Query().Get("subnet")
	var linked Subnet
	if linkID != "" {
		linked, err = a.S.subnet(r.Context(), linkID)
		if err != nil {
			fail(w, 404, "linked subnet not found")
			return
		}
		if req.Kind != "lease" && req.Kind != "reservation" {
			fail(w, 400, "only DHCP lease/reservation reads can be linked")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	data, err := providers.Read(ctx, c, req)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	// Read snapshots are separate from user-assigned inventory, never overwrite it.
	key := digest(canonical(mustJSON(req)))
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), "INSERT INTO observations(provider,kind,object_key,ip,data,observed_at) VALUES(?,?,?,?,?,?) ON CONFLICT(provider,kind,object_key) DO UPDATE SET data=excluded.data,observed_at=excluded.observed_at", r.PathValue("id"), req.Kind, key, req.IP, string(data), now())
	if err == nil && linkID != "" {
		err = syncDHCP(r.Context(), tx, r.PathValue("id"), c.Kind, linked, req, data)
	}
	if err == nil {
		err = a.auditIn(r.Context(), tx, principal(r).ID, "provider.read", r.PathValue("id"), string(mustJSON(req)))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	response := map[string]any{"data": data, "observed_at": now(), "linked_subnet": linkID}
	if req.Kind == "scope" {
		response["suggested_subnets"] = scopeCandidates(c.Kind, data)
	}
	respond(w, 200, response)
}
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func (a *Server) previewProvider(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	c, err := a.provider(r.PathValue("id"))
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	if !c.AllowWrites {
		fail(w, 403, "writes disabled in server configuration")
		return
	}
	var req providers.Request
	if !decode(w, r, &req) {
		return
	}
	if err = req.Validate(); err != nil || req.Action == "read" {
		fail(w, 400, "valid mutation request required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	before, err := providers.Read(ctx, c, req)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	payload := changePayload{Request: req, Before: before, Fingerprint: digest(canonical(before))}
	id, err := a.enqueue(r.Context(), principal(r).ID, "provider", r.PathValue("id"), "preview", string(mustJSON(payload)))
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, map[string]any{"job_id": id, "before": before, "requested": req, "warning": "External changes are not atomic with MIPAM or other services. Confirm this exact job ID to queue it. Preview expires after 10 minutes."})
}
func (a *Server) enqueue(ctx context.Context, actor, kind, target, status, payload string) (string, error) {
	id := newID()
	tx, err := a.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var pending int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE status IN ('queued','running','preview')").Scan(&pending); err != nil {
		return "", err
	}
	if pending >= 1000 {
		return "", errors.New("job queue limit reached")
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO jobs(id,kind,actor,target,status,payload,created) VALUES(?,?,?,?,?,?,?)", id, kind, actor, target, status, payload, now())
	if err == nil {
		err = a.auditIn(ctx, tx, actor, "job."+status, id, payload)
	}
	if err == nil {
		err = tx.Commit()
	}
	return id, err
}
func (a *Server) confirmJob(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	if req.Confirm != id {
		fail(w, 400, "confirm must equal job ID")
		return
	}
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(r.Context(), "UPDATE jobs SET status='queued' WHERE id=? AND status='preview' AND actor=? AND created>?", id, principal(r).ID, time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339))
	if err != nil {
		a.internal(w, err)
		return
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		fail(w, 409, "preview expired, already confirmed, or owned by another user")
		return
	}
	if err = a.auditIn(r.Context(), tx, principal(r).ID, "job.confirm", id, ""); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, map[string]string{"status": "queued"})
}
func (a *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u := principal(r)
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(r.Context(), "UPDATE jobs SET status='cancelled' WHERE id=? AND (actor=? OR ?='admin') AND status IN ('queued','preview')", id, u.ID, u.Role)
	if err != nil {
		a.internal(w, err)
		return
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		fail(w, 409, "only pending jobs you own can be cancelled")
		return
	}
	if err = a.auditIn(r.Context(), tx, u.ID, "job.cancel", id, ""); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func (a *Server) getJobs(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	rows, err := a.S.DB.QueryContext(r.Context(), "SELECT id,kind,actor,target,status,payload,result,created FROM jobs WHERE actor=? OR ?='admin' ORDER BY rowid DESC LIMIT 200", u.ID, u.Role)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		if err = rows.Scan(&j.ID, &j.Kind, &j.Actor, &j.Target, &j.Status, &j.Payload, &j.Result, &j.Created); err != nil {
			a.internal(w, err)
			return
		}
		out = append(out, j)
	}
	if err = rows.Err(); err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, out)
}
func (a *Server) getObservations(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	rows, err := a.S.DB.QueryContext(r.Context(), "SELECT provider,kind,data,observed_at FROM observations ORDER BY observed_at DESC LIMIT 100")
	if err != nil {
		a.internal(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var provider, kind, data, observed string
		if err = rows.Scan(&provider, &kind, &data, &observed); err != nil {
			a.internal(w, err)
			return
		}
		out = append(out, map[string]any{"provider": provider, "kind": kind, "data": json.RawMessage(data), "observed_at": observed})
	}
	if err = rows.Err(); err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, out)
}
