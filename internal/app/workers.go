package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"mipam/internal/providers"
)

func (a *Server) RunWorkers(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.siemLoop(ctx) }()
	go func() { defer wg.Done(); a.backupLoop(ctx) }()
	defer wg.Wait()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := a.S.DB.ExecContext(ctx, "UPDATE jobs SET status='expired' WHERE status='preview' AND created<?", time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339)); err != nil {
				slog.Error("preview expiration failed", "error", err)
			}
			if err := a.runJob(ctx); err != nil && !errors.Is(err, sql.ErrNoRows) {
				slog.Error("worker failed", "error", err)
			}
		}
	}
}
func (a *Server) runJob(ctx context.Context) error {
	var j Job
	err := a.S.DB.QueryRowContext(ctx, `UPDATE jobs SET status='running' WHERE id=(SELECT id FROM jobs WHERE status='queued' ORDER BY rowid LIMIT 1) AND status='queued' RETURNING id,kind,actor,target,status,payload,result,created`).Scan(&j.ID, &j.Kind, &j.Actor, &j.Target, &j.Status, &j.Payload, &j.Result, &j.Created)
	if err != nil {
		return err
	}
	u, err := a.S.userByID(ctx, j.Actor)
	result := ""
	if err == nil && u.Disabled {
		err = errors.New("initiating user disabled")
	}
	if err == nil {
		err = a.audit(ctx, u.ID, "job.execute", j.ID, "")
	}
	if err == nil {
		jobCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		switch j.Kind {
		case "scan":
			result, err = a.scan(jobCtx, u, j)
		case "provider":
			if u.Role != "admin" {
				err = errors.New("administrator permission revoked")
				break
			}
			var payload changePayload
			err = json.Unmarshal([]byte(j.Payload), &payload)
			if err != nil {
				break
			}
			var c providers.Config
			c, err = a.provider(j.Target)
			if err != nil {
				break
			}
			if !c.AllowWrites {
				err = errors.New("provider write permission revoked")
				break
			}
			var before json.RawMessage
			before, err = providers.Read(jobCtx, c, payload.Request)
			if err != nil {
				break
			}
			if digest(canonical(before)) != payload.Fingerprint {
				err = errors.New("provider state changed since preview; create a new preview")
				break
			}
			var after json.RawMessage
			after, err = providers.Apply(jobCtx, c, payload.Request)
			if err == nil {
				result = string(after)
			}
		default:
			err = errors.New("unknown job type")
		}
		cancel()
	}
	status := "succeeded"
	if err != nil {
		status = "failed"
		result = err.Error()
	}
	// Completion persists even if the SIEM queue filled after the external mutation.
	endCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, saveErr := a.S.DB.ExecContext(endCtx, "UPDATE jobs SET status=?,result=? WHERE id=?", status, result, j.ID)
	if saveErr != nil {
		return saveErr
	}
	if e := a.audit(endCtx, j.Actor, "job."+status, j.ID, result); e != nil {
		slog.Error("job completion audit delivery failed", "job", j.ID, "error", e)
	}
	return nil
}
func (a *Server) backupLoop(ctx context.Context) {
	if a.C.BackupHours == 0 {
		return
	}
	t := time.NewTicker(time.Duration(a.C.BackupHours) * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			path, err := a.Backup(ctx)
			if err != nil {
				slog.Error("scheduled backup failed", "error", err)
			} else {
				if err = a.audit(ctx, "system", "backup.complete", path, ""); err != nil {
					slog.Error("backup audit failed", "error", err)
				}
			}
		}
	}
}
func (a *Server) siemLoop(ctx context.Context) {
	if a.C.SIEMURL == "" {
		return
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for i := 0; i < 20; i++ {
				if err := a.deliverEvent(ctx); err != nil {
					if !errors.Is(err, sql.ErrNoRows) {
						slog.Warn("SIEM delivery pending", "error", err)
					}
					break
				}
			}
		}
	}
}
func (a *Server) deliverEvent(ctx context.Context) error {
	var event Audit
	var attempts int
	err := a.S.DB.QueryRowContext(ctx, "SELECT a.id,a.time,a.actor,a.action,a.target,a.detail,o.attempts FROM outbox o JOIN audit a ON a.id=o.id WHERE o.next_try<=? ORDER BY a.rowid LIMIT 1", time.Now().Unix()).Scan(&event.ID, &event.Time, &event.Actor, &event.Action, &event.Target, &event.Detail, &attempts)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(event)
	err = a.sendEvent(ctx, raw)
	if err == nil {
		_, err = a.S.DB.ExecContext(ctx, "DELETE FROM outbox WHERE id=?", event.ID)
		return err
	}
	delay := time.Second * time.Duration(1<<min(attempts+1, 10))
	_, saveErr := a.S.DB.ExecContext(ctx, "UPDATE outbox SET attempts=attempts+1,next_try=? WHERE id=?", time.Now().Add(delay).Unix(), event.ID)
	if saveErr != nil {
		return saveErr
	}
	return err
}
func (a *Server) sendEvent(ctx context.Context, raw []byte) error {
	u, err := url.Parse(a.C.SIEMURL)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("invalid SIEM URL")
	}
	if u.Scheme == "tls" {
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}}
		conn, err := d.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return errors.New("TLS syslog connection failed")
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		msg := fmt.Sprintf("<134>1 %s mipam mipam - audit - %s", now(), raw)
		_, err = fmt.Fprintf(conn, "%d %s", len(msg), msg)
		return err
	}
	if u.Scheme != "https" {
		return errors.New("SIEM requires https:// or tls://host:port")
	}
	hec := strings.HasSuffix(u.Path, "/services/collector/event")
	body := raw
	if hec {
		body, _ = json.Marshal(map[string]any{"event": json.RawMessage(raw), "sourcetype": "mipam:audit"})
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return errors.New("SIEM redirects rejected") }}
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := os.Getenv(a.C.SIEMTokenEnv); token != "" {
		prefix := "Bearer "
		if hec {
			prefix = "Splunk "
		}
		req.Header.Set("Authorization", prefix+token)
	}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("SIEM request failed")
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("SIEM HTTP %d", res.StatusCode)
	}
	if hec {
		var result struct {
			Code *int `json:"code"`
		}
		if json.Unmarshal(data, &result) != nil || result.Code == nil || *result.Code != 0 {
			return errors.New("Splunk HEC rejected event")
		}
	}
	return nil
}
