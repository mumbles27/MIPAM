package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

type scanRequest struct {
	Start string `json:"start"`
	Limit int    `json:"limit"`
}

func scanTargets(n Subnet, req scanRequest) ([]netip.Addr, error) {
	p, _ := netip.ParsePrefix(n.CIDR)
	start := p.Addr()
	var err error
	if req.Start != "" {
		start, err = netip.ParseAddr(req.Start)
		if err != nil || !p.Contains(start) {
			return nil, errors.New("scan start outside subnet")
		}
	}
	if req.Limit < 1 || req.Limit > 1024 {
		return nil, errors.New("scan limit must be 1..1024")
	}
	if p.Addr().Is6() && req.Start == "" {
		return nil, errors.New("IPv6 requires an explicit start address")
	}
	out := []netip.Addr{}
	for ip := start; ip.IsValid() && p.Contains(ip) && len(out) < req.Limit; ip = ip.Next() {
		if !reservedIP(p, ip) {
			out = append(out, ip)
		}
	}
	return out, nil
}
func (a *Server) queueScan(w http.ResponseWriter, r *http.Request) {
	n, ok := a.subnetAccess(w, r, true)
	if !ok {
		return
	}
	if !n.ScanEnabled {
		fail(w, 403, "enable scanning on this subnet first")
		return
	}
	req := scanRequest{Limit: 256}
	if !decode(w, r, &req) {
		return
	}
	targets, err := scanTargets(n, req)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	id, err := a.enqueue(r.Context(), principal(r).ID, "scan", n.ID, "queued", string(mustJSON(req)))
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 202, map[string]any{"job_id": id, "targets": len(targets)})
}
func (a *Server) scan(ctx context.Context, u User, j Job) (string, error) {
	n, err := a.S.subnet(ctx, j.Target)
	if err != nil {
		return "", err
	}
	if !allowed(u, n.Site, true) || !n.ScanEnabled {
		return "", errors.New("scan authorization revoked")
	}
	var req scanRequest
	if err = json.Unmarshal([]byte(j.Payload), &req); err != nil {
		return "", err
	}
	targets, err := scanTargets(n, req)
	if err != nil {
		return "", err
	}
	ping, err := exec.LookPath("ping")
	if err != nil {
		return "", errors.New("system ping executable is required")
	}
	type result struct {
		IP, Reach string
		Err       error
	}
	input := make(chan netip.Addr)
	output := make(chan result, len(targets))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range input {
				c, cancel := context.WithTimeout(ctx, 3*time.Second)
				args := []string{"-n", "-c", "1", "-W", "1", ip.String()}
				if runtime.GOOS == "windows" {
					args = []string{"-n", "1", "-w", "1000", ip.String()}
				}
				err := exec.CommandContext(c, ping, args...).Run()
				timedOut := errors.Is(c.Err(), context.DeadlineExceeded)
				cancel()
				reach := "reachable"
				if err != nil {
					var exit *exec.ExitError
					if errors.As(err, &exit) && exit.ExitCode() == 1 {
						reach = "no-response"
						err = nil
					} else if timedOut && ctx.Err() == nil {
						reach = "no-response"
						err = nil
					}
				}
				output <- result{ip.String(), reach, err}
			}
		}()
	}
	go func() {
		defer close(input)
		pace := time.NewTicker(50 * time.Millisecond)
		defer pace.Stop()
		for _, ip := range targets {
			select {
			case <-ctx.Done():
				return
			case <-pace.C:
			}
			select {
			case input <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(output) }()
	count, reachable, failures := 0, 0, 0
	for result := range output {
		if result.Err != nil {
			failures++
			continue
		}
		count++
		lastSeen := ""
		if result.Reach == "reachable" {
			lastSeen = now()
			reachable++
		}
		_, err = a.S.DB.ExecContext(ctx, `INSERT INTO addresses(subnet_id,ip,reachability,last_seen) VALUES(?,?,?,?) ON CONFLICT(subnet_id,ip) DO UPDATE SET reachability=excluded.reachability,last_seen=CASE WHEN excluded.last_seen<>'' THEN excluded.last_seen ELSE addresses.last_seen END`, n.ID, result.IP, result.Reach, lastSeen)
		if err != nil {
			return "", err
		}
	}
	summary := fmt.Sprintf("Probed %d addresses; %d replied; %d probe errors. Allocation states unchanged.", count, reachable, failures)
	if ctx.Err() != nil {
		return summary, ctx.Err()
	}
	if failures > 0 {
		return summary, fmt.Errorf("%s Check ping privileges and platform configuration", summary)
	}
	return summary, nil
}
func (a *Server) discoverNeighbors(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req struct {
		Device string `json:"device"`
	}
	if !decode(w, r, &req) {
		return
	}
	var config *SNMPConfig
	for i := range a.C.SNMP {
		if a.C.SNMP[i].ID == req.Device {
			config = &a.C.SNMP[i]
			break
		}
	}
	if config == nil {
		fail(w, 404, "SNMP device not configured")
		return
	}
	if os.Getenv(config.AuthEnv) == "" || os.Getenv(config.PrivacyEnv) == "" {
		fail(w, 400, "SNMPv3 secret environment variables not set")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	client := &gosnmp.GoSNMP{Target: config.Host, Port: 161, Version: gosnmp.Version3, Timeout: 3 * time.Second, Retries: 1, MaxOids: gosnmp.MaxOids, MaxRepetitions: 20, Context: ctx, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv, SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: config.User, AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: os.Getenv(config.AuthEnv), PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: os.Getenv(config.PrivacyEnv)}}
	if err := client.Connect(); err != nil {
		fail(w, 502, "SNMP connection failed")
		return
	}
	defer client.Conn.Close()
	out := []map[string]string{}
	warnings := []string{}
	for _, table := range []struct{ Name, OID string }{{"lldp", "1.0.8802.1.1.2.1.4.1.1"}, {"cdp", "1.3.6.1.4.1.9.9.23.1.2.1.1"}} {
		err := client.BulkWalk(table.OID, func(p gosnmp.SnmpPDU) error {
			if len(out) >= 5000 {
				return errors.New("neighbor response limit reached")
			}
			value := fmt.Sprint(p.Value)
			if b, ok := p.Value.([]byte); ok {
				if utf8.Valid(b) && !strings.ContainsRune(string(b), 0) {
					value = string(b)
				} else {
					value = hex.EncodeToString(b)
				}
			}
			out = append(out, map[string]string{"protocol": table.Name, "oid": p.Name, "value": value})
			return nil
		})
		if err != nil {
			warnings = append(warnings, table.Name+" collection failed or truncated")
		}
	}
	data := mustJSON(map[string]any{"device": req.Device, "entries": out, "warnings": warnings, "observed_at": now()})
	if len(out) == 0 {
		fail(w, 502, "no neighbor data returned; check SNMP credentials, MIB support and network reachability")
		return
	}
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), "INSERT INTO observations(provider,kind,object_key,data,observed_at) VALUES(?,'neighbors','tables',?,?) ON CONFLICT(provider,kind,object_key) DO UPDATE SET data=excluded.data,observed_at=excluded.observed_at", req.Device, string(data), now())
	if err == nil {
		err = a.auditIn(r.Context(), tx, principal(r).ID, "neighbors.collect", req.Device, "SNMPv3 authPriv")
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, data)
}
