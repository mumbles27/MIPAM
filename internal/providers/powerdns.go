package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

type rrset struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     uint32   `json:"ttl"`
	Records []record `json:"records"`
}
type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

func fqdn(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") + "." }
func recordName(r Request) string {
	if r.Name == "@" || r.Name == r.Zone || fqdn(r.Name) == fqdn(r.Zone) {
		return fqdn(r.Zone)
	}
	if strings.HasSuffix(fqdn(r.Name), "."+fqdn(r.Zone)) {
		return fqdn(r.Name)
	}
	return fqdn(r.Name + "." + strings.TrimSuffix(r.Zone, "."))
}
func pdnsPath(c Config, r Request) string {
	server := c.Server
	if server == "" {
		server = "localhost"
	}
	return "/api/v1/servers/" + url.PathEscape(server) + "/zones/" + url.PathEscape(fqdn(r.Zone))
}
func pdnsRead(ctx context.Context, c Config, r Request) (json.RawMessage, error) {
	if r.Kind != "dns" {
		return nil, errors.New("PowerDNS supports DNS only")
	}
	raw, err := request(ctx, c, "GET", pdnsPath(c, r), nil)
	if err != nil {
		return nil, err
	}
	if r.Name == "" {
		return raw, nil
	}
	var zone struct {
		RRSets []rrset `json:"rrsets"`
	}
	if err = json.Unmarshal(raw, &zone); err != nil {
		return nil, err
	}
	out := []rrset{}
	for _, x := range zone.RRSets {
		if fqdn(x.Name) == recordName(r) && (r.Type == "" || x.Type == r.Type) {
			out = append(out, x)
		}
	}
	return json.Marshal(out)
}
func pdnsApply(ctx context.Context, c Config, r Request) (json.RawMessage, error) {
	if r.Kind != "dns" {
		return nil, errors.New("PowerDNS supports DNS only")
	}
	before, err := pdnsRead(ctx, c, r)
	if err != nil {
		return nil, err
	}
	var old []rrset
	if err = json.Unmarshal(before, &old); err != nil {
		return nil, err
	}
	if r.Action == "create" && len(old) > 0 {
		return nil, errors.New("RRset already exists; use update")
	}
	if r.Action != "create" && len(old) == 0 {
		return nil, errors.New("RRset does not exist")
	}
	// Single-record editing must never silently discard other RRset members.
	if len(old) > 0 && len(old[0].Records) > 1 {
		return nil, errors.New("multi-record RRsets are read-only in this editor")
	}
	change := "REPLACE"
	records := []record{{Content: r.Content}}
	if r.Action == "delete" {
		change = "DELETE"
		records = []record{}
	}
	body := map[string]any{"rrsets": []any{map[string]any{"name": recordName(r), "type": r.Type, "ttl": r.TTL, "changetype": change, "records": records}}}
	if _, err = request(ctx, c, "PATCH", pdnsPath(c, r), body); err != nil {
		return nil, err
	}
	after, err := pdnsRead(ctx, c, r)
	if err != nil {
		return nil, errors.New("write submitted; read-back failed; reconcile before retry")
	}
	var got []rrset
	if err = json.Unmarshal(after, &got); err != nil {
		return nil, err
	}
	if r.Action == "delete" {
		if len(got) != 0 {
			return nil, errors.New("delete read-back mismatch")
		}
	} else {
		if len(got) != 1 || len(got[0].Records) != 1 || got[0].Records[0].Content != r.Content || got[0].TTL != r.TTL {
			return nil, errors.New("write read-back mismatch; inspect external state")
		}
	}
	return after, nil
}
