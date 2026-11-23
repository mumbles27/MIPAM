package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	Kind, URL, Server, Secret, CAFile, CertFile, KeyFile string
	AllowWrites                                          bool
}

// Request is deliberately typed: adapters never accept arbitrary script/command text.
type Request struct {
	Kind     string `json:"kind"`
	Action   string `json:"action"`
	Zone     string `json:"zone,omitempty"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Content  string `json:"content,omitempty"`
	TTL      uint32 `json:"ttl,omitempty"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	ScopeID  string `json:"scope_id,omitempty"`
	CIDR     string `json:"cidr,omitempty"`
	Start    string `json:"start,omitempty"`
	End      string `json:"end,omitempty"`
	SubnetID uint32 `json:"subnet_id,omitempty"`
}

var dnsName = regexp.MustCompile(`^[a-zA-Z0-9_.*-]+(?:\.[a-zA-Z0-9_*-]+)*\.?$`)

func (r Request) Validate() error {
	switch r.Action {
	case "read", "create", "update", "delete":
	default:
		return errors.New("unsupported action")
	}
	switch r.Kind {
	case "dns", "scope", "reservation", "lease", "ad-computer":
	default:
		return errors.New("unsupported resource kind")
	}
	if r.Kind == "lease" || r.Kind == "ad-computer" {
		if r.Action != "read" {
			return errors.New("leases and directory data are read-only")
		}
		return nil
	}
	if r.Kind == "dns" {
		if !dnsName.MatchString(r.Zone) || len(r.Zone) > 253 {
			return errors.New("valid DNS zone required")
		}
		if r.Name != "" && r.Name != "@" && (!dnsName.MatchString(r.Name) || len(r.Name) > 253) {
			return errors.New("invalid DNS name")
		}
		switch r.Type {
		case "", "A", "AAAA", "CNAME", "PTR", "TXT", "MX", "SRV":
		default:
			return errors.New("unsupported DNS record type")
		}
		if r.Action != "read" {
			if r.Name == "" || r.Type == "" {
				return errors.New("DNS name and type required")
			}
			if r.Action != "delete" {
				if r.Content == "" || len(r.Content) > 4096 || strings.ContainsAny(r.Content, "\x00\r\n") {
					return errors.New("invalid DNS content")
				}
				if r.Type == "A" || r.Type == "AAAA" {
					ip, err := netip.ParseAddr(r.Content)
					if err != nil || (r.Type == "A" && !ip.Is4()) || (r.Type == "AAAA" && !ip.Is6()) {
						return errors.New("record address family mismatch")
					}
				}
				if r.TTL < 1 || r.TTL > 604800 {
					return errors.New("TTL must be 1..604800")
				}
			}
		}
	}
	if r.Kind == "scope" {
		if r.ScopeID != "" {
			if _, err := netip.ParseAddr(r.ScopeID); err != nil {
				return errors.New("invalid scope ID")
			}
		}
		if r.Action == "create" {
			p, err := netip.ParsePrefix(r.CIDR)
			if err != nil || !p.Addr().Is4() || p != p.Masked() {
				return errors.New("canonical IPv4 CIDR required")
			}
			if r.ScopeID != "" && r.ScopeID != p.Addr().String() {
				return errors.New("scope_id must equal the CIDR network address")
			}
			start, e1 := netip.ParseAddr(r.Start)
			end, e2 := netip.ParseAddr(r.End)
			if e1 != nil || e2 != nil || !p.Contains(start) || !p.Contains(end) || start.Compare(end) > 0 {
				return errors.New("invalid DHCP range")
			}
			if r.Name == "" || len(r.Name) > 200 {
				return errors.New("scope name required")
			}
		}
		if (r.Action == "update" || r.Action == "delete") && r.ScopeID == "" && r.SubnetID == 0 {
			return errors.New("scope identifier required")
		}
	}
	if r.Kind == "reservation" && r.Action != "read" {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.Is4() {
			return errors.New("IPv4 reservation address required")
		}
		if r.ScopeID == "" && r.SubnetID == 0 {
			return errors.New("scope identifier required")
		}
		if r.Action != "delete" {
			if _, err := net.ParseMAC(r.MAC); err != nil {
				return errors.New("valid MAC required")
			}
		}
	}
	if len(r.Name) > 253 || len(r.ScopeID) > 64 {
		return errors.New("field too long")
	}
	return nil
}
func Client(c Config) (*http.Client, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid CA file")
		}
		t.RootCAs = pool
	}
	if c.CertFile != "" || c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, err
		}
		t.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{TLSClientConfig: t, Proxy: http.ProxyFromEnvironment}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return errors.New("provider redirects are not allowed")
	}}, nil
}
func validEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid provider URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("provider transport requires HTTPS (HTTP allowed only on loopback)")
		}
	}
	return nil
}
func request(ctx context.Context, c Config, method, path string, body any) (json.RawMessage, error) {
	if err := validEndpoint(c.URL); err != nil {
		return nil, err
	}
	client, err := Client(c)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	var data []byte
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Kind == "powerdns" {
		req.Header.Set("X-API-Key", c.Secret)
	}
	if c.Kind == "kea" && c.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.Secret)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("provider connection failed")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 8<<20 {
		return nil, errors.New("provider response exceeds 8 MiB; use narrower query")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned HTTP %d", res.StatusCode)
	}
	if len(raw) == 0 {
		raw = []byte(`null`)
	}
	if !json.Valid(raw) {
		return nil, errors.New("provider response is not JSON")
	}
	return raw, nil
}
func Read(ctx context.Context, c Config, r Request) (json.RawMessage, error) {
	r.Action = "read"
	if err := r.Validate(); err != nil {
		return nil, err
	}
	switch c.Kind {
	case "powerdns":
		return pdnsRead(ctx, c, r)
	case "kea":
		return keaRead(ctx, c, r)
	case "windows":
		if c.CertFile == "" || c.KeyFile == "" {
			return nil, errors.New("Windows connector requires a client certificate")
		}
		return request(ctx, c, "POST", "/execute", r)
	case "bind":
		return bindRead(ctx, c, r)
	default:
		return nil, errors.New("provider not implemented")
	}
}
func Apply(ctx context.Context, c Config, r Request) (json.RawMessage, error) {
	if !c.AllowWrites {
		return nil, errors.New("provider write access disabled")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if r.Action == "read" {
		return nil, errors.New("mutation action required")
	}
	switch c.Kind {
	case "powerdns":
		return pdnsApply(ctx, c, r)
	case "kea":
		return keaApply(ctx, c, r)
	case "windows":
		if c.CertFile == "" || c.KeyFile == "" {
			return nil, errors.New("Windows connector requires a client certificate")
		}
		return request(ctx, c, "POST", "/execute", r)
	case "bind":
		return bindApply(ctx, c, r)
	default:
		return nil, errors.New("provider not implemented")
	}
}
