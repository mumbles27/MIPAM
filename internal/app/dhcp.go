package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"mipam/internal/providers"
)

type DHCPState struct {
	Provider string `json:"provider"`
	Kind     string `json:"kind"`
	IP       string `json:"ip"`
	State    string `json:"state"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	Observed string `json:"observed_at"`
	Expires  string `json:"expires"`
}

func scopeCandidates(kind string, raw json.RawMessage) []Subnet {
	out := []Subnet{}
	if kind == "windows" {
		var scopes []struct {
			ScopeID string `json:"scope_id"`
			Name    string `json:"name"`
			Mask    string `json:"mask"`
		}
		if json.Unmarshal(raw, &scopes) != nil {
			return out
		}
		for _, s := range scopes {
			ip, err := netip.ParseAddr(s.ScopeID)
			mask := net.ParseIP(s.Mask)
			if err != nil || mask == nil || mask.To4() == nil {
				continue
			}
			ones, bits := net.IPMask(mask.To4()).Size()
			if bits != 32 {
				continue
			}
			out = append(out, Subnet{Name: s.Name, CIDR: netip.PrefixFrom(ip, ones).Masked().String(), Site: "IMPORTED"})
		}
	}
	if kind == "kea" {
		var cfg struct {
			DHCP4 struct {
				Subnets []struct {
					ID   int    `json:"id"`
					CIDR string `json:"subnet"`
				} `json:"subnet4"`
			} `json:"Dhcp4"`
		}
		if json.Unmarshal(raw, &cfg) != nil {
			return out
		}
		for _, s := range cfg.DHCP4.Subnets {
			if p, err := netip.ParsePrefix(s.CIDR); err == nil {
				out = append(out, Subnet{Name: "Kea " + p.String(), CIDR: p.Masked().String(), Site: "IMPORTED"})
			}
		}
	}
	return out
}
func normalizeDHCP(kind, resource string, raw json.RawMessage) []DHCPState {
	out := []DHCPState{}
	if kind == "windows" {
		var data []struct {
			IP       string `json:"ip"`
			MAC      string `json:"mac"`
			Name     string `json:"name"`
			Hostname string `json:"hostname"`
			State    string `json:"state"`
			Expires  string `json:"expires"`
		}
		if json.Unmarshal(raw, &data) != nil {
			return out
		}
		for _, x := range data {
			state := "unknown"
			if resource == "reservation" {
				state = "reserved"
			} else if strings.EqualFold(x.State, "Active") || strings.EqualFold(x.State, "ActiveReservation") {
				state = "leased"
			} else if strings.EqualFold(x.State, "Declined") {
				state = "conflict"
			}
			host := x.Hostname
			if host == "" {
				host = x.Name
			}
			out = append(out, DHCPState{IP: x.IP, MAC: x.MAC, Hostname: host, State: state, Expires: x.Expires})
		}
	}
	if kind == "kea" {
		var data struct {
			Reservations []struct {
				IP       string `json:"ip-address"`
				MAC      string `json:"hw-address"`
				Hostname string `json:"hostname"`
			} `json:"hosts"`
			Leases []struct {
				IP       string `json:"ip-address"`
				MAC      string `json:"hw-address"`
				Hostname string `json:"hostname"`
				State    int    `json:"state"`
				CLTT     int64  `json:"cltt"`
				Lifetime int64  `json:"valid-lft"`
			} `json:"leases"`
		}
		if json.Unmarshal(raw, &data) != nil {
			return out
		}
		if resource == "reservation" {
			for _, x := range data.Reservations {
				out = append(out, DHCPState{IP: x.IP, MAC: x.MAC, Hostname: x.Hostname, State: "reserved"})
			}
			if len(out) == 0 {
				var x struct {
					IP       string `json:"ip-address"`
					MAC      string `json:"hw-address"`
					Hostname string `json:"hostname"`
				}
				if json.Unmarshal(raw, &x) == nil && x.IP != "" {
					out = append(out, DHCPState{IP: x.IP, MAC: x.MAC, Hostname: x.Hostname, State: "reserved"})
				}
			}
		} else {
			for _, x := range data.Leases {
				state := "unknown"
				if x.State == 0 {
					state = "leased"
				} else if x.State == 1 {
					state = "conflict"
				}
				out = append(out, DHCPState{IP: x.IP, MAC: x.MAC, Hostname: x.Hostname, State: state, Expires: time.Unix(x.CLTT+x.Lifetime, 0).UTC().Format(time.RFC3339)})
			}
		}
	}
	return out
}
func syncDHCP(ctx context.Context, tx *sql.Tx, provider, kind string, n Subnet, r providers.Request, raw json.RawMessage) error {
	p, _ := netip.ParsePrefix(n.CIDR)
	if kind != "windows" && kind != "kea" {
		return errors.New("provider has no DHCP normalization")
	}
	if kind == "windows" && r.ScopeID != p.Addr().String() {
		return errors.New("Windows scope ID must match linked subnet")
	}
	if r.IP == "" && (kind == "windows" || r.Kind == "reservation") {
		if _, err := tx.ExecContext(ctx, "DELETE FROM dhcp_state WHERE provider=? AND subnet_id=? AND kind=?", provider, n.ID, r.Kind); err != nil {
			return err
		}
	} else if r.Kind == "reservation" {
		if _, err := tx.ExecContext(ctx, "DELETE FROM dhcp_state WHERE provider=? AND subnet_id=? AND kind=? AND ip=?", provider, n.ID, r.Kind, r.IP); err != nil {
			return err
		}
	}
	for _, x := range normalizeDHCP(kind, r.Kind, raw) {
		ip, err := netip.ParseAddr(x.IP)
		if err != nil || !p.Contains(ip) {
			continue
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO dhcp_state VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(provider,subnet_id,kind,ip) DO UPDATE SET state=excluded.state,mac=excluded.mac,hostname=excluded.hostname,observed=excluded.observed,expires=excluded.expires", provider, n.ID, r.Kind, ip.String(), x.State, x.MAC, x.Hostname, now(), x.Expires)
		if err != nil {
			return err
		}
	}
	return nil
}
func (a *Server) overlayDHCP(ctx context.Context, subnet string, out []Address) error {
	rows, err := a.S.DB.QueryContext(ctx, "SELECT provider,kind,ip,state,mac,hostname,observed,expires FROM dhcp_state WHERE subnet_id=?", subnet)
	if err != nil {
		return err
	}
	defer rows.Close()
	index := map[string][]DHCPState{}
	for rows.Next() {
		var x DHCPState
		if err = rows.Scan(&x.Provider, &x.Kind, &x.IP, &x.State, &x.MAC, &x.Hostname, &x.Observed, &x.Expires); err != nil {
			return err
		}
		index[x.IP] = append(index[x.IP], x)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	for i := range out {
		x := &out[i]
		x.DHCP = index[x.IP]
		x.DisplayState = x.State
		for _, ob := range x.DHCP {
			observed, err := time.Parse(time.RFC3339, ob.Observed)
			if err != nil || time.Since(observed) > 15*time.Minute {
				if x.DisplayState == "unknown" || x.DisplayState == "available" {
					x.DisplayState = "stale"
				}
				continue
			}
			if ob.Expires != "" {
				expiry, err := time.Parse(time.RFC3339, ob.Expires)
				if err != nil || time.Now().After(expiry) {
					if x.DisplayState == "unknown" || x.DisplayState == "available" {
						x.DisplayState = "stale"
					}
					continue
				}
			}
			switch ob.State {
			case "leased":
				if x.State == "static" || x.State == "excluded" || x.DisplayState == "conflict" {
					x.DisplayState = "conflict"
				} else {
					x.DisplayState = "leased"
				}
			case "reserved":
				if x.DisplayState != "leased" && x.DisplayState != "conflict" {
					x.DisplayState = "reserved"
				}
			case "conflict":
				x.DisplayState = "conflict"
			}
		}
		if x.State == "network" {
			x.DisplayState = "network"
		}
	}
	return nil
}
