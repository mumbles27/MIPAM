package app

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
)

func (a *Server) getSubnets(w http.ResponseWriter, r *http.Request) {
	all, err := listSubnets(r.Context(), a.S.DB)
	if err != nil {
		a.internal(w, err)
		return
	}
	out := []Subnet{}
	for _, n := range all {
		if allowed(principal(r), n.Site, false) {
			out = append(out, n)
		}
	}
	respond(w, 200, out)
}
func (a *Server) saveSubnet(w http.ResponseWriter, r *http.Request) {
	var n Subnet
	if !decode(w, r, &n) {
		return
	}
	u := principal(r)
	if !allowed(u, n.Site, true) {
		fail(w, 403, "site write permission required")
		return
	}
	n.ID = r.PathValue("id")
	if n.ID != "" {
		old, err := a.S.subnet(r.Context(), n.ID)
		if err != nil {
			fail(w, 404, "subnet not found")
			return
		}
		if !allowed(u, old.Site, true) {
			fail(w, 403, "site write permission required")
			return
		}
		if old.CIDR != n.CIDR || old.VRF != n.VRF {
			fail(w, 409, "CIDR and routing domain are immutable; create a replacement subnet")
			return
		}
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
	if err = validateSubnet(&n, all); err != nil {
		fail(w, 400, err.Error())
		return
	}
	action := "subnet.create"
	if n.ID == "" {
		n.ID = newID()
		n.Version = 1
		_, err = tx.ExecContext(r.Context(), "INSERT INTO subnets VALUES(?,?,?,?,?,?,?,?,?)", n.ID, n.Name, n.CIDR, n.Site, n.VRF, n.VLAN, n.Description, n.ScanEnabled, n.Version)
	} else {
		action = "subnet.update"
		var res sql.Result
		res, err = tx.ExecContext(r.Context(), "UPDATE subnets SET name=?,site=?,vlan=?,description=?,scan_enabled=?,version=version+1 WHERE id=? AND version=?", n.Name, n.Site, n.VLAN, n.Description, n.ScanEnabled, n.ID, n.Version)
		if err == nil {
			count, _ := res.RowsAffected()
			if count != 1 {
				fail(w, 409, "subnet changed; reload before saving")
				return
			}
			n.Version++
		}
	}
	detail, _ := json.Marshal(n)
	if err == nil {
		err = a.auditIn(r.Context(), tx, u.ID, action, n.ID, string(detail))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, n)
}
func (a *Server) subnetAccess(w http.ResponseWriter, r *http.Request, write bool) (Subnet, bool) {
	n, err := a.S.subnet(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, 404, "subnet not found")
		return n, false
	}
	if !allowed(principal(r), n.Site, write) {
		_ = a.audit(r.Context(), principal(r).ID, "authorization.denied", n.ID, "")
		fail(w, 403, "site permission required")
		return n, false
	}
	return n, true
}
func (a *Server) deleteSubnet(w http.ResponseWriter, r *http.Request) {
	n, ok := a.subnetAccess(w, r, true)
	if !ok {
		return
	}
	if r.URL.Query().Get("confirm") != n.CIDR {
		fail(w, 400, "confirm must match the CIDR")
		return
	}
	v, _ := strconv.Atoi(r.URL.Query().Get("version"))
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(r.Context(), "DELETE FROM subnets WHERE id=? AND version=?", n.ID, v)
	if err != nil {
		a.internal(w, err)
		return
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		fail(w, 409, "subnet changed; reload")
		return
	}
	detail, _ := json.Marshal(n)
	if err = a.auditIn(r.Context(), tx, principal(r).ID, "subnet.delete", n.ID, string(detail)); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func addresses(rows *sql.Rows) ([]Address, error) {
	defer rows.Close()
	out := []Address{}
	for rows.Next() {
		var n Address
		if err := rows.Scan(&n.SubnetID, &n.IP, &n.Hostname, &n.MAC, &n.State, &n.Note, &n.Reachability, &n.LastSeen, &n.Version); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func reservedIP(p netip.Prefix, ip netip.Addr) bool {
	if !ip.Is4() || p.Bits() >= 31 {
		return false
	}
	b := ip.As4()
	v := binary.BigEndian.Uint32(b[:])
	mask := uint32(0xffffffff) << uint(32-p.Bits())
	return ip == p.Masked().Addr() || v&^mask == ^mask
}
func (a *Server) getAddresses(w http.ResponseWriter, r *http.Request) {
	n, ok := a.subnetAccess(w, r, false)
	if !ok {
		return
	}
	rows, err := a.S.DB.QueryContext(r.Context(), "SELECT subnet_id,ip,hostname,mac,state,note,reachability,last_seen,version FROM addresses WHERE subnet_id=?", n.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	saved, err := addresses(rows)
	if err != nil {
		a.internal(w, err)
		return
	}
	p, _ := netip.ParsePrefix(n.CIDR)
	start := p.Addr()
	if v := r.URL.Query().Get("start"); v != "" {
		start, err = netip.ParseAddr(v)
		if err != nil || !p.Contains(start) {
			fail(w, 400, "start address outside subnet")
			return
		}
	}
	limit := 256
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil || limit < 1 || limit > 1024 {
			fail(w, 400, "limit must be 1..1024")
			return
		}
	}
	index := map[string]Address{}
	counts := map[string]int{}
	for _, x := range saved {
		index[x.IP] = x
		counts[x.State]++
	}
	out := []Address{}
	next := ""
	if p.Addr().Is6() {
		// IPv6 is sparse: paginate only explicitly known addresses.
		for _, x := range saved {
			ip, _ := netip.ParseAddr(x.IP)
			if ip.Compare(start) >= 0 {
				out = append(out, x)
			}
		}
		sortAddresses(out)
		if len(out) > limit {
			next = out[limit].IP
			out = out[:limit]
		}
	} else {
		ip := start
		for len(out) < limit && ip.IsValid() && p.Contains(ip) {
			x, found := index[ip.String()]
			if !found {
				x = Address{SubnetID: n.ID, IP: ip.String(), State: "unknown", Reachability: "unknown"}
			}
			if reservedIP(p, ip) {
				x.State = "network"
			}
			out = append(out, x)
			ip = ip.Next()
		}
		if ip.IsValid() && p.Contains(ip) {
			next = ip.String()
		}
	}
	if err = a.overlayDHCP(r.Context(), n.ID, out); err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, map[string]any{"subnet": n, "addresses": out, "next": next, "counts": counts, "recorded": len(saved), "sparse": p.Addr().Is6()})
}
func validateAddress(n Subnet, x *Address) error {
	p, _ := netip.ParsePrefix(n.CIDR)
	ip, err := netip.ParseAddr(x.IP)
	if err != nil || !p.Contains(ip) || ip.Is4In6() {
		return errors.New("address outside subnet")
	}
	if reservedIP(p, ip) {
		return errors.New("network/broadcast addresses cannot be assigned")
	}
	x.IP = ip.String()
	switch x.State {
	case "unknown", "available", "static", "reserved", "excluded", "conflict":
	default:
		return errors.New("invalid inventory state; leases are provider observations")
	}
	if len(x.Hostname) > 253 || len(x.Note) > 4000 {
		return errors.New("field too long")
	}
	if x.MAC != "" {
		mac, err := net.ParseMAC(x.MAC)
		if err != nil {
			return errors.New("invalid MAC")
		}
		x.MAC = mac.String()
	}
	return nil
}
func (a *Server) saveAddress(w http.ResponseWriter, r *http.Request) {
	n, ok := a.subnetAccess(w, r, true)
	if !ok {
		return
	}
	var x Address
	if !decode(w, r, &x) {
		return
	}
	x.SubnetID = n.ID
	x.IP = r.PathValue("ip")
	if err := validateAddress(n, &x); err != nil {
		fail(w, 400, err.Error())
		return
	}
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer tx.Rollback()
	before := ""
	_ = tx.QueryRowContext(r.Context(), "SELECT json_object('state',state,'hostname',hostname,'mac',mac,'note',note) FROM addresses WHERE subnet_id=? AND ip=?", n.ID, x.IP).Scan(&before)
	if x.Version == 0 {
		_, err = tx.ExecContext(r.Context(), "INSERT INTO addresses(subnet_id,ip,hostname,mac,state,note) VALUES(?,?,?,?,?,?)", n.ID, x.IP, x.Hostname, x.MAC, x.State, x.Note)
		if err != nil {
			fail(w, 409, "address already recorded; reload")
			return
		}
		x.Version = 1
	} else {
		var res sql.Result
		res, err = tx.ExecContext(r.Context(), "UPDATE addresses SET hostname=?,mac=?,state=?,note=?,version=version+1 WHERE subnet_id=? AND ip=? AND version=?", x.Hostname, x.MAC, x.State, x.Note, n.ID, x.IP, x.Version)
		if err == nil {
			c, _ := res.RowsAffected()
			if c != 1 {
				fail(w, 409, "address changed; reload")
				return
			}
			x.Version++
		}
	}
	after, _ := json.Marshal(x)
	if err == nil {
		err = a.auditIn(r.Context(), tx, principal(r).ID, "address.save", n.ID+"/"+x.IP, fmt.Sprintf(`{"before":%s,"after":%s}`, jsonOrNull(before), after))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, x)
}
func jsonOrNull(s string) string {
	if s == "" {
		return "null"
	}
	return s
}
func (a *Server) deleteAddress(w http.ResponseWriter, r *http.Request) {
	n, ok := a.subnetAccess(w, r, true)
	if !ok {
		return
	}
	v, _ := strconv.Atoi(r.URL.Query().Get("version"))
	ip := r.PathValue("ip")
	tx, err := a.S.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, err)
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(r.Context(), "DELETE FROM addresses WHERE subnet_id=? AND ip=? AND version=?", n.ID, ip, v)
	if err != nil {
		a.internal(w, err)
		return
	}
	count, _ := res.RowsAffected()
	if count != 1 {
		fail(w, 409, "address changed; reload")
		return
	}
	if err = a.auditIn(r.Context(), tx, principal(r).ID, "address.delete", n.ID+"/"+ip, ""); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
