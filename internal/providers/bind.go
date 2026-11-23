package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

func bindQuery(ctx context.Context, c Config, r Request) ([]dns.RR, error) {
	if r.Kind != "dns" || r.Name == "" || r.Type == "" {
		return nil, errors.New("BIND requires an explicit DNS name and type")
	}
	if _, _, err := net.SplitHostPort(c.URL); err != nil {
		return nil, errors.New("BIND URL must be host:port")
	}
	client := &dns.Client{Net: "tcp", Timeout: 10 * time.Second, TsigSecret: map[string]string{fqdn(c.Server): c.Secret}}
	msg := new(dns.Msg)
	msg.SetQuestion(recordName(r), dns.StringToType[r.Type])
	msg.RecursionDesired = false
	if c.Secret != "" {
		msg.SetTsig(fqdn(c.Server), dns.HmacSHA256, 300, time.Now().Unix())
	}
	res, _, err := client.ExchangeContext(ctx, msg, c.URL)
	if err != nil {
		return nil, errors.New("BIND query failed")
	}
	if res.Rcode != dns.RcodeSuccess && res.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("BIND query returned %s", dns.RcodeToString[res.Rcode])
	}
	if !res.Authoritative {
		return nil, errors.New("BIND server is not authoritative")
	}
	out := []dns.RR{}
	for _, rr := range res.Answer {
		if rr.Header().Name == recordName(r) && rr.Header().Rrtype == dns.StringToType[r.Type] {
			out = append(out, rr)
		}
	}
	return out, nil
}
func bindRead(ctx context.Context, c Config, r Request) (json.RawMessage, error) {
	rrs, err := bindQuery(ctx, c, r)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, rr := range rrs {
		out = append(out, rr.String())
	}
	return json.Marshal(out)
}
func bindApply(ctx context.Context, c Config, r Request) (json.RawMessage, error) {
	if c.Secret == "" || c.Server == "" {
		return nil, errors.New("TSIG key name (server) and secret required")
	}
	old, err := bindQuery(ctx, c, r)
	if err != nil {
		return nil, err
	}
	if len(old) > 1 {
		return nil, errors.New("multi-record RRsets are read-only in this editor")
	}
	if r.Action == "create" && len(old) > 0 {
		return nil, errors.New("record already exists")
	}
	if r.Action != "create" && len(old) == 0 {
		return nil, errors.New("record does not exist")
	}
	msg := new(dns.Msg)
	msg.SetUpdate(fqdn(r.Zone))
	var desired dns.RR
	if r.Action != "delete" {
		desired, err = dns.NewRR(fmt.Sprintf("%s %d IN %s %s", recordName(r), r.TTL, r.Type, r.Content))
		if err != nil {
			return nil, errors.New("invalid DNS record content")
		}
	}
	if r.Action == "create" {
		msg.RRsetNotUsed([]dns.RR{desired})
	} else {
		msg.Used(old)
		msg.RemoveRRset(old)
	}
	if desired != nil {
		msg.Insert([]dns.RR{desired})
	}
	msg.SetTsig(fqdn(c.Server), dns.HmacSHA256, 300, time.Now().Unix())
	client := &dns.Client{Net: "tcp", Timeout: 10 * time.Second, TsigSecret: map[string]string{fqdn(c.Server): c.Secret}}
	res, _, err := client.ExchangeContext(ctx, msg, c.URL)
	if err != nil {
		return nil, errors.New("BIND update outcome uncertain; reconcile before retry")
	}
	if res.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("BIND update rejected: %s", dns.RcodeToString[res.Rcode])
	}
	got, err := bindQuery(ctx, c, r)
	if err != nil {
		return nil, errors.New("BIND read-back failed after update")
	}
	if r.Action == "delete" {
		if len(got) != 0 {
			return nil, errors.New("delete read-back mismatch")
		}
	} else if len(got) != 1 || got[0].String() != desired.String() {
		return nil, errors.New("update read-back mismatch")
	}
	return bindRead(ctx, c, r)
}
