package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestPowerDNSLifecycle(t *testing.T) {
	var mu sync.Mutex
	var entries []rrset
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("X-API-Key") != "test-only-key" {
			t.Error("missing auth")
		}
		if r.Method == "PATCH" {
			var body struct {
				Sets []struct {
					rrset
					Change string `json:"changetype"`
				} `json:"rrsets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Sets[0].Change == "DELETE" {
				entries = nil
			} else {
				entries = []rrset{body.Sets[0].rrset}
			}
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rrsets": entries})
	}))
	defer server.Close()
	c := Config{Kind: "powerdns", URL: server.URL, Secret: "test-only-key", AllowWrites: true}
	r := Request{Kind: "dns", Action: "create", Zone: "example.test", Name: "host", Type: "A", Content: "192.0.2.1", TTL: 3600}
	if _, err := Apply(context.Background(), c, r); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), c, r); err == nil {
		t.Fatal("duplicate create succeeded")
	}
	r.Action = "update"
	r.Content = "192.0.2.2"
	if _, err := Apply(context.Background(), c, r); err != nil {
		t.Fatal(err)
	}
	r.Action = "delete"
	if _, err := Apply(context.Background(), c, r); err != nil {
		t.Fatal(err)
	}
	c.AllowWrites = false
	if _, err := Apply(context.Background(), c, r); err == nil {
		t.Fatal("disabled writes allowed")
	}
}
func TestPowerDNSPreservesMultiRecordSets(t *testing.T) {
	writes := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rrsets": []rrset{{Name: "host.example.test.", Type: "A", TTL: 60, Records: []record{{Content: "192.0.2.1"}, {Content: "192.0.2.2"}}}}})
	}))
	defer s.Close()
	_, err := Apply(context.Background(), Config{Kind: "powerdns", URL: s.URL, AllowWrites: true}, Request{Kind: "dns", Action: "delete", Zone: "example.test", Name: "host", Type: "A"})
	if err == nil || writes != 0 {
		t.Fatal("multi-record set was modified")
	}
}
func TestValidationAndTransport(t *testing.T) {
	for _, r := range []Request{
		{Kind: "shell", Action: "create"},
		{Kind: "dns", Action: "create", Zone: "example.test", Name: "host", Type: "A", Content: "::1", TTL: 60},
		{Kind: "dns", Action: "create", Zone: "example.test", Name: "host", Type: "TXT", Content: "evil\nrecord", TTL: 60},
		{Kind: "reservation", Action: "create", IP: "not-an-ip", MAC: "bad"},
		{Kind: "lease", Action: "delete"},
	} {
		if r.Validate() == nil {
			t.Fatalf("invalid request accepted: %+v", r)
		}
	}
	for _, s := range []string{"http://192.0.2.1", "https://user:password@example.test", "file:///etc/passwd"} {
		if validEndpoint(s) == nil {
			t.Fatal("unsafe transport", s)
		}
	}
	if validEndpoint("https://example.test") != nil {
		t.Fatal("HTTPS rejected")
	}
}
func TestKeaCapabilityGate(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":0,"arguments":["config-get","list-commands"]}`))
	}))
	defer s.Close()
	_, err := Apply(context.Background(), Config{Kind: "kea", URL: s.URL, AllowWrites: true}, Request{Kind: "reservation", Action: "create", SubnetID: 1, IP: "192.0.2.1", MAC: "00:11:22:33:44:55"})
	if err == nil {
		t.Fatal("missing hook ignored")
	}
}
func TestDNSNames(t *testing.T) {
	for _, name := range []string{"host", "host.example.test.", "host.example.test"} {
		if got := recordName(Request{Name: name, Zone: "example.test"}); got != "host.example.test." {
			t.Fatal(got)
		}
	}
}
