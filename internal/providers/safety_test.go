package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKeaScopeProjectionAndLeaseBoundary(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command string `json:"command"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		switch req.Command {
		case "config-get":
			_, _ = w.Write([]byte(`{"result":0,"arguments":{"Dhcp4":{"lease-database":{"password":"test-secret"},"subnet4":[{"id":1,"subnet":"192.0.2.0/24","user-context":{"secret":"test-secret"},"pools":[{"pool":"192.0.2.10 - 192.0.2.20","password":"test-secret"}]}],"shared-networks":[{"subnet4":[{"id":2,"subnet":"198.51.100.0/24"}]}]}}}`))
		case "list-commands":
			_, _ = w.Write([]byte(`{"result":0,"arguments":["lease4-get-page"]}`))
		case "lease4-get-page":
			_, _ = w.Write([]byte(`{"result":0,"arguments":{"leases":[{"subnet-id":1,"ip-address":"192.0.2.10"},{"subnet-id":2,"ip-address":"198.51.100.10"}],"next":"198.51.100.10"}}`))
		default:
			t.Error("unexpected command", req.Command)
		}
	}))
	defer s.Close()
	c := Config{Kind: "kea", URL: s.URL}
	raw, err := Read(context.Background(), c, Request{Kind: "scope"})
	if err != nil || strings.Contains(string(raw), "secret") || !strings.Contains(string(raw), "198.51.100.0/24") {
		t.Fatalf("unsafe or incomplete scope projection: %s, %v", raw, err)
	}
	raw, err = Read(context.Background(), c, Request{Kind: "lease", SubnetID: 1})
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Leases []struct {
			Subnet int `json:"subnet-id"`
		} `json:"leases"`
	}
	if err = json.Unmarshal(raw, &page); err != nil || len(page.Leases) != 1 || page.Leases[0].Subnet != 1 {
		t.Fatalf("cross-subnet lease leaked: %s, %v", raw, err)
	}
}

func TestScopeIDCannotAuthorizeAnotherNetwork(t *testing.T) {
	r := Request{Kind: "scope", Action: "create", ScopeID: "192.0.2.0", CIDR: "198.51.100.0/24", Start: "198.51.100.10", End: "198.51.100.20", Name: "wrong scope"}
	if r.Validate() == nil {
		t.Fatal("scope allowlist bypass accepted")
	}
}
