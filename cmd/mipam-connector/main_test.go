package main

import (
	"mipam/internal/providers"
	"testing"
)

func TestConnectorAllowlist(t *testing.T) {
	c := config{Zones: []string{"example.test"}, Scopes: []string{"192.0.2.0"}}
	if !authorized(c, providers.Request{Kind: "dns", Action: "read", Zone: "example.test."}) {
		t.Fatal("allowed read rejected")
	}
	if authorized(c, providers.Request{Kind: "dns", Action: "delete", Zone: "example.test"}) {
		t.Fatal("write bypass")
	}
	c.AllowWrites = true
	if authorized(c, providers.Request{Kind: "dns", Action: "delete", Zone: "outside.test"}) {
		t.Fatal("zone escape")
	}
	if authorized(c, providers.Request{Kind: "scope", Action: "read"}) {
		t.Fatal("unscoped read")
	}
	if authorized(c, providers.Request{Kind: "ad-computer", Action: "read"}) {
		t.Fatal("directory bypass")
	}
}
