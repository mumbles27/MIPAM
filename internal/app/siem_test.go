package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSIEMRetryPreservesEventUntilAcknowledged(t *testing.T) {
	x := newTest(t)
	failDelivery := true
	var received []string
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Splunk test-only-token" {
			t.Error("missing HEC authentication")
		}
		var envelope struct {
			Event Audit `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Error(err)
		}
		received = append(received, envelope.Event.ID)
		w.Header().Set("Content-Type", "application/json")
		if failDelivery {
			_, _ = w.Write([]byte(`{"code":9}`))
		} else {
			_, _ = w.Write([]byte(`{"code":0}`))
		}
	}))
	defer sink.Close()
	// Tests are not parallel; only this test's TLS transport trusts the fixture.
	old := http.DefaultTransport
	http.DefaultTransport = sink.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })
	t.Setenv("MIPAM_TEST_HEC", "test-only-token")
	x.a.C.SIEMURL = sink.URL + "/services/collector/event"
	x.a.C.SIEMTokenEnv = "MIPAM_TEST_HEC"
	if err := x.a.audit(context.Background(), x.user, "test.event", "test", ""); err != nil {
		t.Fatal(err)
	}
	if err := x.a.deliverEvent(context.Background()); err == nil {
		t.Fatal("HEC error code incorrectly acknowledged")
	}
	var attempts int
	var next int64
	if err := x.a.S.DB.QueryRow("SELECT attempts,next_try FROM outbox").Scan(&attempts, &next); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || next <= time.Now().Unix() {
		t.Fatal("retry not durably scheduled")
	}
	failDelivery = false
	if _, err := x.a.S.DB.Exec("UPDATE outbox SET next_try=0"); err != nil {
		t.Fatal(err)
	}
	if err := x.a.deliverEvent(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := x.a.S.DB.QueryRow("SELECT count(*) FROM outbox").Scan(&count); err != nil || count != 0 {
		t.Fatal("acknowledged event retained", err)
	}
	if len(received) != 2 || received[0] == "" || received[0] != received[1] {
		t.Fatal("retry lost stable event ID")
	}
}

func TestSIEMRejectsPlaintext(t *testing.T) {
	x := newTest(t)
	x.a.C.SIEMURL = "http://127.0.0.1:1/events"
	if x.a.sendEvent(context.Background(), []byte(`{}`)) == nil {
		t.Fatal("unencrypted SIEM delivery accepted")
	}
}
