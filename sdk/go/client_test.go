package graphite

// Round 19 (F-19-C6): transport rules for the Go client — no API key or
// verdict over plain HTTP to anything but the local machine, and
// ListManifests refuses a non-200 like every other call. Loopback httptest
// servers only.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// noNetwork is a transport that never dials. The refusal under test happens
// before any request is built; if it ever regresses, the request fails here
// instead of leaving the machine.
var noNetwork = &http.Client{Transport: &http.Transport{
	DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("test transport: dialing is not allowed in this test")
	},
}}

func TestPlainHTTPToANonLoopbackHostIsRefused(t *testing.T) {
	for _, base := range []string{
		"http://graphite.internal:7331",
		"http://10.0.0.5:7331",
		"http://128.0.0.1",
		"http://[::2]:7331",
		"http://localhost.evil.example",
		"http://127.0.0.1.nip.io",
	} {
		c := NewClientWithAPIKey(base, strings.Repeat("k", 32))
		c.HTTPClient = noNetwork
		if err := c.Health(); err == nil || !strings.Contains(err.Error(), "non-loopback") {
			t.Errorf("%s: Health must be refused before any request, got %v", base, err)
		}
		if _, err := c.Verify(&VerificationInput{}); err == nil || !strings.Contains(err.Error(), "non-loopback") {
			t.Errorf("%s: Verify must be refused before the key is sent, got %v", base, err)
		}
		if _, err := c.ListManifests(); err == nil || !strings.Contains(err.Error(), "non-loopback") {
			t.Errorf("%s: ListManifests must be refused before the key is sent, got %v", base, err)
		}
	}
}

func TestBaseURLPolicyAcceptsHTTPSAndLoopbackHTTP(t *testing.T) {
	for _, base := range []string{
		"https://graphite.internal",
		"https://10.0.0.5:7331/",
		"http://localhost:7331",
		"http://LOCALHOST:7331",
		"http://127.0.0.1:7331/",
		"http://127.255.255.254",
		"http://[::1]:7331",
	} {
		if err := CheckBaseURL(base); err != nil {
			t.Errorf("%s must be accepted: %v", base, err)
		}
	}
	for _, base := range []string{"ftp://127.0.0.1", "ws://127.0.0.1:7331", "", "https://", "127.0.0.1:7331", "http://127.1"} {
		if err := CheckBaseURL(base); err == nil {
			t.Errorf("%q must be refused", base)
		}
	}
}

func TestLoopbackHTTPStillCarriesTheKey(t *testing.T) {
	// A loopback server proves the policy is not just a string check: the
	// same client pointed at it works, and the key arrives.
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := NewClientWithAPIKey(srv.URL, "loopback-test-key")
	if _, err := c.ListManifests(); err != nil {
		t.Fatalf("loopback http must work: %v", err)
	}
	if gotAuth != "Bearer loopback-test-key" {
		t.Fatalf("the key must reach a loopback server, got %q", gotAuth)
	}
}

func TestListManifestsRefusesANon200(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			// A JSON body that would decode into an empty list if the status
			// were ignored — the failure mode this test pins.
			_, _ = w.Write([]byte(`[]`))
		}))
		manifests, err := NewClient(srv.URL).ListManifests()
		srv.Close()
		if err == nil {
			t.Errorf("status %d: ListManifests returned %v and no error — a failed request read as \"no manifests\"", status, manifests)
		}
	}
}
