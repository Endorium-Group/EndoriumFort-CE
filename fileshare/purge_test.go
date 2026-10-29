package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

func purgeOrder(t *testing.T, rid int, mutate func(*ticketClaims)) string {
	t.Helper()
	now := time.Now()
	c := ticketClaims{Version: 1, Type: ticketPurge, User: "admin", Resource: rid,
		IssuedAt: now.Unix(), Expires: now.Add(time.Minute).Unix(), Nonce: randomHex(8)}
	if mutate != nil {
		mutate(&c)
	}
	tk, err := signTicket(testSecret, c)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func (h *harness) purge(rid string, order string) int {
	body, _ := json.Marshal(map[string]string{"order": order})
	return h.do("POST", "/internal/spaces/"+rid+"/purge", nil, bytes.NewReader(body), false).Code
}

func TestPurgeRemovesSpaceAndSessions(t *testing.T) {
	h := newHarness(t)
	alice := h.login("alice", 1)
	bob := h.login("bob", 1)
	h.postJSON(alice, "mkdir", pathRequest{Path: "/", Name: "d"})
	h.postJSON(alice, "shares", map[string]any{"path": "/d", "grantee": "bob", "mode": "ro"})
	if _, err := h.srv.store.homeDir(2, "carol"); err != nil { // space 2 must survive
		t.Fatal(err)
	}

	order := purgeOrder(t, 1, nil)
	if code := h.purge("1", order); code != http.StatusOK {
		t.Fatalf("purge: %d", code)
	}
	if _, err := os.Stat(h.srv.store.spaceDir(1)); !os.IsNotExist(err) {
		t.Fatalf("space 1 still on disk: %v", err)
	}
	if rec := h.do("GET", "/files/api/r/1/list", bob, nil, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session of a purged space still open: %d", rec.Code)
	}
	if list, _ := h.srv.store.listShares(1); len(list) != 0 {
		t.Fatalf("shares survived: %+v", list)
	}
	if _, err := os.Stat(h.srv.store.spaceDir(2)); err != nil {
		t.Fatalf("space 2 touched: %v", err)
	}
	if code := h.purge("1", order); code != http.StatusUnauthorized {
		t.Fatalf("purge order replayed: %d", code)
	}
}

func TestPurgeOrderChecks(t *testing.T) {
	h := newHarness(t)
	alice := h.login("alice", 1)
	h.upload(alice, "home", "/", "a.txt", "x")
	cases := map[string]string{
		"session ticket": ticketFor(t, "alice", 1, nil),
		"other space":    purgeOrder(t, 2, nil),
		"expired":        purgeOrder(t, 1, func(c *ticketClaims) { c.Expires = time.Now().Add(-time.Hour).Unix() }),
		"bad signature":  purgeOrder(t, 1, nil) + "0",
	}
	for name, order := range cases {
		if code := h.purge("1", order); code != http.StatusUnauthorized {
			t.Errorf("%s accepted: %d", name, code)
		}
	}
	if _, err := os.Stat(h.srv.store.spaceDir(1)); err != nil {
		t.Fatalf("space removed by a refused order: %v", err)
	}
	// And a purge order is no drive ticket.
	body, _ := json.Marshal(map[string]string{"ticket": purgeOrder(t, 1, nil)})
	if rec := h.do("POST", "/files/api/r/1/session", nil, bytes.NewReader(body), true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("purge order opened a session: %d", rec.Code)
	}
}
