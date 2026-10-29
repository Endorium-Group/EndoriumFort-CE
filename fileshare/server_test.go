package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef-test")

type harness struct {
	t   *testing.T
	srv *server
	h   http.Handler
	dir string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	audit, err := openAudit(filepath.Join(dir, "audit.jsonl"), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{dataDir: dir, secret: testSecret, sessionTTL: 10 * time.Minute,
		maxUpload: 1 << 20, quota: 4 << 20, maxZipEntries: 100}
	srv := newServer(cfg, newStore(dir), audit)
	return &harness{t: t, srv: srv, h: srv.routes(), dir: dir}
}

func ticketFor(t *testing.T, user string, rid int, mutate func(*ticketClaims)) string {
	t.Helper()
	now := time.Now()
	c := ticketClaims{Version: 1, User: user, UserID: 1, Resource: rid, SessionID: 9,
		IssuedAt: now.Unix(), Expires: now.Add(time.Minute).Unix(),
		SessionExpires: now.Add(time.Hour).Unix(), Nonce: randomHex(8)}
	if mutate != nil {
		mutate(&c)
	}
	tk, err := signTicket(testSecret, c)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func (h *harness) do(method, target string, cookie *http.Cookie, body io.Reader, csrf bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf {
		req.Header.Set(csrfHeader, "1")
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func (h *harness) login(user string, rid int) *http.Cookie {
	h.t.Helper()
	body, _ := json.Marshal(map[string]string{"ticket": ticketFor(h.t, user, rid, nil)})
	rec := h.do("POST", "/files/api/r/"+strconv.Itoa(rid)+"/session", nil, bytes.NewReader(body), true)
	if rec.Code != 200 {
		h.t.Fatalf("login %s: %d %s", user, rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	h.t.Fatal("no session cookie")
	return nil
}

func (h *harness) upload(c *http.Cookie, root, dir, name, content string) int {
	target := "/files/api/r/1/upload?root=" + root + "&path=" + dir + "&name=" + name
	req := httptest.NewRequest("PUT", target, strings.NewReader(content))
	req.AddCookie(c)
	req.Header.Set(csrfHeader, "1")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec.Code
}

func (h *harness) postJSON(c *http.Cookie, route string, v any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(v)
	return h.do("POST", "/files/api/r/1/"+route, c, bytes.NewReader(body), true)
}

func TestTicketRejected(t *testing.T) {
	h := newHarness(t)
	cases := map[string]string{
		"bad signature": ticketFor(t, "alice", 1, nil) + "00",
		"expired":       ticketFor(t, "alice", 1, func(c *ticketClaims) { c.Expires = time.Now().Add(-time.Hour).Unix() }),
		"session over":  ticketFor(t, "alice", 1, func(c *ticketClaims) { c.SessionExpires = time.Now().Add(-time.Second).Unix() }),
		"other space":   ticketFor(t, "alice", 2, nil),
		"garbage":       "nope",
	}
	for name, tk := range cases {
		body, _ := json.Marshal(map[string]string{"ticket": tk})
		rec := h.do("POST", "/files/api/r/1/session", nil, bytes.NewReader(body), true)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d", name, rec.Code)
		}
	}
}

func TestTicketSingleUse(t *testing.T) {
	h := newHarness(t)
	body, _ := json.Marshal(map[string]string{"ticket": ticketFor(t, "alice", 1, nil)})
	if rec := h.do("POST", "/files/api/r/1/session", nil, bytes.NewReader(body), true); rec.Code != 200 {
		t.Fatalf("first use: %d", rec.Code)
	}
	if rec := h.do("POST", "/files/api/r/1/session", nil, bytes.NewReader(body), true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay accepted: %d", rec.Code)
	}
}

func TestSessionScopedToResource(t *testing.T) {
	h := newHarness(t)
	c := h.login("alice", 1)
	if rec := h.do("GET", "/files/api/r/2/list", c, nil, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie of space 1 opened space 2: %d", rec.Code)
	}
}

func TestCSRFHeaderRequired(t *testing.T) {
	h := newHarness(t)
	c := h.login("alice", 1)
	body, _ := json.Marshal(pathRequest{Path: "/", Name: "x"})
	if rec := h.do("POST", "/files/api/r/1/mkdir", c, bytes.NewReader(body), false); rec.Code != http.StatusForbidden {
		t.Fatalf("mkdir without CSRF header: %d", rec.Code)
	}
}

func TestPathTraversalRefused(t *testing.T) {
	h := newHarness(t)
	alice := h.login("alice", 1)
	bob := h.login("bob", 1)
	if code := h.upload(bob, "home", "/", "secret.txt", "bob only"); code != 201 {
		t.Fatalf("upload: %d", code)
	}
	// A symlink planted in alice's drive (e.g. by an operator) must not lead out.
	home, _ := h.srv.store.homeDir(1, "alice")
	bobHome, _ := h.srv.store.homeDir(1, "bob")
	if err := os.Symlink(bobHome, filepath.Join(home, "link")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../u_626f62/secret.txt", "/../../spaces", "link/secret.txt", "..%2F..%2Faudit.jsonl"} {
		rec := h.do("GET", "/files/api/r/1/download?path="+p, alice, nil, false)
		if rec.Code == 200 {
			t.Errorf("path %q leaked: %s", p, rec.Body)
		}
	}
	for _, name := range []string{"../evil", "a/b", ".", "..", uploadTempPrefix + "x"} {
		if code := h.upload(alice, "home", "/", name, "x"); code == 201 {
			t.Errorf("name %q accepted", name)
		}
	}
}

func TestShareLifecycle(t *testing.T) {
	h := newHarness(t)
	alice := h.login("alice", 1)
	bob := h.login("bob", 1)
	carol := h.login("carol", 1)

	if rec := h.postJSON(alice, "mkdir", pathRequest{Path: "/", Name: "projet"}); rec.Code != 201 {
		t.Fatalf("mkdir: %d", rec.Code)
	}
	if code := h.upload(alice, "home", "/projet", "plan.txt", "v1"); code != 201 {
		t.Fatalf("upload: %d", code)
	}
	rec := h.postJSON(alice, "shares", map[string]any{"path": "/projet", "grantee": "bob", "mode": "ro"})
	if rec.Code != 201 {
		t.Fatalf("share: %d %s", rec.Code, rec.Body)
	}
	var sh shareView
	_ = json.Unmarshal(rec.Body.Bytes(), &sh)
	root := "share:" + sh.ID

	// bob reads, cannot write; carol cannot see it at all.
	if rec := h.do("GET", "/files/api/r/1/download?root="+root+"&path=/plan.txt", bob, nil, false); rec.Code != 200 || rec.Body.String() != "v1" {
		t.Fatalf("bob read: %d %q", rec.Code, rec.Body)
	}
	if code := h.upload(bob, root, "/", "x.txt", "x"); code != http.StatusForbidden {
		t.Fatalf("bob wrote on read-only share: %d", code)
	}
	if rec := h.do("GET", "/files/api/r/1/list?root="+root, carol, nil, false); rec.Code != http.StatusNotFound {
		t.Fatalf("carol listed bob's share: %d", rec.Code)
	}
	// bob cannot re-share nor revoke alice's share.
	if rec := h.do("DELETE", "/files/api/r/1/shares/"+sh.ID, bob, nil, true); rec.Code != http.StatusNotFound {
		t.Fatalf("bob revoked alice's share: %d", rec.Code)
	}

	// Upgrade to read-write: same share, bob may now write (on alice's quota).
	h.postJSON(alice, "shares", map[string]any{"path": "/projet", "grantee": "bob", "mode": "rw"})
	if code := h.upload(bob, root, "/", "notes.txt", "bob"); code != 201 {
		t.Fatalf("bob write on rw share: %d", code)
	}
	if rec := h.postJSON(bob, "delete", pathRequest{Root: root, Path: "/"}); rec.Code == 200 {
		t.Fatal("bob deleted the share root")
	}

	// Renaming the folder keeps the share; deleting it drops the share.
	if rec := h.postJSON(alice, "rename", pathRequest{Path: "/projet", NewName: "projet-2026"}); rec.Code != 200 {
		t.Fatalf("rename: %d", rec.Code)
	}
	if rec := h.do("GET", "/files/api/r/1/download?root="+root+"&path=/notes.txt", bob, nil, false); rec.Code != 200 {
		t.Fatalf("share lost after rename: %d", rec.Code)
	}
	if rec := h.postJSON(alice, "delete", pathRequest{Path: "/projet-2026"}); rec.Code != 200 {
		t.Fatalf("delete: %d", rec.Code)
	}
	list, _ := h.srv.store.listShares(1)
	if len(list) != 0 {
		t.Fatalf("share survived deletion: %+v", list)
	}
}

func TestFileShareShowsOnlyThatFile(t *testing.T) {
	h := newHarness(t)
	alice := h.login("alice", 1)
	bob := h.login("bob", 1)
	h.upload(alice, "home", "/", "public.txt", "ok")
	h.upload(alice, "home", "/", "private.txt", "no")
	rec := h.postJSON(alice, "shares", map[string]any{"path": "/public.txt", "grantee": "bob", "mode": "rw"})
	var sh shareView
	_ = json.Unmarshal(rec.Body.Bytes(), &sh)
	if sh.Mode != "ro" {
		t.Fatalf("file share mode = %s, want ro", sh.Mode)
	}
	root := "share:" + sh.ID
	rec = h.do("GET", "/files/api/r/1/list?root="+root, bob, nil, false)
	if !strings.Contains(rec.Body.String(), "public.txt") || strings.Contains(rec.Body.String(), "private.txt") {
		t.Fatalf("listing: %s", rec.Body)
	}
	if rec := h.do("GET", "/files/api/r/1/download?root="+root+"&path=/private.txt", bob, nil, false); rec.Code == 200 {
		t.Fatal("sibling of a shared file was readable")
	}
}

func TestExpiredShareHidden(t *testing.T) {
	h := newHarness(t)
	alice := h.login("alice", 1)
	bob := h.login("bob", 1)
	h.postJSON(alice, "mkdir", pathRequest{Path: "/", Name: "d"})
	rec := h.postJSON(alice, "shares", map[string]any{"path": "/d", "grantee": "bob", "mode": "ro", "expiresInDays": 1})
	var sh shareView
	_ = json.Unmarshal(rec.Body.Bytes(), &sh)
	h.srv.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	// The session itself would have expired too; extend it for the test.
	h.srv.mu.Lock()
	for _, s := range h.srv.sessions {
		s.expires = time.Now().Add(72 * time.Hour)
	}
	h.srv.mu.Unlock()
	if rec := h.do("GET", "/files/api/r/1/list?root=share:"+sh.ID, bob, nil, false); rec.Code != http.StatusNotFound {
		t.Fatalf("expired share still open: %d", rec.Code)
	}
}

func TestQuotaEnforced(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.quota = 10
	alice := h.login("alice", 1)
	if code := h.upload(alice, "home", "/", "a", "123456"); code != 201 {
		t.Fatalf("first upload: %d", code)
	}
	if code := h.upload(alice, "home", "/", "b", "123456"); code != http.StatusInsufficientStorage {
		t.Fatalf("over quota: %d", code)
	}
}

func TestAuditChain(t *testing.T) {
	h := newHarness(t)
	alice := h.login("alice", 1)
	h.upload(alice, "home", "/", "a", "1")
	raw, err := os.ReadFile(filepath.Join(h.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		t.Fatalf("audit lines: %d", len(lines))
	}
	var second auditEvent
	_ = json.Unmarshal([]byte(lines[1]), &second)
	if second.Prev == "" || second.Action != "upload" || second.User != "alice" {
		t.Fatalf("audit entry: %+v", second)
	}
}
