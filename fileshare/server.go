package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cookieName  = "ef_files"
	csrfHeader  = "X-EF-Files"
	apiPrefix   = "/files/api/r/"
	maxJSONBody = 64 << 10
)

type fileSession struct {
	token     string
	user      string
	userID    int
	resource  int
	sessionID int
	expires   time.Time
}

type server struct {
	cfg    config
	store  *store
	audit  *auditLog
	replay *replayGuard
	now    func() time.Time

	mu       sync.Mutex
	sessions map[string]*fileSession

	usageMu sync.Mutex
	usage   map[string]usageEntry
}

func newServer(cfg config, st *store, audit *auditLog) *server {
	return &server{
		cfg:      cfg,
		store:    st,
		audit:    audit,
		replay:   newReplayGuard(),
		now:      time.Now,
		sessions: make(map[string]*fileSession),
		usage:    make(map[string]usageEntry),
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /internal/spaces/{rid}/purge", s.handlePurge)
	mux.HandleFunc("POST /files/api/r/{rid}/session", s.handleOpenSession)
	mux.HandleFunc("DELETE /files/api/r/{rid}/session", s.authed(s.handleCloseSession))
	mux.HandleFunc("GET /files/api/r/{rid}/me", s.authed(s.handleMe))
	mux.HandleFunc("GET /files/api/r/{rid}/list", s.authed(s.handleList))
	mux.HandleFunc("GET /files/api/r/{rid}/download", s.authed(s.handleDownload))
	mux.HandleFunc("PUT /files/api/r/{rid}/upload", s.authed(s.handleUpload))
	mux.HandleFunc("POST /files/api/r/{rid}/mkdir", s.authed(s.handleMkdir))
	mux.HandleFunc("POST /files/api/r/{rid}/rename", s.authed(s.handleRename))
	mux.HandleFunc("POST /files/api/r/{rid}/delete", s.authed(s.handleDelete))
	mux.HandleFunc("GET /files/api/r/{rid}/shares", s.authed(s.handleListShares))
	mux.HandleFunc("POST /files/api/r/{rid}/shares", s.authed(s.handleCreateShare))
	mux.HandleFunc("DELETE /files/api/r/{rid}/shares/{id}", s.authed(s.handleDeleteShare))
	return securityHeaders(mux)
}

// Every answer is private, never cached, never rendered as a page.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *server) reapLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := s.now()
			s.mu.Lock()
			for token, sess := range s.sessions {
				if sess.expires.Before(now) {
					delete(s.sessions, token)
				}
			}
			s.mu.Unlock()
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func resourceID(r *http.Request) (int, bool) {
	rid, err := strconv.Atoi(r.PathValue("rid"))
	return rid, err == nil && rid > 0
}

func (s *server) secureCookie(r *http.Request) bool {
	switch s.cfg.cookieSecure {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func cookiePath(rid int) string { return apiPrefix + strconv.Itoa(rid) + "/" }

// authed resolves the session cookie of the resource in the URL and enforces
// the CSRF header on anything that changes state.
func (s *server) authed(next func(http.ResponseWriter, *http.Request, *fileSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.secret == nil {
			writeError(w, http.StatusServiceUnavailable, "File share service is not configured")
			return
		}
		rid, ok := resourceID(r)
		if !ok {
			writeError(w, http.StatusNotFound, "Not found")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get(csrfHeader) != "1" {
			writeError(w, http.StatusForbidden, "Missing "+csrfHeader+" header")
			return
		}
		cookie, err := r.Cookie(cookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "File share session required")
			return
		}
		s.mu.Lock()
		sess := s.sessions[cookie.Value]
		s.mu.Unlock()
		if sess == nil || sess.resource != rid || sess.expires.Before(s.now()) {
			writeError(w, http.StatusUnauthorized, "File share session expired")
			return
		}
		next(w, r, sess)
	}
}

func (s *server) record(r *http.Request, sess *fileSession, ev auditEvent) {
	if sess != nil {
		ev.User = sess.user
		ev.Resource = sess.resource
		ev.SessionID = sess.sessionID
	}
	ev.RemoteIP = clientIP(r)
	if ev.Outcome == "" {
		ev.Outcome = "ok"
	}
	s.audit.write(ev)
}

// ── session ──────────────────────────────────────────────────────────────

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "configured": s.cfg.secret != nil})
}

func (s *server) handleOpenSession(w http.ResponseWriter, r *http.Request) {
	if s.cfg.secret == nil {
		writeError(w, http.StatusServiceUnavailable, "File share service is not configured")
		return
	}
	rid, ok := resourceID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "Not found")
		return
	}
	if r.Header.Get(csrfHeader) != "1" {
		writeError(w, http.StatusForbidden, "Missing "+csrfHeader+" header")
		return
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	now := s.now()
	claims, err := verifyTicket(s.cfg.secret, body.Ticket, now)
	if err == nil && claims.Resource != rid {
		err = errors.New("ticket issued for another resource")
	}
	if err == nil && !s.replay.use(claims.Nonce, time.Unix(claims.Expires, 0), now) {
		err = errTicketReplayed
	}
	if err != nil {
		s.record(r, nil, auditEvent{Action: "session.open", User: claims.User, Resource: rid,
			Outcome: "denied", Detail: err.Error()})
		writeError(w, http.StatusUnauthorized, "Invalid file share ticket")
		return
	}

	expires := now.Add(s.cfg.sessionTTL)
	if end := time.Unix(claims.SessionExpires, 0); end.Before(expires) {
		expires = end
	}
	sess := &fileSession{
		token:     randomHex(32),
		user:      claims.User,
		userID:    claims.UserID,
		resource:  rid,
		sessionID: claims.SessionID,
		expires:   expires,
	}
	s.mu.Lock()
	// A renewal replaces the previous cookie of the same browser.
	if old, err := r.Cookie(cookieName); err == nil {
		if prev := s.sessions[old.Value]; prev != nil && prev.user == sess.user && prev.resource == rid {
			delete(s.sessions, old.Value)
		}
	}
	s.sessions[sess.token] = sess
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sess.token,
		Path:     cookiePath(rid),
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteStrictMode,
	})
	s.record(r, sess, auditEvent{Action: "session.open"})
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       sess.user,
		"resourceId": rid,
		"expiresAt":  expires.UTC().Format(time.RFC3339),
		"ttlSeconds": int(time.Until(expires).Seconds()),
	})
}

func (s *server) handleCloseSession(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	s.mu.Lock()
	delete(s.sessions, sess.token)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: cookiePath(sess.resource), MaxAge: -1,
		HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteStrictMode,
	})
	s.record(r, sess, auditEvent{Action: "session.close"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	home, err := s.store.homeDir(sess.resource, sess.user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Drive unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":           sess.user,
		"resourceId":     sess.resource,
		"expiresAt":      sess.expires.UTC().Format(time.RFC3339),
		"usedBytes":      s.usageOf(home),
		"quotaBytes":     s.cfg.quota,
		"maxUploadBytes": s.cfg.maxUpload,
	})
}
