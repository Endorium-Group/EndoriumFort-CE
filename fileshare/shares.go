package main

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

type shareView struct {
	ID        string     `json:"id"`
	Owner     string     `json:"owner"`
	Grantee   string     `json:"grantee"`
	Name      string     `json:"name"`
	Path      string     `json:"path,omitempty"` // only shown to the owner
	IsDir     bool       `json:"isDir"`
	Mode      string     `json:"mode"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Expired   bool       `json:"expired"`
}

func viewOf(sh share, now time.Time, owner bool) shareView {
	v := shareView{ID: sh.ID, Owner: sh.Owner, Grantee: sh.Grantee, Name: sh.Name(),
		IsDir: sh.IsDir, Mode: sh.Mode, CreatedAt: sh.CreatedAt, ExpiresAt: sh.ExpiresAt,
		Expired: sh.expired(now)}
	if owner {
		v.Path = "/" + sh.Path
	}
	return v
}

func (s *server) handleListShares(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	list, err := s.store.listShares(sess.resource)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Shares unavailable")
		return
	}
	now := s.now()
	outgoing, incoming := []shareView{}, []shareView{}
	for _, sh := range list {
		switch {
		case sh.Owner == sess.user:
			outgoing = append(outgoing, viewOf(sh, now, true))
		case sh.Grantee == sess.user && !sh.expired(now):
			incoming = append(incoming, viewOf(sh, now, false))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"outgoing": outgoing, "incoming": incoming})
}

const maxShareDays = 365

func (s *server) handleCreateShare(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	var req struct {
		Path          string `json:"path"`
		Grantee       string `json:"grantee"`
		Mode          string `json:"mode"`
		ExpiresInDays int    `json:"expiresInDays"`
	}
	ev := auditEvent{Action: "share.create"}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	req.Grantee = strings.TrimSpace(req.Grantee)
	ev.Path, ev.Target = req.Path, req.Grantee
	if req.Grantee == "" || len(req.Grantee) > 255 || req.Grantee == sess.user ||
		strings.ContainsFunc(req.Grantee, func(r rune) bool { return r < 32 }) {
		s.fail(w, r, sess, ev, errBadPath)
		return
	}
	if req.Mode != "ro" && req.Mode != "rw" {
		writeError(w, http.StatusBadRequest, "mode must be ro or rw")
		return
	}
	if req.ExpiresInDays < 0 || req.ExpiresInDays > maxShareDays {
		writeError(w, http.StatusBadRequest, "expiresInDays out of range")
		return
	}
	// Only your own items can be shared (no re-sharing of what you received).
	view, err := s.openView(sess, "home")
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	defer view.Close()
	rel, err := cleanRel(req.Path)
	if err == nil && rel == "." {
		err = errBadPath
	}
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	info, err := view.root.Lstat(rel)
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		s.fail(w, r, sess, ev, errBadPath)
		return
	}
	now := s.now().UTC()
	sh := share{Owner: sess.user, Path: rel, IsDir: info.IsDir(), Grantee: req.Grantee,
		Mode: req.Mode, CreatedAt: now}
	if !sh.IsDir {
		sh.Mode = "ro" // a single file is shared read-only
	}
	if req.ExpiresInDays > 0 {
		exp := now.Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		sh.ExpiresAt = &exp
	}
	sh, err = s.store.addShare(sess.resource, sh)
	if errors.Is(err, errTooManyShares) {
		writeError(w, http.StatusTooManyRequests, "Too many shares")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Share could not be saved")
		return
	}
	ev.Detail = sh.Mode
	s.record(r, sess, ev)
	writeJSON(w, http.StatusCreated, viewOf(sh, now, true))
}

func (s *server) handleDeleteShare(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	id := r.PathValue("id")
	ev := auditEvent{Action: "share.revoke", Root: "share:" + id}
	sh, found, err := s.store.removeShare(sess.resource, id, sess.user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Share could not be removed")
		return
	}
	if !found {
		s.fail(w, r, sess, ev, errNotFound)
		return
	}
	ev.Path, ev.Target = "/"+sh.Path, sh.Grantee
	s.record(r, sess, ev)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
