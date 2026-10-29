package main

// Removing the drive space of a deleted fileshare resource. Two ways in:
//   - POST /internal/spaces/{rid}/purge with a bastion-signed purge order (the
//     bastion sends it when the resource is deleted). /internal/ is not under
//     /files/, so the reverse proxy never exposes it to browsers.
//   - `endoriumfort-files purge <rid>` from inside the container, for spaces
//     left behind while the service was unreachable (`spaces` lists them).

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// purgeSpace closes the space's drive sessions and deletes its files and
// shares. The directory is first renamed aside, so a half-finished removal
// never leaves a partially readable space behind.
func (s *store) purgeSpace(rid int) (bool, error) {
	dir := s.spaceDir(rid)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		s.mu.Lock()
		delete(s.shares, rid)
		s.mu.Unlock()
		return false, nil
	}
	trash := filepath.Join(s.dataDir, "spaces", fmt.Sprintf(".purge-%d-%d", rid, time.Now().UnixNano()))
	s.mu.Lock()
	err := os.Rename(dir, trash)
	delete(s.shares, rid)
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	return true, os.RemoveAll(trash)
}

func (s *server) dropSessions(rid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, sess := range s.sessions {
		if sess.resource == rid {
			delete(s.sessions, token)
		}
	}
}

func (s *server) handlePurge(w http.ResponseWriter, r *http.Request) {
	if s.cfg.secret == nil {
		writeError(w, http.StatusServiceUnavailable, "File share service is not configured")
		return
	}
	rid, ok := resourceID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "Not found")
		return
	}
	var body struct {
		Order string `json:"order"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	now := s.now()
	ev := auditEvent{Action: "space.purge", Resource: rid}
	claims, err := verifyPurge(s.cfg.secret, body.Order, now)
	if err == nil && claims.Resource != rid {
		err = errors.New("order issued for another resource")
	}
	if err == nil && !s.replay.use(claims.Nonce, time.Unix(claims.Expires, 0), now) {
		err = errTicketReplayed
	}
	ev.User = claims.User
	if err != nil {
		ev.Outcome, ev.Detail = "denied", err.Error()
		s.record(r, nil, ev)
		writeError(w, http.StatusUnauthorized, "Invalid purge order")
		return
	}
	s.dropSessions(rid)
	existed, err := s.store.purgeSpace(rid)
	if err != nil {
		ev.Outcome, ev.Detail = "error", err.Error()
		s.record(r, nil, ev)
		writeError(w, http.StatusInternalServerError, "Purge failed")
		return
	}
	if !existed {
		ev.Detail = "no data"
	}
	s.record(r, nil, ev)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "removed": existed})
}

// ── command line ──

type spaceInfo struct {
	id    int
	users int
	bytes int64
}

func listSpaces(dataDir string) ([]spaceInfo, error) {
	items, err := os.ReadDir(filepath.Join(dataDir, "spaces"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []spaceInfo
	for _, item := range items {
		id, err := strconv.Atoi(item.Name())
		if err != nil || !item.IsDir() {
			continue
		}
		info := spaceInfo{id: id}
		homes, _ := os.ReadDir(filepath.Join(dataDir, "spaces", item.Name(), "home"))
		info.users = len(homes)
		_ = filepath.WalkDir(filepath.Join(dataDir, "spaces", item.Name()), func(_ string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if fi, err := d.Info(); err == nil {
					info.bytes += fi.Size()
				}
			}
			return nil
		})
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

// runCommand handles `spaces` and `purge <rid>`; ok=false means "not a command".
func runCommand(args []string) (code int, ok bool) {
	if len(args) == 0 {
		return 0, false
	}
	cfg := loadConfig()
	switch args[0] {
	case "spaces":
		spaces, err := listSpaces(cfg.dataDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1, true
		}
		fmt.Println("RESOURCE\tUSERS\tBYTES")
		for _, sp := range spaces {
			fmt.Printf("%d\t%d\t%d\n", sp.id, sp.users, sp.bytes)
		}
		return 0, true
	case "purge":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: endoriumfort-files purge <resourceId>")
			return 2, true
		}
		rid, err := strconv.Atoi(args[1])
		if err != nil || rid <= 0 {
			fmt.Fprintln(os.Stderr, "invalid resource id")
			return 2, true
		}
		existed, err := newStore(cfg.dataDir).purgeSpace(rid)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1, true
		}
		if audit, err := openAudit(filepath.Join(cfg.dataDir, "audit.jsonl"), nil); err == nil {
			audit.write(auditEvent{Action: "space.purge", User: "cli", Resource: rid, Outcome: "ok", Detail: "command line"})
		}
		if existed {
			fmt.Printf("space %d removed\n", rid)
		} else {
			fmt.Printf("space %d had no data\n", rid)
		}
		return 0, true
	}
	return 0, false
}
