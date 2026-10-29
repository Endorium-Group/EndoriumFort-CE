package main

// On-disk layout, all under the service's own data volume:
//
//	<data>/spaces/<resourceId>/home/u_<hex(username)>/...   one drive per user
//	<data>/spaces/<resourceId>/shares.json                  who shares what
//	<data>/audit.jsonl                                      hash-chained journal
//
// Usernames are hex-encoded so no name can ever form a path component.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxSharesPerOwner = 500

type share struct {
	ID        string     `json:"id"`
	Owner     string     `json:"owner"`
	Path      string     `json:"path"` // relative to the owner's home, never "."
	IsDir     bool       `json:"isDir"`
	Grantee   string     `json:"grantee"`
	Mode      string     `json:"mode"` // "ro" | "rw"
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

func (s share) Name() string { return path.Base(s.Path) }

func (s share) expired(now time.Time) bool {
	return s.ExpiresAt != nil && !s.ExpiresAt.After(now)
}

type store struct {
	dataDir string
	mu      sync.Mutex
	shares  map[int][]share // per resource, loaded lazily
}

func newStore(dataDir string) *store {
	return &store{dataDir: dataDir, shares: make(map[int][]share)}
}

func (s *store) spaceDir(rid int) string {
	return filepath.Join(s.dataDir, "spaces", strconv.Itoa(rid))
}

func homeDirName(user string) string { return "u_" + hex.EncodeToString([]byte(user)) }

// homeDir returns (and creates) the drive of `user` in space `rid`.
func (s *store) homeDir(rid int, user string) (string, error) {
	dir := filepath.Join(s.spaceDir(rid), "home", homeDirName(user))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	return dir, nil
}

func (s *store) sharesFile(rid int) string {
	return filepath.Join(s.spaceDir(rid), "shares.json")
}

// load must be called with s.mu held.
func (s *store) load(rid int) ([]share, error) {
	if list, ok := s.shares[rid]; ok {
		return list, nil
	}
	raw, err := os.ReadFile(s.sharesFile(rid))
	var list []share
	switch {
	case errors.Is(err, os.ErrNotExist):
		list = []share{}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("shares.json of space %d: %w", rid, err)
		}
	}
	s.shares[rid] = list
	return list, nil
}

// save must be called with s.mu held. Atomic: temp file + rename.
func (s *store) save(rid int, list []share) error {
	if err := os.MkdirAll(s.spaceDir(rid), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.sharesFile(rid) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.sharesFile(rid)); err != nil {
		return err
	}
	s.shares[rid] = list
	return nil
}

func (s *store) listShares(rid int) ([]share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load(rid)
	if err != nil {
		return nil, err
	}
	return append([]share(nil), list...), nil
}

func (s *store) findShare(rid int, id string) (share, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load(rid)
	if err != nil {
		return share{}, false, err
	}
	for _, sh := range list {
		if sh.ID == id {
			return sh, true, nil
		}
	}
	return share{}, false, nil
}

var errTooManyShares = errors.New("too many shares")

func (s *store) addShare(rid int, sh share) (share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load(rid)
	if err != nil {
		return sh, err
	}
	owned := 0
	for i, existing := range list {
		if existing.Owner != sh.Owner {
			continue
		}
		owned++
		// Sharing the same item with the same person again updates the grant.
		if existing.Path == sh.Path && existing.Grantee == sh.Grantee {
			sh.ID = existing.ID
			next := append([]share(nil), list...)
			next[i] = sh
			return sh, s.save(rid, next)
		}
	}
	if owned >= maxSharesPerOwner {
		return sh, errTooManyShares
	}
	sh.ID = randomHex(12)
	return sh, s.save(rid, append(append([]share(nil), list...), sh))
}

// removeShare deletes share `id` if `owner` owns it.
func (s *store) removeShare(rid int, id, owner string) (share, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load(rid)
	if err != nil {
		return share{}, false, err
	}
	for i, sh := range list {
		if sh.ID == id && sh.Owner == owner {
			next := append(append([]share(nil), list[:i]...), list[i+1:]...)
			return sh, true, s.save(rid, next)
		}
	}
	return share{}, false, nil
}

func underPath(p, base string) bool {
	return p == base || strings.HasPrefix(p, base+"/")
}

// pathMoved keeps the shares of `owner` pointing at an item after it (or one
// of its parents) was renamed.
func (s *store) pathMoved(rid int, owner, from, to string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load(rid)
	if err != nil {
		return err
	}
	changed := false
	next := append([]share(nil), list...)
	for i, sh := range next {
		if sh.Owner == owner && underPath(sh.Path, from) {
			next[i].Path = to + strings.TrimPrefix(sh.Path, from)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.save(rid, next)
}

// pathDeleted drops the shares of `owner` on an item that no longer exists.
func (s *store) pathDeleted(rid int, owner, removed string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load(rid)
	if err != nil {
		return err
	}
	next := make([]share, 0, len(list))
	for _, sh := range list {
		if sh.Owner == owner && underPath(sh.Path, removed) {
			continue
		}
		next = append(next, sh)
	}
	if len(next) == len(list) {
		return nil
	}
	return s.save(rid, next)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
