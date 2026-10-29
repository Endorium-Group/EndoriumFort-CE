package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

const uploadTempPrefix = ".ef-upload-"

// A view on a drive: the caller's own home, or a share someone gave them.
// All file access goes through os.Root, which refuses any path (.., absolute,
// symlink) that would leave the directory it was opened on.
type driveView struct {
	root     *os.Root
	rootName string // "home" | "share:<id>"
	owner    string // whose drive (and quota) this is
	home     string // owner's home directory on disk
	base     string // owner-relative path the view is rooted at ("" = home)
	writable bool
	onlyName string // file share: the single visible entry
}

func (v *driveView) Close() { _ = v.root.Close() }

// ownerPath maps a view-relative path to the owner's home (for shares).
func (v *driveView) ownerPath(rel string) string {
	if v.onlyName != "" {
		return v.base
	}
	if rel == "." {
		return v.base
	}
	if v.base == "" {
		return rel
	}
	return v.base + "/" + rel
}

var (
	errNotFound  = errors.New("not found")
	errForbidden = errors.New("forbidden")
	errBadPath   = errors.New("invalid path")
)

// cleanRel turns a client path ("/a/b", "a/b/", "") into a root-relative one.
func cleanRel(p string) (string, error) {
	if strings.ContainsRune(p, 0) || strings.Contains(p, "\\") {
		return "", errBadPath
	}
	p = path.Clean("/" + p)
	if p == "/" {
		return ".", nil
	}
	return p[1:], nil
}

func validName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 255 ||
		strings.HasPrefix(name, uploadTempPrefix) {
		return false
	}
	for _, r := range name {
		if r == '/' || r == '\\' || unicode.IsControl(r) {
			return false
		}
	}
	return strings.TrimSpace(name) != ""
}

func (s *server) openView(sess *fileSession, rootName string) (*driveView, error) {
	if rootName == "" || rootName == "home" {
		home, err := s.store.homeDir(sess.resource, sess.user)
		if err != nil {
			return nil, err
		}
		root, err := os.OpenRoot(home)
		if err != nil {
			return nil, err
		}
		return &driveView{root: root, rootName: "home", owner: sess.user, home: home, writable: true}, nil
	}
	id, ok := strings.CutPrefix(rootName, "share:")
	if !ok || id == "" {
		return nil, errBadPath
	}
	sh, found, err := s.store.findShare(sess.resource, id)
	if err != nil {
		return nil, err
	}
	if !found || sh.Grantee != sess.user || sh.expired(s.now()) {
		return nil, errNotFound
	}
	home, err := s.store.homeDir(sess.resource, sh.Owner)
	if err != nil {
		return nil, err
	}
	ownerRoot, err := os.OpenRoot(home)
	if err != nil {
		return nil, err
	}
	defer ownerRoot.Close()
	view := &driveView{rootName: rootName, owner: sh.Owner, home: home, base: sh.Path,
		writable: sh.Mode == "rw" && sh.IsDir}
	if sh.IsDir {
		view.root, err = ownerRoot.OpenRoot(sh.Path)
	} else {
		view.onlyName = path.Base(sh.Path)
		view.root, err = ownerRoot.OpenRoot(path.Dir(sh.Path))
	}
	if err != nil {
		return nil, errNotFound
	}
	return view, nil
}

// resolve checks a view-relative path against a file share's single entry.
func (v *driveView) resolve(p string) (string, error) {
	rel, err := cleanRel(p)
	if err != nil {
		return "", err
	}
	if v.onlyName != "" && rel != "." && rel != v.onlyName {
		return "", errNotFound
	}
	return rel, nil
}

func statusFor(err error) (int, string) {
	switch {
	case errors.Is(err, errBadPath):
		return http.StatusBadRequest, "Invalid path"
	case errors.Is(err, errForbidden):
		return http.StatusForbidden, "Read-only access"
	case errors.Is(err, errNotFound), errors.Is(err, fs.ErrNotExist):
		return http.StatusNotFound, "Not found"
	case errors.Is(err, fs.ErrExist):
		return http.StatusConflict, "An item with this name already exists"
	}
	// os.Root escape attempts and anything else.
	return http.StatusBadRequest, "Operation refused"
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, sess *fileSession, ev auditEvent, err error) {
	status, msg := statusFor(err)
	ev.Outcome = "denied"
	ev.Detail = err.Error()
	s.record(r, sess, ev)
	writeError(w, status, msg)
}

// ── list ─────────────────────────────────────────────────────────────────

type entry struct {
	Name     string    `json:"name"`
	Dir      bool      `json:"dir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

func (s *server) handleList(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	q := r.URL.Query()
	ev := auditEvent{Action: "list", Root: q.Get("root"), Path: q.Get("path")}
	view, err := s.openView(sess, q.Get("root"))
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	defer view.Close()
	rel, err := view.resolve(q.Get("path"))
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	entries := []entry{}
	if view.onlyName != "" {
		info, err := view.root.Stat(view.onlyName)
		if err != nil {
			s.fail(w, r, sess, ev, err)
			return
		}
		entries = append(entries, entry{Name: info.Name(), Size: info.Size(), Modified: info.ModTime().UTC()})
	} else {
		dir, err := view.root.Open(rel)
		if err != nil {
			s.fail(w, r, sess, ev, err)
			return
		}
		items, err := dir.ReadDir(-1)
		dir.Close()
		if err != nil {
			s.fail(w, r, sess, ev, err)
			return
		}
		for _, item := range items {
			if strings.HasPrefix(item.Name(), uploadTempPrefix) || item.Type()&fs.ModeSymlink != 0 {
				continue
			}
			info, err := item.Info()
			if err != nil {
				continue
			}
			e := entry{Name: item.Name(), Dir: item.IsDir(), Modified: info.ModTime().UTC()}
			if !e.Dir {
				e.Size = info.Size()
			}
			entries = append(entries, e)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	display := "/"
	if rel != "." {
		display = "/" + rel
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"root":     view.rootName,
		"path":     display,
		"owner":    view.owner,
		"writable": view.writable,
		"entries":  entries,
	})
}

// ── download ─────────────────────────────────────────────────────────────

func attachment(name string) string {
	fallback := strings.Map(func(r rune) rune {
		if r > 126 || r < 32 || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	return mime.FormatMediaType("attachment", map[string]string{"filename": fallback}) +
		"; filename*=UTF-8''" + url.PathEscape(name)
}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	q := r.URL.Query()
	ev := auditEvent{Action: "download", Root: q.Get("root"), Path: q.Get("path")}
	view, err := s.openView(sess, q.Get("root"))
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	defer view.Close()
	rel, err := view.resolve(q.Get("path"))
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	if view.onlyName != "" {
		rel = view.onlyName
	}
	info, err := view.root.Lstat(rel)
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	if info.IsDir() {
		s.downloadZip(w, r, sess, view, rel, ev)
		return
	}
	if !info.Mode().IsRegular() {
		s.fail(w, r, sess, ev, errNotFound)
		return
	}
	f, err := view.root.Open(rel)
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	defer f.Close()
	// Always a download, never rendered: the browser cannot run what it gets.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", attachment(path.Base(rel)))
	ev.Bytes = info.Size()
	s.record(r, sess, ev)
	http.ServeContent(w, r, "", info.ModTime(), f)
}

func (s *server) downloadZip(w http.ResponseWriter, r *http.Request, sess *fileSession, view *driveView, rel string, ev auditEvent) {
	fsys := view.root.FS()
	name := path.Base(rel)
	if rel == "." {
		name = "drive"
		if view.base != "" {
			name = path.Base(view.base)
		}
	}
	// Count first so a huge tree is refused before any byte is sent.
	count := 0
	err := fs.WalkDir(fsys, rel, func(_ string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > s.cfg.maxZipEntries {
			return fmt.Errorf("more than %d entries", s.cfg.maxZipEntries)
		}
		return nil
	})
	if err != nil {
		ev.Outcome = "denied"
		ev.Detail = err.Error()
		s.record(r, sess, ev)
		writeError(w, http.StatusRequestEntityTooLarge, "Folder too large to download as an archive")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", attachment(name+".zip"))
	zw := zip.NewWriter(w)
	var total int64
	walkErr := fs.WalkDir(fsys, rel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), uploadTempPrefix) || d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		inZip := p
		if rel != "." {
			inZip = strings.TrimPrefix(strings.TrimPrefix(p, rel), "/")
			if inZip == "" {
				return nil
			}
		}
		if d.IsDir() {
			if p == rel {
				return nil
			}
			_, err := zw.Create(inZip + "/")
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		hdr.Name = inZip
		hdr.Method = zip.Deflate
		dst, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		src, err := fsys.Open(p)
		if err != nil {
			return err
		}
		n, err := io.Copy(dst, src)
		src.Close()
		total += n
		return err
	})
	closeErr := zw.Close()
	ev.Bytes = total
	ev.Detail = "zip"
	if walkErr != nil || closeErr != nil {
		ev.Outcome = "error"
		ev.Detail = fmt.Sprintf("zip: %v %v", walkErr, closeErr)
	}
	s.record(r, sess, ev)
}

// ── write operations ─────────────────────────────────────────────────────

type usageEntry struct {
	bytes int64
	at    time.Time
}

// usageOf is the size of a drive, cached briefly (a walk per upload is fine,
// a walk per listing is not).
func (s *server) usageOf(home string) int64 {
	s.usageMu.Lock()
	if e, ok := s.usage[home]; ok && time.Since(e.at) < 30*time.Second {
		s.usageMu.Unlock()
		return e.bytes
	}
	s.usageMu.Unlock()
	var total int64
	_ = filepath.WalkDir(home, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	s.usageMu.Lock()
	s.usage[home] = usageEntry{bytes: total, at: time.Now()}
	s.usageMu.Unlock()
	return total
}

func (s *server) invalidateUsage(home string) {
	s.usageMu.Lock()
	delete(s.usage, home)
	s.usageMu.Unlock()
}

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	q := r.URL.Query()
	name := q.Get("name")
	ev := auditEvent{Action: "upload", Root: q.Get("root"), Path: path.Join("/", q.Get("path"), name)}
	view, err := s.openView(sess, q.Get("root"))
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	defer view.Close()
	if !view.writable {
		s.fail(w, r, sess, ev, errForbidden)
		return
	}
	dir, err := view.resolve(q.Get("path"))
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	if !validName(name) {
		s.fail(w, r, sess, ev, errBadPath)
		return
	}
	if r.ContentLength < 0 {
		writeError(w, http.StatusLengthRequired, "Content-Length required")
		return
	}
	if r.ContentLength > s.cfg.maxUpload {
		ev.Outcome, ev.Detail = "denied", "max upload size"
		s.record(r, sess, ev)
		writeError(w, http.StatusRequestEntityTooLarge, "File exceeds the maximum upload size")
		return
	}
	if s.cfg.quota > 0 && s.usageOf(view.home)+r.ContentLength > s.cfg.quota {
		ev.Outcome, ev.Detail = "denied", "quota"
		s.record(r, sess, ev)
		writeError(w, http.StatusInsufficientStorage, "Storage quota exceeded")
		return
	}
	target := path.Join(dir, name)
	if existing, err := view.root.Lstat(target); err == nil {
		if existing.IsDir() || q.Get("overwrite") != "1" {
			s.fail(w, r, sess, ev, fs.ErrExist)
			return
		}
	}

	// Write beside the target, then rename: a cut upload never leaves half a file.
	tmp := path.Join(dir, uploadTempPrefix+randomHex(8))
	f, err := view.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	n, copyErr := io.Copy(f, http.MaxBytesReader(w, r.Body, r.ContentLength))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || n != r.ContentLength {
		_ = view.root.Remove(tmp)
		ev.Outcome, ev.Detail, ev.Bytes = "error", "incomplete upload", n
		s.record(r, sess, ev)
		writeError(w, http.StatusBadRequest, "Upload incomplete")
		return
	}
	if err := view.root.Rename(tmp, target); err != nil {
		_ = view.root.Remove(tmp)
		s.fail(w, r, sess, ev, err)
		return
	}
	s.invalidateUsage(view.home)
	ev.Bytes = n
	s.record(r, sess, ev)
	writeJSON(w, http.StatusCreated, map[string]any{"name": name, "size": n})
}

type pathRequest struct {
	Root    string `json:"root"`
	Path    string `json:"path"`
	Name    string `json:"name,omitempty"`
	NewName string `json:"newName,omitempty"`
}

func (s *server) writableView(w http.ResponseWriter, r *http.Request, sess *fileSession, action string) (*driveView, pathRequest, auditEvent, bool) {
	var req pathRequest
	ev := auditEvent{Action: action}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return nil, req, ev, false
	}
	ev.Root, ev.Path = req.Root, req.Path
	view, err := s.openView(sess, req.Root)
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return nil, req, ev, false
	}
	if !view.writable {
		view.Close()
		s.fail(w, r, sess, ev, errForbidden)
		return nil, req, ev, false
	}
	return view, req, ev, true
}

func (s *server) handleMkdir(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	view, req, ev, ok := s.writableView(w, r, sess, "mkdir")
	if !ok {
		return
	}
	defer view.Close()
	dir, err := view.resolve(req.Path)
	if err == nil && !validName(req.Name) {
		err = errBadPath
	}
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	target := path.Join(dir, req.Name)
	ev.Path = "/" + target
	if err := view.root.Mkdir(target, 0o750); err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	s.record(r, sess, ev)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (s *server) handleRename(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	view, req, ev, ok := s.writableView(w, r, sess, "rename")
	if !ok {
		return
	}
	defer view.Close()
	rel, err := view.resolve(req.Path)
	if err == nil && (rel == "." || !validName(req.NewName)) {
		err = errBadPath
	}
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	target := path.Join(path.Dir(rel), req.NewName)
	ev.Target = "/" + target
	if _, err := view.root.Lstat(target); err == nil {
		s.fail(w, r, sess, ev, fs.ErrExist)
		return
	}
	if err := view.root.Rename(rel, target); err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	if err := s.store.pathMoved(sess.resource, view.owner, view.ownerPath(rel), view.ownerPath(target)); err != nil {
		ev.Detail = "shares not updated: " + err.Error()
	}
	s.record(r, sess, ev)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleDelete(w http.ResponseWriter, r *http.Request, sess *fileSession) {
	view, req, ev, ok := s.writableView(w, r, sess, "delete")
	if !ok {
		return
	}
	defer view.Close()
	rel, err := view.resolve(req.Path)
	if err == nil && rel == "." {
		err = errBadPath // the root of a drive or of a share stays
	}
	if err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	if _, err := view.root.Lstat(rel); err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	if err := view.root.RemoveAll(rel); err != nil {
		s.fail(w, r, sess, ev, err)
		return
	}
	s.invalidateUsage(view.home)
	if err := s.store.pathDeleted(sess.resource, view.owner, view.ownerPath(rel)); err != nil {
		ev.Detail = "shares not updated: " + err.Error()
	}
	s.record(r, sess, ev)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
