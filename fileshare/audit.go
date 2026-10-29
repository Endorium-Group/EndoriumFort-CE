package main

// Append-only, hash-chained journal of every file operation: each line carries
// the SHA-256 of the previous one, so a removed or edited line breaks the chain.
// Lines are also written to stdout for the container log / SIEM collector.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type auditEvent struct {
	Time      string `json:"ts"`
	Action    string `json:"action"`
	User      string `json:"user"`
	Resource  int    `json:"resourceId"`
	SessionID int    `json:"sessionId,omitempty"`
	Root      string `json:"root,omitempty"`
	Path      string `json:"path,omitempty"`
	Target    string `json:"target,omitempty"`
	Bytes     int64  `json:"bytes,omitempty"`
	Outcome   string `json:"outcome"`
	Detail    string `json:"detail,omitempty"`
	RemoteIP  string `json:"ip,omitempty"`
	Prev      string `json:"prev"`
}

type auditLog struct {
	mu   sync.Mutex
	file *os.File
	out  io.Writer
	last string
}

func openAudit(pathname string, out io.Writer) (*auditLog, error) {
	f, err := os.OpenFile(pathname, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	a := &auditLog{file: f, out: out}
	// Resume the chain from the last line.
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		var lastLine []byte
		for scanner.Scan() {
			lastLine = append(lastLine[:0], scanner.Bytes()...)
		}
		if len(lastLine) > 0 {
			sum := sha256.Sum256(lastLine)
			a.last = hex.EncodeToString(sum[:])
		}
	}
	return a, nil
}

func (a *auditLog) write(ev auditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
	ev.Prev = a.last
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	sum := sha256.Sum256(line)
	a.last = hex.EncodeToString(sum[:])
	line = append(line, '\n')
	if a.file != nil {
		_, _ = a.file.Write(line)
	}
	if a.out != nil {
		_, _ = a.out.Write(line)
	}
}
