// EndoriumFort file share service.
//
// A standalone drive service, deliberately kept outside the bastion process:
// it runs in its own container with its own volume, holds no bastion secret
// other than the ticket key, and never touches the bastion database. The
// bastion decides who may open a "fileshare" resource (assignment, access
// policies, approvals, MFA posture) and hands the browser a signed, single-use
// ticket; this service turns the ticket into a short session cookie scoped to
// that resource. A compromise of one side does not give the other's data.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type config struct {
	listen        string
	dataDir       string
	secret        []byte
	sessionTTL    time.Duration
	maxUpload     int64
	quota         int64 // per user drive, 0 = unlimited
	cookieSecure  string
	maxZipEntries int
}

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func envInt(name string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		log.Printf("ignoring invalid %s=%q", name, v)
		return def
	}
	return n
}

// The ticket key, from the environment or a mounted secret file.
func loadSecret() []byte {
	if file := strings.TrimSpace(os.Getenv("ENDORIUMFORT_FILESHARE_SECRET_FILE")); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			log.Printf("cannot read ENDORIUMFORT_FILESHARE_SECRET_FILE: %v", err)
			return nil
		}
		return []byte(strings.TrimSpace(string(raw)))
	}
	return []byte(strings.TrimSpace(os.Getenv("ENDORIUMFORT_FILESHARE_SECRET")))
}

func loadConfig() config {
	return config{
		listen:        envOr("EF_FS_LISTEN", ":8090"),
		dataDir:       envOr("EF_FS_DATA_DIR", "/data"),
		secret:        loadSecret(),
		sessionTTL:    time.Duration(envInt("EF_FS_SESSION_TTL_SECONDS", 900)) * time.Second,
		maxUpload:     envInt("EF_FS_MAX_UPLOAD_MB", 2048) << 20,
		quota:         envInt("EF_FS_QUOTA_MB", 10240) << 20,
		cookieSecure:  envOr("EF_FS_COOKIE_SECURE", "auto"),
		maxZipEntries: int(envInt("EF_FS_MAX_ZIP_ENTRIES", 20000)),
	}
}

const minSecretLen = 32

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}
	if code, ok := runCommand(os.Args[1:]); ok {
		os.Exit(code)
	}
	cfg := loadConfig()
	if cfg.sessionTTL < time.Minute {
		cfg.sessionTTL = time.Minute
	}
	if err := os.MkdirAll(cfg.dataDir, 0o750); err != nil {
		log.Fatalf("data dir %s: %v", cfg.dataDir, err)
	}
	audit, err := openAudit(cfg.dataDir+"/audit.jsonl", os.Stdout)
	if err != nil {
		log.Fatalf("audit log: %v", err)
	}
	if len(cfg.secret) < minSecretLen {
		// Stay up (health reports it) rather than crash-loop next to the
		// bastion: every API call answers 503 until the key is set.
		log.Printf("ENDORIUMFORT_FILESHARE_SECRET is missing or shorter than %d chars: file share disabled", minSecretLen)
		cfg.secret = nil
	}

	srv := newServer(cfg, newStore(cfg.dataDir), audit)
	httpServer := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.reapLoop(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()

	log.Printf("EndoriumFort file share listening on %s (data %s)", cfg.listen, cfg.dataDir)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// Distroless images have no curl: the binary checks itself.
func runHealthcheck() int {
	addr := envOr("EF_FS_LISTEN", ":8090")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
