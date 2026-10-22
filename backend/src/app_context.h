#pragma once
// ─── EndoriumFort — Application context ─────────────────────────────────
// Holds all shared state and provides core operations (auth, audit, CRUD).

#include "crow.h"
#include "models.h"
#include "database.h"
#include "license.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>

// ── Rate limiting state ──
struct RateLimitEntry {
  std::queue<std::chrono::steady_clock::time_point> attempts;
  int consecutive_failures = 0;  // Track consecutive failures for exponential backoff
  std::chrono::steady_clock::time_point last_failure_time;  // Time of last failure
  std::chrono::steady_clock::time_point block_until;  // Time when IP/user will be unblocked
};

struct TunnelTicket {
  std::string ticket;
  std::string proof;
  std::string challenge;
  std::string signingKeyId;
  std::string serverAttestation;
  int userId = 0;
  std::string user;
  std::string role;
  int resourceId = 0;
  // Session (opened through the access policy) this tunnel runs under.
  int sessionId = 0;
  std::string issuedForIp;
  std::string issuedForUserAgent;
  std::string issuedAt;
  std::string expiresAt;
};

// Long-lived, narrowly-scoped credential an agent exchanges its short-lived
// bootstrap token for. It can ONLY mint tunnel tickets, and only for the one
// resource / source IP / agent it was issued to, so a leaked credential cannot
// be replayed as a user session the way a bearer token could.
struct TunnelCredential {
  std::string credential;
  int userId = 0;
  std::string user;
  std::string role;
  int resourceId = 0;
  // Session (opened through the access policy) this credential runs under:
  // it stops minting tickets once that session ends or its grant expires.
  int sessionId = 0;
  std::string issuedForIp;
  std::string issuedForUserAgent;
  std::string issuedAt;
  std::string expiresAt;
  int64_t lastUsedEpoch = 0;
};

struct RelayEnrollmentToken {
  std::string token;
  std::string createdAt;
  std::string expiresAt;
  std::string createdBy;
  int64_t expiresAtEpoch = 0;
  bool used = false;
};

struct RelayCertificate {
  std::string certificateId;
  std::string certificate;
  std::string createdAt;
  std::string expiresAt;
  std::string createdBy;
  std::string boundRelayId;
  int64_t expiresAtEpoch = 0;
  bool revoked = false;
};

struct WebAuthnChallenge {
  std::string requestId;
  int userId = 0;
  std::string username;
  std::string purpose;
  std::string challenge;
  std::string rpId;
  std::string origin;
  std::string createdAt;
  std::string expiresAt;
  int64_t expiresAtEpoch = 0;
};

struct AppContext {
  // ── Session state ──
  std::mutex session_mutex;
  std::unordered_map<int, Session> sessions;
  std::atomic<int> next_session_id{1};

  // ── Auth state ──
  std::mutex auth_mutex;
  std::unordered_map<std::string, AuthSession> auth_sessions;
  int listen_port = 8080;
  int token_ttl_seconds = 3600;  // 1 hour default

  // ── Resource state ──
  std::mutex resource_mutex;
  std::unordered_map<int, Resource> resources;
  std::atomic<int> next_resource_id{1};

  // ── User state ──
  std::mutex user_mutex;
  std::unordered_map<int, UserAccount> users;
  std::atomic<int> next_user_id{1};

  // ── WebAuthn / passkeys ──
  std::mutex webauthn_mutex;
  std::unordered_map<int, WebAuthnCredential> webauthn_credentials;
  std::unordered_map<std::string, int> webauthn_credential_by_external_id;
  std::unordered_map<std::string, WebAuthnChallenge> webauthn_challenges;
  std::atomic<int> next_webauthn_credential_id{1};
  int webauthn_challenge_ttl_seconds = 180;
  std::string webauthn_rp_id_override;
  std::string webauthn_origin_override;

  // ── Audit state ──
  std::mutex audit_mutex;
  std::vector<AuditEvent> audit_events;
  std::atomic<int> next_audit_id{1};
  std::string audit_path = "audit-log.jsonl";
  // Tamper-evidence: each persisted audit line carries a hash chaining it to the
  // previous one (PCI 10.5, ISO A.8.15, NIST AU-9, ANSSI). When an HMAC key is
  // configured (ENDORIUMFORT_AUDIT_HMAC_KEY) the chain is keyed, so an attacker
  // who cannot read the key cannot forge a consistent chain; without a key it
  // falls back to a plain SHA-256 chain (detects edits/truncation only).
  std::string audit_chain_hash = "GENESIS";  // head of the chain (under mutex)
  std::string audit_hmac_key;                // raw key bytes; empty = SHA-256
  // Retention/rotation (PCI 10.7 keep ≥12mo vs RGPD storage-limitation — left
  // configurable so operators set their own policy). max_file_bytes>0 seals the
  // active log into a timestamped archive once it grows past the threshold (the
  // in-memory chain head carries over, so archives stay cross-linked);
  // retention_days>0 purges archives older than that. 0 = disabled (grow/keep).
  int audit_max_file_bytes = 0;
  int audit_retention_days = 0;
  // Seed the chain head (and key) from the environment + existing log tail.
  void init_audit_chain();
  // Re-read the on-disk log and recompute the chain. Returns {ok, lines,
  // firstBrokenLine} where firstBrokenLine is 0 when intact.
  struct AuditChainCheck {
    bool ok = true;
    int64_t lines = 0;
    int64_t firstBrokenLine = 0;
    // Lines written before the chain existed (an upgraded install): the
    // leading run of lines without hashes. Reported, not verifiable.
    int64_t legacyLines = 0;
  };
  AuditChainCheck verify_audit_chain();
  // RGPD access/portability (art.15/20): return persisted audit log lines whose
  // actor matches `actor`, most recent first, capped at `max_lines`. Each string
  // is the raw JSON object as stored.
  std::vector<std::string> collect_audit_lines_for_actor(const std::string &actor,
                                                         size_t max_lines);
  // ── Mobile device registration (push / signed approvals) ──
  // Register (or upsert by user+pushToken) a device; returns its id, or -1 on
  // error. list_user_devices/delete_user_device are scoped to the owning user.
  int register_user_device(const UserDevice &device);
  std::vector<UserDevice> list_user_devices(int user_id);
  bool delete_user_device(int user_id, int device_id);
  // Verify that `signature_b64url` over `message` was produced by the private
  // key of device `device_id` owned by `user_id` (public key stored at
  // registration, SPKI base64url). ES256 (EC P-256) or Ed25519. Used for
  // non-repudiable mobile approvals. Returns false on any mismatch.
  bool verify_device_signature(int user_id, int device_id,
                               const std::string &message,
                               const std::string &signature_b64url);
  // Seal the active log into an archive when it exceeds audit_max_file_bytes and
  // purge archives older than audit_retention_days. Caller holds audit_mutex.
  void maybe_rotate_audit_locked();

  // ── Session recordings ──
  std::mutex recording_mutex;
  std::unordered_map<int, SessionRecording> recordings;
  std::atomic<int> next_recording_id{1};
  std::string recordings_dir = "recordings";

  // ── Session DNA chain (tamper-evident audit lineage) ──
  std::mutex session_dna_mutex;

  // ── Incident containment mode ──
  std::mutex containment_mutex;
  bool containment_mode_enabled = false;
  std::string containment_updated_at;
  std::string containment_updated_by;
  std::string containment_reason;

  // ── Active security incident lifecycle ──
  std::mutex incident_mutex;
  std::atomic<int> next_incident_id{1};
  bool incident_active = false;
  int incident_id = 0;
  int incident_critical_count = 0;
  int incident_window_seconds = 0;
  std::string incident_profile;
  std::string incident_title;
  std::string incident_summary;
  std::string incident_opened_at;
  std::string incident_opened_by;
  std::string incident_closed_at;
  std::string incident_closed_by;
  std::string incident_close_reason;

  // ── Access requests (dual control) ──
  std::mutex access_request_mutex;
  std::unordered_map<int, AccessRequest> access_requests;
  std::atomic<int> next_access_request_id{1};
  // Fires after an access request is created. The EE push module fills this to
  // notify approvers' mobile devices; unset in CE (and EE without the module) =
  // no-op. Invoked from the request-create handler.
  std::function<void(const AccessRequest &request)> on_access_request_created;

  // ── Runtime session behavior counters ──
  std::mutex behavior_mutex;
  std::unordered_map<int, int64_t> session_input_events;

    // ── Runtime anomaly signal correlation ──
    std::mutex anomaly_mutex;
    std::unordered_map<std::string, std::queue<std::chrono::steady_clock::time_point>>
      anomaly_signal_windows;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>
      anomaly_signal_cooldowns;

  // ── Ephemeral credential leases ──
  std::mutex ephemeral_credential_mutex;
  std::unordered_map<int, EphemeralCredentialLease> ephemeral_credentials;
  std::atomic<int> next_ephemeral_credential_id{1};

  // ── Proxy cookie jar ──
  std::mutex proxy_cookie_mutex;
  std::unordered_map<std::string, std::unordered_map<std::string, std::string>>
      proxy_cookie_jar;

  // ── SSE events ──
  std::mutex event_mutex;
  std::vector<SessionEvent> session_events;
  std::atomic<int> next_event_id{1};

  // ── Rate limiting ──
  std::mutex rate_limit_mutex;
  std::unordered_map<std::string, RateLimitEntry> rate_limit_map;
  int rate_limit_max_attempts = 10;  // max attempts per window
  std::chrono::seconds rate_limit_window{300};  // 5 minute window

  // ── Database ──
  SqliteDb sqlite;

  // ── SSH session closure callback ──
  std::function<void(int)> close_ssh_for_session = [](int) {};

  // ── Dynamic secrets seams (premium; set by the pro/ vault module) ──
  // provision: given a session, create an ephemeral OS account on the target and
  // return the login username + password to use. Returns false (with a reason in
  // `detail`) if unavailable or provisioning failed — the caller then fails
  // closed. deprovision: destroy the ephemeral account bound to a session id.
  // Both are no-ops / empty in the Community edition (no dynamic secrets).
  std::function<bool(const Session &, std::string & /*username*/,
                     std::string & /*password*/, std::string & /*detail*/)>
      provision_dynamic_credential;
  std::function<void(int /*session_id*/)> deprovision_dynamic_for_session =
      [](int) {};

  // ── RBI recording seams (premium; set by pro/rbi_recording.cc, no-op in CE) ──
  // The RBI browser lives in core (rbi.cc), but recording its graphical stream is
  // an Enterprise feature. When present AND licensed (rbi.recording), the pro
  // module returns an opaque handle (>0) from open, receives each JPEG frame, and
  // finalizes on close. Unset in CE (and in EE without the license) → no capture.
  // format: "mjpeg" (full-frame JPEG, cdp engine) or "tiles" (dirty-rect tile
  // stream, tiles engine) — selects the on-disk .efr container the player reads.
  std::function<int64_t(int /*session_id*/, int /*width*/, int /*height*/,
                        const std::string & /*title*/, const std::string & /*format*/)>
      rbi_recording_open;
  std::function<void(int64_t /*handle*/, const std::string & /*jpeg*/)>
      rbi_recording_frame;
  std::function<void(int64_t /*handle*/)> rbi_recording_close;

  // ── RBI transfer policy seam (premium; set by pro/rbi_transfer.cc, no-op in CE) ──
  // File transfer (upload/download) and clipboard paste in the isolated browser is
  // a CORE capability (rbi.cc relays the bytes). Governing it — a DLP policy that
  // may allow/deny per direction, cap sizes, filter extensions — plus the audit
  // trail, is Enterprise. When unset (CE, or EE without the `rbi.transfer` license)
  // every transfer is allowed: the capability must never be bricked by licensing.
  // The pro module, when licensed, returns false to block and records an audit
  // event for each attempt. direction: "upload" | "download" | "paste".
  std::function<bool(int /*session_id*/, const std::string & /*direction*/,
                     const std::string & /*name*/, int64_t /*size*/)>
      rbi_transfer_check;

  // ── Integration seams (premium; set by pro/enterprise.cc, unset in CE) ──
  // itsm_ticket_check: called when a session is opened with a ticket id. Returns
  // true to let the session open; false (reason in `detail`) to refuse it.
  // siem_forward: receives each audit event once it is persisted. It must not
  // block (the pro module queues events and sends them from a worker thread).
  std::function<bool(const std::string & /*ticket_id*/, std::string & /*detail*/)>
      itsm_ticket_check;
  std::function<void(const AuditEvent &)> siem_forward;

  // ── Tunnel state ──
  std::mutex tunnel_mutex;
  std::unordered_map<crow::websocket::connection *,
                     std::shared_ptr<TunnelState>>
      tunnel_connections;

  // ── VNC WebSocket state ──
  std::mutex vnc_mutex;
  std::unordered_map<crow::websocket::connection *,
                     std::shared_ptr<VncConnection>>
      vnc_connections;

  // ── One-time tunnel tickets ──
  std::mutex tunnel_ticket_mutex;
  std::unordered_map<std::string, TunnelTicket> tunnel_tickets;
  int tunnel_ticket_ttl_seconds = 30;
  int tunnel_signature_max_skew_seconds = 45;

  // ── Tunnel nonce anti-replay cache ──
  std::mutex tunnel_nonce_mutex;
  std::unordered_map<std::string, int64_t> tunnel_seen_nonces;
  int tunnel_nonce_ttl_seconds = 90;

  // ── Tunnel cryptographic key-id rotation (agility window) ──
  std::mutex tunnel_signing_key_mutex;
  std::string tunnel_signing_key_current_id;
  std::string tunnel_signing_key_previous_id;
  std::string tunnel_signing_key_current_secret;
  std::string tunnel_signing_key_previous_secret;
  int64_t tunnel_signing_key_current_epoch = 0;
  int64_t tunnel_signing_key_previous_epoch = 0;
  int tunnel_signing_key_rotation_seconds = 300;
  int tunnel_signing_key_grace_seconds = 600;

  // ── Tunnel ticket issuance throttle ──
  std::mutex tunnel_ticket_issue_limit_mutex;
  std::unordered_map<std::string, RateLimitEntry> tunnel_ticket_issue_by_subject;
  int tunnel_ticket_issue_max_attempts = 120;
  std::chrono::seconds tunnel_ticket_issue_window{60};

  // ── Tunnel credentials (resource-scoped, survive the bootstrap token) ──
  std::mutex tunnel_credential_mutex;
  std::unordered_map<std::string, TunnelCredential> tunnel_credentials;
  int tunnel_credential_ttl_seconds = 43200;  // 12h default
  int tunnel_credential_max_per_user = 32;

  // ── Relay control-plane state ──
  std::mutex relay_mutex;
  std::unordered_map<std::string, RelayNode> relays;
  std::unordered_map<int, std::string> resource_relay_bindings;
  std::unordered_map<std::string, RelayEnrollmentToken> relay_enrollment_tokens;
  std::unordered_map<std::string, RelayCertificate> relay_certificates;
  std::string relay_enroll_secret;
  bool relay_certificate_required = true;
  int relay_certificate_ttl_seconds = 2592000;  // 30d
  int relay_enrollment_token_ttl_seconds = 600;  // 10min
  int relay_token_ttl_seconds = 86400;  // 24h
  int relay_heartbeat_stale_seconds = 90;

  // ── Tunnel-agent inventory (populated from X-EndoriumFort-Agent-* headers) ──
  std::mutex agents_mutex;
  std::unordered_map<std::string, AgentInfo> agents;
  int agent_stale_seconds = 300;  // agent considered offline after 5 min silence

  // ── Cluster / HA control-plane state ──
  std::mutex cluster_mutex;
  std::unordered_map<std::string, ClusterPeerNode> cluster_peers;
  bool cluster_enabled = false;
  std::string cluster_node_id = "node-local";
  std::string cluster_node_label = "Primary Node";
  std::string cluster_advertise_addr;
  std::string cluster_role = "standalone";
  std::string cluster_shared_secret;
  int cluster_heartbeat_stale_seconds = 45;

  // ── License / entitlement state (freemium open-core) ──
  std::mutex license_mutex;
  std::string license_inline;     // ENDORIUMFORT_LICENSE (raw compact token)
  std::string license_file_path;  // ENDORIUMFORT_LICENSE_FILE
  std::string license_crl_path;   // ENDORIUMFORT_LICENSE_CRL_FILE
  bool license_signature_valid = false;   // hybrid signature verified at load
  license::LicenseClaims license_claims;  // cached claims (signature checked once)
  std::string license_invalid_reason;     // reason when signature invalid/absent
  int64_t license_clock_watermark = 0;    // highest epoch seen (anti-rollback)
  int64_t license_watermark_last_persist = 0;
  std::unordered_set<std::string> license_denylist;  // revoked licenseIds (CRL)

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
  // ── SSH WebSocket state ──
  std::mutex ws_mutex;
  std::unordered_map<crow::websocket::connection *,
                     std::shared_ptr<SshConnection>>
      ws_connections;

  // ── Shadow (admin live monitoring) state ──
  std::mutex shadow_mutex;
  std::unordered_map<int, std::vector<crow::websocket::connection *>>
      shadow_connections;  // session_id -> list of shadow watchers
#endif
#endif

  // ── Core operations ──
  std::string generate_token();
  std::optional<AuthSession> find_auth(const crow::request &req);
  std::optional<AuthSession> find_auth_by_token(const std::string &token);
  void append_audit(const AuditEvent &event);
  void append_session_event(const std::string &type, const Session &session);
  bool invalidate_token(const std::string &token);
  void invalidate_user_tokens(int user_id);
  void invalidate_user_tunnel_credentials(int user_id);
  void invalidate_user_tokens_except(int user_id, const std::string &token);
  void cleanup_expired_tokens();
  std::string compute_expiry();

  // ── Graceful shutdown hooks ──
  // Generic teardown registry (core). Premium background workers (e.g. the
  // scheduler in pro/) register a stop callback here so main.cc can tear them
  // down cleanly after the server loop returns. No premium code leaks into CE:
  // the hook is only ever populated when a pro module registers one.
  std::mutex shutdown_hooks_mutex;
  std::vector<std::function<void()>> shutdown_hooks;
  void register_shutdown_hook(std::function<void()> fn);
  void run_shutdown_hooks();

  // ── Security ──
  bool check_rate_limit(const std::string &key);
  void record_failed_login_attempt(const std::string &key);
  bool is_login_blocked(const std::string &key);
  void clear_login_attempts(const std::string &key);
  int get_consecutive_failures(const std::string &key);
  int record_anomaly_signal(const std::string &key,
                            std::chrono::seconds window);
  bool should_emit_anomaly_signal(const std::string &key,
                                  std::chrono::seconds cooldown);
  void clear_anomaly_signal(const std::string &key);
  bool is_safe_target(const std::string &host, bool allow_loopback = false);

  // ── DB init ──
  // Tests pass ":memory:" to get the real schema without a file.
  void init_database(const std::string &path = "endoriumfort.db");
  void seed_default_admin();

  // ── Session CRUD ──
  void load_sessions_from_db();
  bool insert_session(const Session &session);
  bool update_session_termination(const Session &session);
  void terminate_session(int session_id, const std::string &actor,
                         const std::string &role, const std::string &event_type);

  // ── Resource CRUD ──
  void load_resources_from_db();
  bool insert_resource(const Resource &resource);
  bool update_resource_db(const Resource &resource);
  bool delete_resource_db(int resource_id);

  // ── User CRUD ──
  void load_users_from_db();
  bool insert_user(const UserAccount &user);
  bool update_user_db(const UserAccount &user);
  bool delete_user_db(int user_id);

  // ── 2FA / TOTP ──
  bool update_user_totp(int user_id, bool enabled, const std::string &secret);
  bool update_user_mfa_preference(int user_id, const std::string &method);
  void load_webauthn_credentials_from_db();
  bool insert_webauthn_credential(const WebAuthnCredential &credential);
  bool update_webauthn_credential(const WebAuthnCredential &credential);
  bool delete_webauthn_credential(int credential_id);
  std::vector<WebAuthnCredential> get_user_webauthn_credentials(int user_id);
  std::optional<WebAuthnCredential> find_webauthn_credential_by_external_id(
      const std::string &credential_id);
  bool user_has_webauthn(int user_id);
  WebAuthnChallenge create_webauthn_challenge(int user_id,
                                              const std::string &username,
                                              const std::string &purpose,
                                              const std::string &rp_id,
                                              const std::string &origin);
  std::optional<WebAuthnChallenge> consume_webauthn_challenge(
      const std::string &request_id, int user_id, const std::string &purpose);
  void cleanup_expired_webauthn_challenges();

  // ── Password management ──
  bool update_user_password_hash(int user_id, const std::string &hash);
  bool update_user_bootstrap_flags(int user_id, bool password_change_required,
                                   bool mfa_required);

  // ── Session recordings ──
  void init_recordings_dir();
  bool insert_recording(const SessionRecording &rec);
  bool update_recording_close(const SessionRecording &rec);
  void load_recordings_from_db();

  // ── Session DNA chain ──
  bool append_session_dna_entry(int session_id, int audit_event_id,
                                const std::string &event_type,
                                const std::string &payload_json,
                                const std::string &created_at);
  std::vector<SessionDnaEntry> get_session_dna_chain(int session_id);

  // ── Access request CRUD ──
  void load_access_requests_from_db();
  bool insert_access_request(const AccessRequest &req);
  bool update_access_request(const AccessRequest &req);

  // ── Behavior counters ──
  void increment_session_input_event(int session_id);
  int64_t consume_session_input_events(int session_id);

  // ── Ephemeral credential lease CRUD ──
  void load_ephemeral_credentials_from_db();
  bool insert_ephemeral_credential(const EphemeralCredentialLease &lease);
  bool update_ephemeral_credential(const EphemeralCredentialLease &lease);

  // ── Permissions ──
  std::vector<int> get_resource_permissions(int user_id);
  bool grant_resource_permission(int user_id, int resource_id);
  bool revoke_resource_permission(int user_id, int resource_id);

  std::unordered_set<std::string> get_effective_permissions(
      int user_id, const std::string &role);
  bool has_permission(int user_id, const std::string &role,
                      const std::string &permission);

  // ── Session ownership ──
  // The person who opened a session is the subject of its access grant;
  // Session::user is the account on the target, not that person. "" if unknown.
  std::string session_owner(const Session &session);
  // Subjects of all access grants, keyed by grant id (one query for a list).
  std::unordered_map<int, std::string> access_grant_subjects();
  // Journal readers (admins, auditors) see every session; others only theirs.
  bool may_see_session(int user_id, const std::string &user,
                       const std::string &role, const std::string &owner);
  // Resource managers (admins) may act on any session (end it); others only
  // on theirs.
  bool may_operate_session(int user_id, const std::string &user,
                           const std::string &role, const std::string &owner);
  // Driving a session (typing in its shell, its VNC or RBI screen, a
  // Kubernetes exec) is for its owner only, administrators included: the
  // vaulted credential is injected for whoever drives it, so anyone else would
  // act under the owner's name. Administrators observe or end instead.
  bool may_drive_session(const std::string &user, const std::string &owner);

  // ── License / entitlement (defined in license.cc) ──
  void load_license_watermark();                  // read watermark from DB
  void reload_license();                          // (re)read env/file + verify
  license::LicenseStatus current_license_status();  // cheap temporal re-eval
  std::string effective_tier();                   // "free"|"pro"|"enterprise"
  bool license_allows_feature(const std::string &feature);  // license-only gate
  bool feature_active(const std::string &feature);  // license AND env flag
};
