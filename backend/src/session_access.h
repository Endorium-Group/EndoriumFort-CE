#pragma once
// ─── EndoriumFort — policy-checked session opening ──────────────────────
// The access decision behind POST /api/sessions (JIT policies, reason, ticket,
// purpose, approval, MFA posture, containment), shared with the agent tunnel
// routes so a tunnel cannot be opened on looser terms than a session.

#include "models.h"

#include <cstdint>
#include <string>

struct AppContext;

struct SessionOpenRequest {
  int resourceId = 0;
  std::string target;
  std::string user;
  std::string protocol;
  int port = 22;
  std::string justification;
  std::string ticketId;
  std::string purpose;
  std::string purposeEvidence;
  std::string missionRef;
  int accessRequestId = 0;
};

struct SessionOpenResult {
  bool ok = false;
  int status = 0;
  std::string error;
  Session session;

  static SessionOpenResult failure(int status, std::string error) {
    SessionOpenResult result;
    result.status = status;
    result.error = std::move(error);
    return result;
  }
};

// Runs the access decision for `auth` and, when it allows the access, records
// the access grant and the session with their audit events. On refusal the
// result carries the HTTP status and message POST /api/sessions returns.
SessionOpenResult open_session_with_policy(AppContext &ctx,
                                           const AuthSession &auth,
                                           const SessionOpenRequest &request);

struct TunnelSessionCheck {
  bool ok = false;
  int status = 403;
  std::string error;
  // When the session's grant came from a JIT policy, the tunnel must stop at
  // the grant expiry (epoch seconds). 0 = no cap beyond the session itself.
  int64_t grantExpiresEpoch = 0;
};

// Whether an agent tunnel for `resource_id` may run under `session_id`: the
// session must be active, on that resource, opened by `user`, and its access
// grant still issued and unexpired.
TunnelSessionCheck check_tunnel_session(AppContext &ctx, const std::string &user,
                                        int session_id, int resource_id);
