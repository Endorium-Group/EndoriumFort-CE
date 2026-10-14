// Covers the SIEM pipeline's formatting layer: event classification, the flat
// field model, JSON hygiene and the syslog wire format. The transports are not
// exercised here — they need a listener — but everything that decides what
// bytes go on the wire is.
#include "pro/siem.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

siem::Origin test_origin() {
  siem::Origin origin;
  origin.host = "bastion-1";
  origin.node = "node-a";
  origin.product = "endoriumfort";
  origin.version = "1.0.35";
  return origin;
}

AuditEvent make_event(const std::string &type, const std::string &payload) {
  AuditEvent event;
  event.id = 42;
  event.type = type;
  event.actor = "alice";
  event.role = "admin";
  event.createdAt = "2026-10-14T08:30:00Z";
  event.payloadJson = payload;
  event.payloadIsJson = !payload.empty();
  return event;
}

std::string field(const siem::Fields &fields, const std::string &key) {
  for (const auto &entry : fields) {
    if (entry.first == key) return entry.second;
  }
  return "<missing>";
}

bool has_field(const siem::Fields &fields, const std::string &key) {
  return std::any_of(fields.begin(), fields.end(),
                     [&](const std::pair<std::string, std::string> &entry) {
                       return entry.first == key;
                     });
}

// Minimal structural check: balanced quoting and no raw control characters,
// which is what a receiver rejects a batch over.
bool looks_like_flat_json(const std::string &json) {
  if (json.size() < 2 || json.front() != '{' || json.back() != '}') return false;
  bool in_string = false;
  bool escaped = false;
  for (size_t i = 1; i + 1 < json.size(); ++i) {
    const unsigned char ch = static_cast<unsigned char>(json[i]);
    if (ch < 0x20) return false;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch == '\\') {
      escaped = true;
      continue;
    }
    if (ch == '"') in_string = !in_string;
  }
  return !in_string;
}

}  // namespace

int main() {
  bool ok = true;

  // ── Classification ───────────────────────────────────────────────────────
  {
    ok &= expect(siem::severity_for_type("itdr.incident.opened") == "critical",
                 "an incident is critical");
    ok &= expect(siem::severity_for_type("session.containment.applied") == "critical",
                 "containment is critical");
    ok &= expect(siem::severity_for_type("behavior.anomaly.command_spike") == "warning",
                 "an anomaly is a warning, not an error");
    ok &= expect(siem::severity_for_type("auth.login.failure") == "error",
                 "a login failure is an error");
    ok &= expect(siem::severity_for_type("command_guard.block") == "error",
                 "a blocked command is an error");
    ok &= expect(siem::severity_for_type("resource.create") == "notice",
                 "an administrative change is a notice");
    ok &= expect(siem::severity_for_type("session.create") == "info",
                 "ordinary activity is informational");

    ok &= expect(siem::syslog_severity_code("critical") == 2, "critical maps to 2");
    ok &= expect(siem::syslog_severity_code("error") == 3, "error maps to 3");
    ok &= expect(siem::syslog_severity_code("warning") == 4, "warning maps to 4");
    ok &= expect(siem::syslog_severity_code("notice") == 5, "notice maps to 5");
    ok &= expect(siem::syslog_severity_code("info") == 6, "info maps to 6");

    ok &= expect(siem::outcome_for_type("command_guard.block") == "denied",
                 "a block is a denial");
    ok &= expect(siem::outcome_for_type("security.tunnel.ticket.rate_limited") == "denied",
                 "rate limiting is a denial");
    ok &= expect(siem::outcome_for_type("auth.login.failure") == "failure",
                 "a failure is a failure");
    ok &= expect(siem::outcome_for_type("session.create") == "success",
                 "anything else succeeded");
  }

  // ── Field model ──────────────────────────────────────────────────────────
  {
    const auto event = make_event(
        "session.create",
        R"({"sessionId":12,"resourceId":7,"resourceName":"srv-01","target":"10.0.0.5",)"
        R"("protocol":"ssh","sourceIp":"192.0.2.9","username":"root","ttlSeconds":900})");
    const auto fields = siem::event_fields(test_origin(), event);

    ok &= expect(field(fields, "_time") == "2026-10-14T08:30:00Z", "_time is the event time");
    ok &= expect(field(fields, "event_type") == "session.create", "the type is carried");
    ok &= expect(field(fields, "event_category") == "session", "the category is the first segment");
    ok &= expect(field(fields, "event_action") == "create", "the action is the rest");
    ok &= expect(field(fields, "severity") == "info", "the severity is stamped");
    ok &= expect(field(fields, "level") == "info", "level mirrors severity");
    ok &= expect(field(fields, "actor") == "alice", "the actor is carried");
    ok &= expect(field(fields, "actor_role") == "admin", "the role is carried");
    ok &= expect(field(fields, "host") == "bastion-1", "the emitting host is stamped");
    ok &= expect(field(fields, "node_id") == "node-a", "the cluster node is stamped");
    ok &= expect(field(fields, "event_id") == "42", "the audit id is carried");

    // Promoted payload keys get stable names a detection rule can rely on.
    ok &= expect(field(fields, "session_id") == "12", "sessionId is promoted");
    ok &= expect(field(fields, "resource_id") == "7", "resourceId is promoted");
    ok &= expect(field(fields, "resource_name") == "srv-01", "resourceName is promoted");
    ok &= expect(field(fields, "source_ip") == "192.0.2.9", "sourceIp is promoted");
    ok &= expect(field(fields, "target") == "10.0.0.5", "target is promoted");
    ok &= expect(field(fields, "protocol") == "ssh", "protocol is promoted");
    ok &= expect(field(fields, "target_user") == "root", "username is promoted");
    // Everything else keeps its name behind a prefix that cannot collide.
    ok &= expect(field(fields, "ef_ttlSeconds") == "900", "unknown keys are prefixed");
    ok &= expect(!has_field(fields, "ttlSeconds"), "unknown keys are never bare");

    const std::string summary = field(fields, "_msg");
    ok &= expect(summary.find("session.create by alice") == 0, "the summary leads with the event");
    ok &= expect(summary.find("srv-01") != std::string::npos, "the summary names the resource");
    ok &= expect(summary.find("192.0.2.9") != std::string::npos, "the summary names the source");
  }

  {
    // A payload must not be able to overwrite the classification or the origin.
    const auto event = make_event(
        "auth.login.failure",
        R"({"actor":"attacker","host":"evil","severity":"info","_time":"1970-01-01T00:00:00Z"})");
    const auto fields = siem::event_fields(test_origin(), event);
    ok &= expect(field(fields, "actor") == "alice", "the payload cannot spoof the actor");
    ok &= expect(field(fields, "host") == "bastion-1", "the payload cannot spoof the host");
    ok &= expect(field(fields, "severity") == "error", "the payload cannot spoof the severity");
    ok &= expect(field(fields, "_time") == "2026-10-14T08:30:00Z",
                 "the payload cannot spoof the timestamp");
    ok &= expect(field(fields, "ef_actor") == "attacker", "the payload value is kept, prefixed");
  }

  {
    // Nested structures are flattened, then kept verbatim past the depth cap.
    const auto event = make_event("resource.update",
                                  R"({"policy":{"mfa":{"required":true,"methods":["totp"]}}})");
    const auto fields = siem::event_fields(test_origin(), event);
    ok &= expect(field(fields, "ef_policy_mfa_required") == "true", "nested scalars are flattened");
    ok &= expect(field(fields, "ef_policy_mfa_methods").find("totp") != std::string::npos,
                 "a list is kept as JSON text");
  }

  {
    // A non-JSON payload still ships, as one field.
    AuditEvent event = make_event("note.added", "");
    event.payloadJson = "plain text note";
    event.payloadIsJson = false;
    const auto fields = siem::event_fields(test_origin(), event);
    ok &= expect(field(fields, "ef_payload") == "plain text note", "a text payload is kept");
  }

  // ── JSON hygiene ─────────────────────────────────────────────────────────
  {
    AuditEvent event = make_event("web.proxy_access", "");
    // Audit payloads carry target-controlled text: an invalid UTF-8 byte, a raw
    // newline and a quote must not be able to break a receiver's parser.
    event.payloadJson = std::string("{\"reason\":\"caf\xe8 \nbreak \\\"quoted\\\"\"}");
    event.payloadIsJson = true;
    const auto json = siem::fields_to_json(siem::event_fields(test_origin(), event));
    ok &= expect(looks_like_flat_json(json), "the rendering stays well-formed JSON");
    ok &= expect(json.find('\n') == std::string::npos, "no raw newline survives");
    ok &= expect(json.find("\xe8") == std::string::npos, "invalid UTF-8 is replaced");
  }

  {
    // Valid multi-byte UTF-8 must survive untouched.
    AuditEvent event = make_event("session.create", R"({"reason":"accès validé ✅"})");
    const auto json = siem::fields_to_json(siem::event_fields(test_origin(), event));
    ok &= expect(json.find("accès validé ✅") != std::string::npos, "valid UTF-8 is preserved");
  }

  {
    // One oversized value cannot blow up an event.
    AuditEvent event = make_event("command_guard.block", "");
    event.payloadJson = "{\"reason\":\"" + std::string(9000, 'A') + "\"}";
    event.payloadIsJson = true;
    const auto fields = siem::event_fields(test_origin(), event);
    ok &= expect(field(fields, "reason").size() == 9000, "the field model keeps the raw value");
    const auto json = siem::fields_to_json(fields);
    ok &= expect(json.size() < 9000, "the rendering truncates it");
    ok &= expect(looks_like_flat_json(json), "a truncated value still renders valid JSON");
  }

  // ── Syslog wire format ───────────────────────────────────────────────────
  {
    siem::SyslogConfig config;
    config.host = "victorialogs";
    config.facility = 13;  // log audit
    config.appName = "endoriumfort";
    const auto event = make_event("auth.login.failure", R"({"sourceIp":"192.0.2.9"})");
    const std::string line = siem::syslog_line(config, test_origin(), event);

    // facility 13 * 8 + severity 3 (error) = 107
    ok &= expect(line.find("<107>1 ") == 0, "PRI combines facility and severity, RFC 5424 version 1");
    ok &= expect(line.find(" 2026-10-14T08:30:00Z bastion-1 endoriumfort ") != std::string::npos,
                 "the header carries the timestamp, host and app name");
    ok &= expect(line.find("[endoriumfort@0 severity=\"error\"") != std::string::npos,
                 "structured data repeats the routing fields");
    ok &= expect(line.find("outcome=\"failure\"") != std::string::npos,
                 "structured data carries the outcome");
    ok &= expect(line.find("@cee: {") != std::string::npos,
                 "the message is a @cee JSON object by default");
    const size_t cee = line.find("@cee: ");
    ok &= expect(cee != std::string::npos && looks_like_flat_json(line.substr(cee + 6)),
                 "the @cee payload is a well-formed object with nothing trailing");
    ok &= expect(line.find('\n') == std::string::npos, "a syslog line never contains a newline");
  }

  {
    siem::SyslogConfig config;
    config.host = "victorialogs";
    config.message = "text";
    const auto event = make_event("session.close", R"({"sessionId":3})");
    const std::string line = siem::syslog_line(config, test_origin(), event);
    ok &= expect(line.find("@cee") == std::string::npos, "text mode ships no JSON");
    ok &= expect(line.find("session.close by alice") != std::string::npos,
                 "text mode ships the human summary");
  }

  {
    siem::SyslogConfig config;
    config.host = "victorialogs";
    config.format = "rfc3164";
    config.message = "json";
    const auto event = make_event("session.create", "{}");
    const std::string line = siem::syslog_line(config, test_origin(), event);
    ok &= expect(line.find("<110>") == 0, "RFC 3164 keeps the same priority");
    ok &= expect(line.find("<110>1 ") == std::string::npos, "RFC 3164 carries no version digit");
    ok &= expect(line.find("Oct 14 08:30:00 bastion-1 endoriumfort: ") != std::string::npos,
                 "RFC 3164 uses the legacy timestamp and tag");
  }

  {
    // An oversized event is truncated to the configured transport limit.
    siem::SyslogConfig config;
    config.host = "victorialogs";
    config.maxMessageBytes = 512;
    AuditEvent event = make_event("command_guard.block", "");
    event.payloadJson = "{\"reason\":\"" + std::string(4000, 'B') + "\"}";
    event.payloadIsJson = true;
    const std::string line = siem::syslog_line(config, test_origin(), event);
    ok &= expect(line.size() == 512, "the line is capped at maxMessageBytes");
  }

  // ── Transport framing ────────────────────────────────────────────────────
  {
    const std::string line = "<107>1 2026-10-14T08:30:00Z bastion-1 app - - msg";
    const std::string octet = siem::frame_syslog(line, "octet");
    ok &= expect(octet == std::to_string(line.size()) + " " + line,
                 "octet counting prefixes the exact byte count");
    const size_t space = octet.find(' ');
    ok &= expect(octet.substr(space + 1).size() == line.size(),
                 "the announced count matches the payload");
    ok &= expect(siem::frame_syslog(line, "lf") == line + "\n",
                 "newline framing appends a single delimiter");
  }

  // ── Destination redaction ────────────────────────────────────────────────
  {
    // The channel API is readable by any operator with `resources.manage`, so a
    // secret an operator put in the URL must not be handed back.
    ok &= expect(siem::redact_url("https://user:s3cret@splunk:8088/services/collector") ==
                     "https://***@splunk:8088/services/collector",
                 "userinfo is masked");
    ok &= expect(siem::redact_url("http://vl:9428/insert/jsonline?_msg_field=_msg&token=abc123") ==
                     "http://vl:9428/insert/jsonline?_msg_field=_msg&token=***",
                 "a secret-looking parameter is masked, the rest is kept");
    ok &= expect(siem::redact_url("http://vl:9428/insert/jsonline?_stream_fields=host,event_category") ==
                     "http://vl:9428/insert/jsonline?_stream_fields=host,event_category",
                 "an ordinary query string is left alone");
    ok &= expect(siem::redact_url("") == "", "an empty URL stays empty");
  }

  // ── Catalog ──────────────────────────────────────────────────────────────
  {
    ok &= expect(siem::channel_implemented("syslog"), "syslog ships in this build");
    ok &= expect(siem::channel_implemented("json_webhook"), "the webhook ships in this build");
    ok &= expect(siem::channel_implemented("splunk"), "Splunk HEC ships in this build");
    ok &= expect(!siem::channel_implemented("sentinel"), "Sentinel has no transport yet");
    ok &= expect(siem::channel_catalog().size() == 4, "the catalog lists every channel");
  }

  if (ok) std::cout << "siem tests passed" << std::endl;
  return ok ? 0 : 1;
}
