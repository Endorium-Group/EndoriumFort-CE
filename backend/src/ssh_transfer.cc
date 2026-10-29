// ─── EndoriumFort — SSH file transfer (SFTP, SCP fallback) ────────────────────
// Browse, download and upload files on the target of an active SSH session,
// from the session page. Core feature (every edition). Gated by the resource's
// own per-direction switches (allowFileDownload / allowFileUpload, off by
// default) and, like the terminal, only the operator who opened the session
// may use it.
//
// Each request opens its own SSH connection (the shell's session is non
// blocking and owned by its reader thread), logged in as the identity the
// terminal used — kept in memory while the session lives — or else with the
// resource's vaulted password. SFTP first; targets without the SFTP subsystem
// (network gear, appliances) fall back to SCP, which cannot list directories.
//
// Files go through a staging area on the bastion so a download is streamed to
// the browser from disk, an upload reaches the target only once complete and
// within ENDORIUMFORT_SSH_TRANSFER_MAX_UPLOAD_MB, and both are hashed (SHA-256)
// for the audit trail.
//
//   GET  /api/sessions/<id>/files?path=           list a directory (SFTP)
//   GET  /api/sessions/<id>/files/download?path=  download a file
//   POST /api/sessions/<id>/files/upload?path=&uploadId=&offset=&final=&overwrite=
//        raw chunk in the body; chunks are appended in order, `final=1` pushes
//        the staged file to the target.

#include "app_context.h"
#include "models.h"
#include "route_common.h"
#include "routes.h"
#include "ssh.h"
#include "utils.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <string>
#include <vector>

#if defined(ENDORIUMFORT_SSH_ENABLED) && !defined(_WIN32)
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <openssl/evp.h>
#include <unistd.h>
#endif

namespace {

constexpr const char *kMaxUploadKey = "ENDORIUMFORT_SSH_TRANSFER_MAX_UPLOAD_MB";

#if defined(ENDORIUMFORT_SSH_ENABLED) && !defined(_WIN32)

constexpr size_t kMaxChunkBytes = 6 * 1024 * 1024;  // nginx allows 8 MB here
constexpr size_t kIoBlock = 64 * 1024;
constexpr int kMaxListEntries = 5000;
constexpr long kSshTimeoutMs = 30000;
// A served download only has to outlive the moment Crow opens it to stream it
// (unlinking an open file is safe); an upload may be resumed for a while.
constexpr auto kDownloadStagingMaxAge = std::chrono::minutes(5);
constexpr auto kUploadStagingMaxAge = std::chrono::minutes(30);

namespace fs = std::filesystem;

int max_upload_mb() { return env_int_value(kMaxUploadKey, 100, 1, 10240); }

// ── Staging area ────────────────────────────────────────────────────────────

fs::path staging_dir() {
  // Relative to the working directory, i.e. /app/data in the image (the
  // persistent volume, which has the room a /tmp may not).
  static const fs::path dir = fs::absolute("transfer-staging");
  std::error_code ec;
  fs::create_directories(dir, ec);
  fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
  return dir;
}

// Drops downloads already served and uploads abandoned half-way.
void sweep_staging() {
  std::error_code ec;
  const auto now = fs::file_time_type::clock::now();
  for (const auto &entry : fs::directory_iterator(staging_dir(), ec)) {
    std::error_code item_ec;
    const auto written = fs::last_write_time(entry.path(), item_ec);
    const bool download = entry.path().filename().string().rfind("dl-", 0) == 0;
    const auto max_age = download ? kDownloadStagingMaxAge : kUploadStagingMaxAge;
    if (!item_ec && now - written > max_age) fs::remove(entry.path(), item_ec);
  }
}

std::string random_hex(size_t bytes) {
  static thread_local std::mt19937_64 rng{std::random_device{}()};
  static const char *digits = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < bytes; ++i) {
    const auto b = static_cast<unsigned>(rng() & 0xff);
    out += digits[b >> 4];
    out += digits[b & 0xf];
  }
  return out;
}

// ── Hashing ─────────────────────────────────────────────────────────────────

class Sha256 {
 public:
  Sha256() : ctx_(EVP_MD_CTX_new()) { EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr); }
  ~Sha256() { EVP_MD_CTX_free(ctx_); }
  Sha256(const Sha256 &) = delete;
  Sha256 &operator=(const Sha256 &) = delete;
  void update(const char *data, size_t len) { EVP_DigestUpdate(ctx_, data, len); }
  std::string hex() {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx_, md, &len);
    static const char *digits = "0123456789abcdef";
    std::string out;
    for (unsigned int i = 0; i < len; ++i) {
      out += digits[md[i] >> 4];
      out += digits[md[i] & 0xf];
    }
    return out;
  }

 private:
  EVP_MD_CTX *ctx_;
};

// ── SSH connection for one request ──────────────────────────────────────────

struct Link {
  int fd = -1;
  LIBSSH2_SESSION *session = nullptr;
  LIBSSH2_SFTP *sftp = nullptr;
  Link() = default;
  Link(const Link &) = delete;
  Link &operator=(const Link &) = delete;
  ~Link() {
    if (sftp) libssh2_sftp_shutdown(sftp);
    if (session) {
      libssh2_session_disconnect(session, "file transfer done");
      libssh2_session_free(session);
    }
    if (fd >= 0) close(fd);
  }
};

bool open_link(const Session &target, const std::string &user,
               const std::string &password, Link &link, std::string &error) {
  link.fd = open_tcp_socket(target.target, target.port, error);
  if (link.fd < 0) return false;
  link.session = libssh2_session_init();
  if (!link.session) {
    error = "libssh2 init failed";
    return false;
  }
  libssh2_session_set_blocking(link.session, 1);
  libssh2_session_set_timeout(link.session, kSshTimeoutMs);
  if (libssh2_session_handshake(link.session, link.fd) != 0) {
    error = "SSH handshake failed";
    return false;
  }
  if (libssh2_userauth_password(link.session, user.c_str(), password.c_str()) != 0) {
    error = "SSH authentication failed";
    return false;
  }
  return true;
}

// SFTP when the target offers it; false means "use SCP".
bool open_sftp(Link &link) {
  link.sftp = libssh2_sftp_init(link.session);
  return link.sftp != nullptr;
}

crow::response sftp_failure(Link &link, const std::string &what) {
  const unsigned long code = link.sftp ? libssh2_sftp_last_error(link.sftp) : 0;
  if (code == LIBSSH2_FX_NO_SUCH_FILE || code == LIBSSH2_FX_NO_SUCH_PATH)
    return crow::response(404, what + ": no such file or directory");
  if (code == LIBSSH2_FX_PERMISSION_DENIED)
    return crow::response(403, what + ": permission denied on the target");
  return crow::response(502, what + ": the target refused the request");
}

bool valid_remote_path(const std::string &path) {
  if (path.empty() || path.size() > 4096) return false;
  return std::none_of(path.begin(), path.end(), [](unsigned char c) {
    return c < 0x20 || c == 0x7f;  // NUL and line breaks included
  });
}

std::string base_name(const std::string &path) {
  std::string trimmed = path;
  while (trimmed.size() > 1 && trimmed.back() == '/') trimmed.pop_back();
  const auto slash = trimmed.rfind('/');
  return slash == std::string::npos ? trimmed : trimmed.substr(slash + 1);
}

std::string parent_of(const std::string &path) {
  if (path == "/") return "/";
  const auto slash = path.rfind('/');
  if (slash == std::string::npos) return ".";
  return slash == 0 ? "/" : path.substr(0, slash);
}

// Content-Disposition with an ASCII fallback and the exact UTF-8 name.
std::string attachment_header(const std::string &name) {
  std::string ascii, encoded;
  static const char *hex = "0123456789ABCDEF";
  for (unsigned char c : name) {
    ascii += (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') ? static_cast<char>(c) : '_';
    if (std::isalnum(c) || c == '.' || c == '-' || c == '_') {
      encoded += static_cast<char>(c);
    } else {
      encoded += '%';
      encoded += hex[c >> 4];
      encoded += hex[c & 0xf];
    }
  }
  if (ascii.empty()) ascii = "download";
  return "attachment; filename=\"" + ascii + "\"; filename*=UTF-8''" + encoded;
}

// ── Authorisation shared by the three routes ────────────────────────────────

enum class Need { List, Download, Upload };

struct Prepared {
  AuthSession auth;
  Session session;
  Resource resource;
  std::string user;
  std::string password;
};

void audit_transfer(AppContext &ctx, const std::string &type, const Prepared &p,
                    const std::string &extra_json) {
  AuditEvent event;
  event.id = ctx.next_audit_id.fetch_add(1);
  event.type = type;
  event.actor = p.auth.user;
  event.role = p.auth.role;
  event.createdAt = now_utc();
  event.payloadJson = "{\"sessionId\":" + std::to_string(p.session.id) +
                      ",\"resourceId\":" + std::to_string(p.resource.id) +
                      ",\"target\":\"" + json_escape(p.session.target) +
                      "\",\"account\":\"" + json_escape(p.user) + "\"" +
                      extra_json + "}";
  event.payloadIsJson = true;
  ctx.append_audit(event);
}

std::optional<crow::response> prepare(AppContext &ctx, const crow::request &request,
                                      int session_id, Need need, Prepared &out) {
  const auto auth = ctx.find_auth(request);
  if (!auth) return crow::response(401, "Unauthorized");
  if (!ctx.has_permission(auth->userId, auth->role, "ssh.connect"))
    return crow::response(403, "Forbidden");
  out.auth = *auth;

  {
    std::lock_guard<std::mutex> lock(ctx.session_mutex);
    const auto it = ctx.sessions.find(session_id);
    if (it == ctx.sessions.end()) return crow::response(404, "Session not found");
    out.session = it->second;
  }
  // Same rule as driving the terminal: only whoever opened the session.
  if (!ctx.may_drive_session(auth->user, ctx.session_owner(out.session)))
    return crow::response(404, "Session not found");
  if (out.session.status != "active") return crow::response(409, "Session closed");
  if (to_lower(out.session.protocol) != "ssh")
    return crow::response(400, "File transfer is only available on SSH sessions");

  {
    std::lock_guard<std::mutex> lock(ctx.resource_mutex);
    const auto it = ctx.resources.find(out.session.resourceId);
    if (it == ctx.resources.end()) return crow::response(404, "Resource not found");
    out.resource = it->second;
  }
  out.user = out.session.user;  // the target account, for the audit of a refusal
  const bool allowed =
      need == Need::Download ? out.resource.allowFileDownload
      : need == Need::Upload ? out.resource.allowFileUpload
                             : (out.resource.allowFileDownload || out.resource.allowFileUpload);
  if (!allowed) {
    audit_transfer(ctx, "ssh.file.denied", out,
                   std::string(",\"direction\":\"") +
                       (need == Need::Upload ? "upload" : need == Need::Download ? "download" : "list") +
                       "\",\"reason\":\"disabled_on_resource\"");
    return crow::response(403, "File transfer is disabled for this resource");
  }

  if (const auto identity = ctx.ssh_identity(session_id)) {
    out.user = identity->user;
    out.password = identity->password;
  } else if (!out.resource.sshPassword.empty()) {
    out.user = out.session.user;
    out.password = out.resource.sshPassword;
  } else {
    return crow::response(
        409, "Connect the terminal first: this session has no SSH credential yet");
  }
  return std::nullopt;
}

crow::json::wvalue policy_json(const Prepared &p) {
  crow::json::wvalue out;
  out["canDownload"] = p.resource.allowFileDownload;
  out["canUpload"] = p.resource.allowFileUpload;
  out["maxUploadMb"] = max_upload_mb();
  return out;
}

// ── Routes ──────────────────────────────────────────────────────────────────

crow::response list_directory(AppContext &ctx, const crow::request &request, int session_id) {
  Prepared p;
  if (auto denied = prepare(ctx, request, session_id, Need::List, p)) return std::move(*denied);
  const char *raw = request.url_params.get("path");
  const std::string asked = raw && *raw ? raw : ".";
  if (!valid_remote_path(asked)) return crow::response(400, "Invalid path");

  Link link;
  std::string error;
  if (!open_link(p.session, p.user, p.password, link, error)) return crow::response(502, error);

  crow::json::wvalue payload = policy_json(p);
  payload["status"] = "ok";
  if (!open_sftp(link)) {
    // SCP only: no listing, the operator types the path.
    payload["sftp"] = false;
    payload["path"] = asked;
    payload["entries"] = crow::json::wvalue::list();
    return crow::response{payload};
  }

  char resolved[4096];
  const int len = libssh2_sftp_realpath(link.sftp, asked.c_str(), resolved, sizeof(resolved) - 1);
  if (len <= 0) return sftp_failure(link, "Cannot open directory");
  const std::string path(resolved, static_cast<size_t>(len));

  LIBSSH2_SFTP_HANDLE *dir = libssh2_sftp_opendir(link.sftp, path.c_str());
  if (!dir) return sftp_failure(link, "Cannot open directory");

  struct Entry {
    std::string name, type;
    uint64_t size = 0;
    uint64_t mtime = 0;
  };
  std::vector<Entry> entries;
  bool truncated = false;
  char name[1024];
  LIBSSH2_SFTP_ATTRIBUTES attrs;
  while (libssh2_sftp_readdir(dir, name, sizeof(name), &attrs) > 0) {
    const std::string entry_name(name);
    if (entry_name == "." || entry_name == "..") continue;
    if (static_cast<int>(entries.size()) >= kMaxListEntries) {
      truncated = true;
      break;
    }
    Entry e;
    e.name = entry_name;
    e.type = "file";
    if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
      if (LIBSSH2_SFTP_S_ISDIR(attrs.permissions)) e.type = "dir";
      else if (LIBSSH2_SFTP_S_ISLNK(attrs.permissions)) e.type = "link";
    }
    if (e.type == "link") {
      // Follow it once so a link to a directory can be opened.
      LIBSSH2_SFTP_ATTRIBUTES target_attrs;
      const std::string full = (path == "/" ? "/" : path + "/") + entry_name;
      if (libssh2_sftp_stat(link.sftp, full.c_str(), &target_attrs) == 0 &&
          (target_attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
          LIBSSH2_SFTP_S_ISDIR(target_attrs.permissions))
        e.type = "dir";
    }
    if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) e.size = attrs.filesize;
    if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) e.mtime = attrs.mtime;
    entries.push_back(std::move(e));
  }
  libssh2_sftp_closedir(dir);

  std::sort(entries.begin(), entries.end(), [](const Entry &a, const Entry &b) {
    const bool a_dir = a.type == "dir", b_dir = b.type == "dir";
    if (a_dir != b_dir) return a_dir;
    return a.name < b.name;
  });

  payload["sftp"] = true;
  payload["path"] = path;
  payload["parent"] = parent_of(path);
  payload["truncated"] = truncated;
  payload["entries"] = crow::json::wvalue::list();
  for (size_t i = 0; i < entries.size(); ++i) {
    auto &out = payload["entries"][static_cast<int>(i)];
    out["name"] = entries[i].name;
    out["type"] = entries[i].type;
    out["size"] = entries[i].size;
    out["mtime"] = entries[i].mtime;
  }
  return crow::response{payload};
}

crow::response download_file(AppContext &ctx, const crow::request &request, int session_id) {
  Prepared p;
  if (auto denied = prepare(ctx, request, session_id, Need::Download, p)) return std::move(*denied);
  const char *raw = request.url_params.get("path");
  const std::string path = raw ? raw : "";
  if (!valid_remote_path(path)) return crow::response(400, "Invalid path");

  Link link;
  std::string error;
  if (!open_link(p.session, p.user, p.password, link, error)) return crow::response(502, error);

  sweep_staging();
  const fs::path staged = staging_dir() / ("dl-" + random_hex(16));
  std::ofstream out(staged, std::ios::binary | std::ios::trunc);
  if (!out) return crow::response(500, "Cannot stage the file on the bastion");
  std::error_code perm_ec;
  fs::permissions(staged, fs::perms::owner_read | fs::perms::owner_write,
                  fs::perm_options::replace, perm_ec);

  Sha256 digest;
  uint64_t size = 0;
  std::string via;
  std::vector<char> buffer(kIoBlock);
  bool complete = false;

  if (open_sftp(link)) {
    via = "sftp";
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    if (libssh2_sftp_stat(link.sftp, path.c_str(), &attrs) != 0) {
      out.close();
      fs::remove(staged);
      return sftp_failure(link, "Cannot read file");
    }
    if ((attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
        LIBSSH2_SFTP_S_ISDIR(attrs.permissions)) {
      out.close();
      fs::remove(staged);
      return crow::response(400, "This is a directory");
    }
    LIBSSH2_SFTP_HANDLE *file =
        libssh2_sftp_open(link.sftp, path.c_str(), LIBSSH2_FXF_READ, 0);
    if (!file) {
      out.close();
      fs::remove(staged);
      return sftp_failure(link, "Cannot read file");
    }
    ssize_t n;
    while ((n = libssh2_sftp_read(file, buffer.data(), buffer.size())) > 0) {
      out.write(buffer.data(), n);
      digest.update(buffer.data(), static_cast<size_t>(n));
      size += static_cast<uint64_t>(n);
    }
    complete = n == 0;
    libssh2_sftp_close(file);
  } else {
    via = "scp";
    libssh2_struct_stat st{};
    LIBSSH2_CHANNEL *channel = libssh2_scp_recv2(link.session, path.c_str(), &st);
    if (!channel) {
      out.close();
      fs::remove(staged);
      return crow::response(404, "Cannot read file: not found or not readable over SCP");
    }
    const uint64_t expected = static_cast<uint64_t>(st.st_size);
    while (size < expected) {
      const size_t want = static_cast<size_t>(std::min<uint64_t>(buffer.size(), expected - size));
      const ssize_t n = libssh2_channel_read(channel, buffer.data(), want);
      if (n <= 0) break;
      out.write(buffer.data(), n);
      digest.update(buffer.data(), static_cast<size_t>(n));
      size += static_cast<uint64_t>(n);
    }
    complete = size == expected;
    libssh2_channel_free(channel);
  }
  out.close();
  if (!complete || !out) {
    fs::remove(staged);
    return crow::response(502, "The transfer from the target was interrupted");
  }

  const std::string sha = digest.hex();
  audit_transfer(ctx, "ssh.file.download", p,
                 ",\"path\":\"" + json_escape(path) + "\",\"size\":" +
                     std::to_string(size) + ",\"sha256\":\"" + sha +
                     "\",\"via\":\"" + via + "\"");

  // Streamed from disk by Crow; the staging sweep removes it afterwards.
  crow::response res;
  res.set_static_file_info_unsafe(staged.string());
  res.set_header("Content-Type", "application/octet-stream");
  res.set_header("Content-Disposition", attachment_header(base_name(path)));
  res.set_header("X-EndoriumFort-SHA256", sha);
  return res;
}

crow::response upload_chunk(AppContext &ctx, const crow::request &request, int session_id) {
  Prepared p;
  if (auto denied = prepare(ctx, request, session_id, Need::Upload, p)) return std::move(*denied);

  const char *raw_path = request.url_params.get("path");
  const char *raw_id = request.url_params.get("uploadId");
  const char *raw_offset = request.url_params.get("offset");
  const std::string path = raw_path ? raw_path : "";
  const std::string upload_id = raw_id ? raw_id : "";
  const bool final = request.url_params.get("final") &&
                     std::string(request.url_params.get("final")) == "1";
  const bool overwrite = request.url_params.get("overwrite") &&
                         std::string(request.url_params.get("overwrite")) == "1";
  if (!valid_remote_path(path)) return crow::response(400, "Invalid path");
  if (upload_id.size() < 8 || upload_id.size() > 64 ||
      !std::all_of(upload_id.begin(), upload_id.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '_';
      }))
    return crow::response(400, "Invalid uploadId");
  int64_t offset = -1;
  try {
    offset = raw_offset ? std::stoll(raw_offset) : -1;
  } catch (...) {
  }
  if (offset < 0) return crow::response(400, "Invalid offset");
  if (request.body.size() > kMaxChunkBytes) return crow::response(413, "Chunk too large");

  // Bound to the session and the user, so nobody else can append to it.
  const fs::path staged = staging_dir() / ("up-" + std::to_string(session_id) + "-" +
                                           std::to_string(p.auth.userId) + "-" + upload_id);
  std::error_code ec;
  if (offset == 0) {
    sweep_staging();
    fs::remove(staged, ec);  // a restarted upload starts over
    if (!overwrite) {
      // Refuse before the operator uploads a whole file for nothing.
      Link link;
      std::string error;
      if (!open_link(p.session, p.user, p.password, link, error))
        return crow::response(502, error);
      LIBSSH2_SFTP_ATTRIBUTES attrs;
      if (open_sftp(link) && libssh2_sftp_stat(link.sftp, path.c_str(), &attrs) == 0) {
        crow::json::wvalue body;
        body["error"] = "exists";
        body["message"] = "A file already exists at this path";
        crow::response res(409, body.dump());
        res.set_header("Content-Type", "application/json");
        return res;
      }
    }
  }
  const uint64_t current = fs::exists(staged, ec) ? fs::file_size(staged, ec) : 0;
  if (static_cast<uint64_t>(offset) != current) {
    crow::json::wvalue body;
    body["error"] = "offset_mismatch";
    body["expected"] = current;
    crow::response res(409, body.dump());
    res.set_header("Content-Type", "application/json");
    return res;
  }

  const uint64_t limit = static_cast<uint64_t>(max_upload_mb()) * 1024 * 1024;
  const uint64_t total = current + request.body.size();
  if (total > limit) {
    fs::remove(staged, ec);
    audit_transfer(ctx, "ssh.file.denied", p,
                   ",\"direction\":\"upload\",\"reason\":\"too_large\",\"path\":\"" +
                       json_escape(path) + "\",\"limitMb\":" +
                       std::to_string(max_upload_mb()));
    return crow::response(413, "File exceeds the maximum upload size (" +
                                   std::to_string(max_upload_mb()) + " MB)");
  }
  {
    std::ofstream out(staged, std::ios::binary | std::ios::app);
    if (!out) return crow::response(500, "Cannot stage the file on the bastion");
    out.write(request.body.data(), static_cast<std::streamsize>(request.body.size()));
    if (!out) return crow::response(500, "Cannot stage the file on the bastion");
  }
  fs::permissions(staged, fs::perms::owner_read | fs::perms::owner_write,
                  fs::perm_options::replace, ec);

  if (!final) {
    crow::json::wvalue body;
    body["status"] = "partial";
    body["received"] = total;
    return crow::response{body};
  }

  // ── Complete: push the staged file to the target ──
  Link link;
  std::string error;
  if (!open_link(p.session, p.user, p.password, link, error)) {
    fs::remove(staged, ec);
    return crow::response(502, error);
  }
  std::ifstream in(staged, std::ios::binary);
  if (!in) return crow::response(500, "Cannot read the staged file");
  Sha256 digest;
  std::vector<char> buffer(kIoBlock);
  std::string via;
  bool complete = true;

  // Writes all of [data, data+len) through `write`, which may write less.
  const auto write_all = [](auto &&write, const char *data, size_t len) {
    while (len > 0) {
      const ssize_t n = write(data, len);
      if (n <= 0) return false;
      data += n;
      len -= static_cast<size_t>(n);
    }
    return true;
  };

  if (open_sftp(link)) {
    via = "sftp";
    LIBSSH2_SFTP_HANDLE *file = libssh2_sftp_open(
        link.sftp, path.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
        LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR | LIBSSH2_SFTP_S_IRGRP |
            LIBSSH2_SFTP_S_IROTH);
    if (!file) {
      fs::remove(staged, ec);
      return sftp_failure(link, "Cannot write file");
    }
    while (complete && in) {
      in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
      const auto got = static_cast<size_t>(in.gcount());
      if (got == 0) break;
      digest.update(buffer.data(), got);
      complete = write_all([&](const char *d, size_t l) { return libssh2_sftp_write(file, d, l); },
                           buffer.data(), got);
    }
    libssh2_sftp_close(file);
  } else {
    via = "scp";  // no existence check possible: SCP always replaces
    LIBSSH2_CHANNEL *channel =
        libssh2_scp_send64(link.session, path.c_str(), 0644,
                           static_cast<libssh2_int64_t>(total), 0, 0);
    if (!channel) {
      fs::remove(staged, ec);
      return crow::response(502, "Cannot write file: the target refused it over SCP");
    }
    while (complete && in) {
      in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
      const auto got = static_cast<size_t>(in.gcount());
      if (got == 0) break;
      digest.update(buffer.data(), got);
      complete = write_all([&](const char *d, size_t l) { return libssh2_channel_write(channel, d, l); },
                           buffer.data(), got);
    }
    libssh2_channel_send_eof(channel);
    libssh2_channel_wait_eof(channel);
    libssh2_channel_wait_closed(channel);
    libssh2_channel_free(channel);
  }
  in.close();
  fs::remove(staged, ec);
  if (!complete) return crow::response(502, "The transfer to the target was interrupted");

  const std::string sha = digest.hex();
  audit_transfer(ctx, "ssh.file.upload", p,
                 ",\"path\":\"" + json_escape(path) + "\",\"size\":" +
                     std::to_string(total) + ",\"sha256\":\"" + sha +
                     "\",\"via\":\"" + via + "\",\"overwrite\":" +
                     (overwrite ? "true" : "false"));
  crow::json::wvalue body;
  body["status"] = "ok";
  body["path"] = path;
  body["size"] = total;
  body["sha256"] = sha;
  body["via"] = via;
  return crow::response{body};
}

#endif  // ENDORIUMFORT_SSH_ENABLED && !_WIN32

}  // namespace

void register_ssh_transfer_routes(CrowApp &app, AppContext &ctx) {
#if defined(ENDORIUMFORT_SSH_ENABLED) && !defined(_WIN32)
  CROW_ROUTE(app, "/api/sessions/<int>/files")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request, int session_id) {
        return list_directory(ctx, request, session_id);
      });
  CROW_ROUTE(app, "/api/sessions/<int>/files/download")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request, int session_id) {
        return download_file(ctx, request, session_id);
      });
  CROW_ROUTE(app, "/api/sessions/<int>/files/upload")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request, int session_id) {
        return upload_chunk(ctx, request, session_id);
      });
#else
  (void)app;
  (void)ctx;
  (void)kMaxUploadKey;
#endif
}
