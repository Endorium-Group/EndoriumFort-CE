// End-to-end test of the database proxy: a throw-away PostgreSQL cluster
// (SCRAM-SHA-256, TLS), the real `psql`, and db_proxy::Connection in between,
// bridged to a local TCP port the way the agent tunnel bridges it to a
// websocket. Skipped (exit 0) when the PostgreSQL binaries are not installed,
// when running as root (postgres refuses), or without a non-loopback IPv4
// address (the proxy refuses loopback targets by design).
//
// ENDORIUMFORT_PG_BIN overrides the directory holding initdb / pg_ctl.

#include "app_context.h"
#include "pro/db_guard.h"
#include "pro/db_proxy.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {
int failures = 0;
bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    ++failures;
  }
  return condition;
}

std::string find_pg_bin() {
  if (const char *env = std::getenv("ENDORIUMFORT_PG_BIN"); env && *env) return env;
  std::string best;
  if (fs::exists("/usr/lib/postgresql"))
    for (const auto &entry : fs::directory_iterator("/usr/lib/postgresql"))
      if (fs::exists(entry.path() / "bin" / "initdb") && entry.path().string() > best)
        best = entry.path().string();
  return best.empty() ? "" : best + "/bin";
}

// A local IPv4 address the proxy will dial: neither loopback nor link-local.
std::string routable_local_ipv4() {
  ifaddrs *list = nullptr;
  if (getifaddrs(&list) != 0) return "";
  std::string found;
  for (ifaddrs *it = list; it; it = it->ifa_next) {
    if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) continue;
    const uint32_t ip = ntohl(reinterpret_cast<sockaddr_in *>(it->ifa_addr)->sin_addr.s_addr);
    if ((ip >> 24) == 127 || (ip >> 16) == 0xA9FE || (ip >> 24) == 0) continue;
    char text[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(it->ifa_addr)->sin_addr, text, sizeof(text));
    found = text;
    break;
  }
  freeifaddrs(list);
  return found;
}

int free_port() {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
  socklen_t len = sizeof(addr);
  getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
  ::close(fd);
  return ntohs(addr.sin_port);
}

struct Run {
  int status = -1;
  std::string output;
};

Run run(const std::string &command) {
  Run result;
  FILE *pipe = popen((command + " 2>&1").c_str(), "r");
  if (!pipe) return result;
  char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), pipe)) > 0) result.output.append(buf, n);
  const int status = pclose(pipe);
  result.status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return result;
}

bool contains(const std::string &haystack, const std::string &needle) {
  return haystack.find(needle) != std::string::npos;
}

// Accepts local connections and runs one proxy per connection, like the
// websocket tunnel does for each agent connection.
class Bridge {
 public:
  Bridge(AppContext &ctx, db_proxy::Target target, db_proxy::Identity identity)
      : ctx_(ctx), target_(std::move(target)), identity_(std::move(identity)) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    const int one = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    ::listen(listen_fd_, 8);
    socklen_t len = sizeof(addr);
    getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len);
    port = ntohs(addr.sin_port);
    acceptor_ = std::thread([this] { accept_loop(); });
  }

  ~Bridge() {
    stopping_ = true;
    acceptor_.join();
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &t : workers_) t.join();
    ::close(listen_fd_);
  }

  void set_target(db_proxy::Target target) {
    std::lock_guard<std::mutex> lock(mutex_);
    target_ = std::move(target);
  }
  void set_guard(bool guard) {
    std::lock_guard<std::mutex> lock(mutex_);
    identity_.guard = guard;
  }

  int port = 0;

 private:
  void accept_loop() {
    while (!stopping_) {
      pollfd p{listen_fd_, POLLIN, 0};
      if (::poll(&p, 1, 100) != 1) continue;
      const int fd = ::accept(listen_fd_, nullptr, nullptr);
      if (fd < 0) continue;
      std::lock_guard<std::mutex> lock(mutex_);
      const auto target = target_;
      const auto identity = identity_;
      workers_.emplace_back([this, fd, target, identity] { serve(fd, target, identity); });
    }
  }

  void serve(int fd, db_proxy::Target target, db_proxy::Identity identity) {
    db_proxy::ClientSide client;
    client.send = [fd](const std::string &bytes) {
      size_t sent = 0;
      while (sent < bytes.size()) {
        const ssize_t n = ::send(fd, bytes.data() + sent, bytes.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) return;
        sent += static_cast<size_t>(n);
      }
    };
    client.close = [fd](const std::string &) { ::shutdown(fd, SHUT_RDWR); };
    auto connection = db_proxy::start(ctx_, target, identity, client);
    char buf[16384];
    while (true) {
      const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
      if (n <= 0) break;
      db_proxy::feed(connection, std::string(buf, static_cast<size_t>(n)));
    }
    db_proxy::stop(connection);
    ::close(fd);
  }

  AppContext &ctx_;
  db_proxy::Target target_;
  db_proxy::Identity identity_;
  int listen_fd_ = -1;
  std::atomic<bool> stopping_{false};
  std::thread acceptor_;
  std::mutex mutex_;
  std::vector<std::thread> workers_;
};

std::vector<AuditEvent> audit_of(AppContext &ctx, const std::string &type) {
  std::vector<AuditEvent> out;
  std::lock_guard<std::mutex> lock(ctx.audit_mutex);
  for (const auto &e : ctx.audit_events)
    if (e.type == type) out.push_back(e);
  return out;
}

bool audited(AppContext &ctx, const std::string &type, const std::string &needle) {
  for (const auto &e : audit_of(ctx, type))
    if (contains(e.payloadJson, needle)) return true;
  return false;
}

}  // namespace

int main() {
  const std::string bin = find_pg_bin();
  const std::string ip = routable_local_ipv4();
  if (bin.empty() || geteuid() == 0 || ip.empty() || run("command -v psql").status != 0) {
    std::cout << "db proxy e2e test skipped (needs PostgreSQL binaries, psql, a non-root user "
                 "and a non-loopback IPv4 address)"
              << std::endl;
    return 0;
  }

  char tmpl[] = "/tmp/ef-dbproxy-XXXXXX";
  const std::string dir = mkdtemp(tmpl);
  const std::string data = dir + "/data";
  const int pg_port = free_port();
  const std::string password = "S3cret-vault-pw";
  { std::ofstream(dir + "/pw") << password << "\n"; }

  bool ok = run(bin + "/initdb -D " + data + " -U postgres --auth=scram-sha-256 --pwfile=" + dir +
                "/pw -E UTF8 >/dev/null").status == 0;
  { std::ofstream(data + "/pg_hba.conf", std::ios::app) << "host all all 0.0.0.0/0 scram-sha-256\n"; }
  // Self-signed certificate so the proxy's TLS leg is exercised.
  const bool tls = run("command -v openssl >/dev/null && openssl req -x509 -newkey rsa:2048 -nodes -keyout " +
                       data + "/server.key -out " + data + "/server.crt -days 1 -subj /CN=pg.test >/dev/null 2>&1 && chmod 600 " +
                       data + "/server.key").status == 0;
  ok = ok && run(bin + "/pg_ctl -D " + data + " -w -l " + dir + "/log -o \"-c listen_addresses=" + ip +
                 " -p " + std::to_string(pg_port) + " -k " + dir + (tls ? " -c ssl=on" : "") +
                 "\" start >/dev/null").status == 0;
  if (!expect(ok, "throw-away PostgreSQL started")) {
    std::cerr << run("cat " + dir + "/log").output;
    return 1;
  }
  const std::string admin = "PGPASSWORD=" + password + " psql -X -q -h " + ip + " -p " +
                            std::to_string(pg_port) + " -U postgres ";
  run(admin + "-d postgres -c 'CREATE DATABASE app'");
  run(admin + "-d app -c 'CREATE TABLE items (id int PRIMARY KEY, name text); "
              "INSERT INTO items VALUES (1, $$one$$), (2, $$two$$)'");

  {
    AppContext ctx;
    ctx.audit_path = "";
    ctx.init_database(":memory:");
    db_guard::init(ctx);
    Session session;
    session.id = 7;
    session.status = "active";
    session.protocol = "postgres";
    ctx.sessions[7] = session;

    db_proxy::Target target;
    target.host = ip;
    target.port = pg_port;
    target.user = "postgres";
    target.password = password;
    target.tlsMode = tls ? "require" : "prefer";
    db_proxy::Identity identity;
    identity.sessionId = 7;
    identity.resourceId = 3;
    identity.resourceName = "pg-test";
    identity.actor = "alice";
    identity.role = "operator";
    identity.guard = true;
    Bridge bridge(ctx, target, identity);

    // The client never knows the database password: no PGPASSWORD here, and a
    // user name the server does not even have.
    const std::string client = "env -u PGPASSWORD psql -X -A -t \"host=127.0.0.1 port=" +
                               std::to_string(bridge.port) +
                               " user=nobody dbname=app connect_timeout=5 sslmode=prefer\" ";

    auto r = run(client + "-c 'SELECT count(*) FROM items'");
    expect(r.status == 0 && contains(r.output, "2"), "simple query through the proxy: " + r.output);
    expect(audited(ctx, "db.query", "\"sql\":\"SELECT count(*) FROM items\""), "query journaled");
    expect(audited(ctx, "db.query", "\"rows\":1"), "rows journaled");
    expect(audited(ctx, "db.connect", "\"database\":\"app\""), "connect journaled with database");
    if (tls) expect(audited(ctx, "db.connect", "\"tls\":true"), "TLS towards the server");
    expect(audited(ctx, "db.query", "\"dbUser\":\"postgres\""), "vaulted account recorded");

    r = run(client + "-c 'DROP TABLE items'");
    expect(r.status != 0 && contains(r.output, "refused by SQL guard rule \"drop\""),
           "guard refuses DROP: " + r.output);
    expect(audited(ctx, "db.query.blocked", "\"rule\":\"drop\""), "blocked query journaled");
    r = run(admin + "-d app -A -t -c 'SELECT count(*) FROM items'");
    expect(contains(r.output, "2"), "table still there");

    // Several statements in one session, a refused one in the middle: the
    // session stays usable after the injected error.
    r = run("printf 'SELECT 1;\\nDELETE FROM items;\\nSELECT name FROM items WHERE id = 2;\\n' | " + client +
            "-f -");
    expect(contains(r.output, "refused by SQL guard rule \"delete_without_where\"") &&
               contains(r.output, "two"),
           "session continues after a refusal: " + r.output);

    // Extended protocol with a bound parameter (psql \bind).
    r = run("printf 'SELECT name FROM items WHERE id = $1 \\\\bind 1 \\\\g\\n' | " + client + "-f -");
    expect(r.status == 0 && contains(r.output, "one"), "extended protocol: " + r.output);
    expect(audited(ctx, "db.query", "\"mode\":\"extended\""), "extended query journaled");
    expect(audited(ctx, "db.query", "\"parameters\":1"), "parameter count journaled");
    expect(!audited(ctx, "db.query", "\"sql\":\"1\""), "parameter value not journaled");

    // Server errors come back to the client and into the journal.
    r = run(client + "-c 'SELECT * FROM missing_table'");
    expect(r.status != 0 && contains(r.output, "missing_table"), "server error forwarded");
    expect(audited(ctx, "db.query", "\"sqlstate\":\"42P01\""), "server error journaled");

    // Guard off on the resource: DROP goes through (on a scratch table).
    bridge.set_guard(false);
    r = run(client + "-c 'CREATE TABLE scratch (x int)' -c 'DROP TABLE scratch'");
    expect(r.status == 0, "unguarded resource lets DROP through: " + r.output);
    bridge.set_guard(true);

    // Terminating the session from the console cuts a running query.
    std::thread killer([&ctx] {
      std::this_thread::sleep_for(std::chrono::milliseconds(1200));
      std::lock_guard<std::mutex> lock(ctx.session_mutex);
      ctx.sessions[7].status = "terminated";
    });
    const auto started = std::chrono::steady_clock::now();
    r = run(client + "-c 'SELECT pg_sleep(8)'");
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - started)
                             .count();
    killer.join();
    expect(audited(ctx, "db.query", "\"error\":\"interrupted: session terminated\"") &&
               audited(ctx, "db.query", "pg_sleep(8)"),
           "the cut query is still journaled");
    expect(r.status != 0 && elapsed < 5000, "terminated session cuts the connection (" +
                                                std::to_string(elapsed) + " ms): " + r.output);
    {
      std::lock_guard<std::mutex> lock(ctx.session_mutex);
      ctx.sessions[7].status = "active";
    }

    // A wrong vaulted password fails cleanly, without leaking anything.
    auto bad = target;
    bad.password = "wrong";
    bridge.set_target(bad);
    r = run(client + "-c 'SELECT 1'");
    expect(r.status != 0 && contains(r.output, "refused the login") && !contains(r.output, "wrong"),
           "bad vault password: " + r.output);
    expect(audited(ctx, "db.connect.failed", "refused the login"), "failed login journaled");

    // TLS demanded from a server without it is refused.
    if (!tls) {
      auto strict = target;
      strict.tlsMode = "require";
      bridge.set_target(strict);
      r = run(client + "-c 'SELECT 1'");
      expect(r.status != 0 && contains(r.output, "does not support TLS"), "require without TLS");
    }
    std::cout << "journal: " << audit_of(ctx, "db.connect").size() << " connections, "
              << audit_of(ctx, "db.query").size() << " queries, "
              << audit_of(ctx, "db.query.blocked").size() << " blocked"
              << (tls ? ", TLS to the server" : ", no TLS") << std::endl;
    if (std::getenv("ENDORIUMFORT_E2E_VERBOSE"))
      for (const auto &e : audit_of(ctx, "db.query")) std::cout << "  " << e.payloadJson << std::endl;
  }

  run(bin + "/pg_ctl -D " + data + " -m immediate stop >/dev/null");
  fs::remove_all(dir);
  if (failures) {
    std::cerr << failures << " db proxy e2e check(s) failed" << std::endl;
    return 1;
  }
  std::cout << "db proxy e2e tests passed" << std::endl;
  return 0;
}
