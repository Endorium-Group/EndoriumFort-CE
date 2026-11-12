// Unit tests for the database proxy's pure parts: PostgreSQL framing and
// parsers (pg_wire.h), SCRAM-SHA-256 and MD5 (pg_auth.h), the relay state
// machine (pg_relay.h) and the SQL guard analyzer (db_guard_sql.cc).
#include "pro/db_dynamic_sql.h"
#include "pro/db_guard.h"
#include "pro/pg_auth.h"
#include "pro/pg_relay.h"
#include "pro/pg_wire.h"

#include <iostream>
#include <string>
#include <vector>

namespace {
int failures = 0;
bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    ++failures;
  }
  return condition;
}

pg_wire::Message msg(const std::string &raw) {
  std::string buffer = raw;
  pg_wire::Message m;
  pg_wire::take_message(buffer, m);
  return m;
}

std::string parse_msg(const std::string &name, const std::string &sql) {
  std::string body = name + std::string(1, '\0') + sql + std::string(1, '\0');
  pg_wire::put_i16(body, 0);
  return pg_wire::message('P', body);
}
std::string bind_msg(const std::string &portal, const std::string &statement, int params) {
  std::string body = portal + std::string(1, '\0') + statement + std::string(1, '\0');
  pg_wire::put_i16(body, 1);  // one format code
  pg_wire::put_i16(body, 0);
  pg_wire::put_i16(body, static_cast<int16_t>(params));
  for (int i = 0; i < params; ++i) {
    pg_wire::put_i32(body, 6);
    body += "secret";  // never recorded
  }
  pg_wire::put_i16(body, 0);
  return pg_wire::message('B', body);
}
std::string execute_msg(const std::string &portal) {
  std::string body = portal + std::string(1, '\0');
  pg_wire::put_i32(body, 0);
  return pg_wire::message('E', body);
}
std::string complete(const std::string &tag) { return pg_wire::message('C', tag + std::string(1, '\0')); }
std::string data_row() {
  std::string body;
  pg_wire::put_i16(body, 1);
  pg_wire::put_i32(body, 1);
  body += "1";
  return pg_wire::message('D', body);
}
std::string server_error(const std::string &text) { return pg_wire::error_response("ERROR", "42P01", text); }

// ── pg_wire ─────────────────────────────────────────────────────────────────

void test_framing() {
  std::string buffer = pg_wire::query_message("SELECT 1") + pg_wire::sync_message();
  const std::string whole = buffer;
  pg_wire::Message m;
  expect(pg_wire::take_message(buffer, m) == pg_wire::Frame::Ok, "first message framed");
  expect(m.type == 'Q' && pg_wire::parse_query(m).value_or("") == "SELECT 1", "query text");
  expect(m.raw == whole.substr(0, m.raw.size()), "raw kept for forwarding");
  expect(pg_wire::take_message(buffer, m) == pg_wire::Frame::Ok && m.type == 'S', "second message");
  expect(buffer.empty(), "buffer consumed");

  std::string partial = whole.substr(0, 7);
  expect(pg_wire::take_message(partial, m) == pg_wire::Frame::NeedMore, "partial needs more");
  std::string bogus = std::string("Q") + std::string("\x7f\xff\xff\xff", 4);
  expect(pg_wire::take_message(bogus, m) == pg_wire::Frame::Invalid, "absurd length refused");
  std::string tiny = std::string("Q") + std::string("\0\0\0\x02", 4);
  expect(pg_wire::take_message(tiny, m) == pg_wire::Frame::Invalid, "length below 4 refused");
}

void test_startup() {
  std::string buffer = pg_wire::startup_message({{"user", "alice"}, {"database", "app"}});
  pg_wire::Message m;
  expect(pg_wire::take_startup(buffer, m) == pg_wire::Frame::Ok, "startup framed");
  expect(pg_wire::startup_code(m) == pg_wire::kProtocol30, "protocol 3.0");
  auto params = pg_wire::startup_params(m);
  expect(params && params->size() == 2 && (*params)[1].second == "app", "startup params");

  std::string ssl = pg_wire::ssl_request();
  expect(pg_wire::take_startup(ssl, m) == pg_wire::Frame::Ok &&
             pg_wire::startup_code(m) == pg_wire::kSslRequestCode,
         "SSLRequest recognised");

  // Missing final terminator.
  std::string broken = pg_wire::startup_message({{"user", "x"}});
  broken.pop_back();
  broken[3] = static_cast<char>(broken[3] - 1);
  expect(pg_wire::take_startup(broken, m) == pg_wire::Frame::Ok && !pg_wire::startup_params(m),
         "unterminated startup refused");
}

void test_parsers() {
  expect(pg_wire::rows_from_tag("SELECT 42") == 42, "select rows");
  expect(pg_wire::rows_from_tag("INSERT 0 3") == 3, "insert rows");
  expect(pg_wire::rows_from_tag("CREATE TABLE") == 0, "ddl has no rows");
  expect(pg_wire::rows_from_tag("SELECTED 5") == 0, "verb must match exactly");
  expect(pg_wire::command_from_tag("UPDATE 7") == "UPDATE", "command from tag");
  expect(pg_wire::command_from_tag("CREATE TABLE") == "CREATE TABLE", "multi-word command");

  auto bind = pg_wire::parse_bind(msg(bind_msg("p1", "s1", 2)));
  expect(bind && bind->portal == "p1" && bind->statement == "s1" && bind->parameters == 2, "bind parsed");
  auto parse = pg_wire::parse_parse(msg(parse_msg("s1", "SELECT $1")));
  expect(parse && parse->first == "s1" && parse->second == "SELECT $1", "parse parsed");

  auto fields = pg_wire::parse_fields(msg(server_error("relation \"x\" does not exist")));
  expect(pg_wire::field(fields, 'C') == "42P01", "sqlstate field");
  expect(pg_wire::field(fields, 'M') == "relation \"x\" does not exist", "message field");

  std::string sasl_body;
  pg_wire::put_i32(sasl_body, 10);
  sasl_body += std::string("SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0", 34);
  auto auth = pg_wire::parse_auth(msg(pg_wire::message('R', sasl_body)));
  expect(auth && auth->first == 10, "auth code");
  const auto mechs = pg_wire::sasl_mechanisms(auth->second);
  expect(mechs.size() == 2 && mechs[1] == "SCRAM-SHA-256", "sasl mechanisms");
}

// ── pg_auth ─────────────────────────────────────────────────────────────────

void test_auth() {
  // RFC 7677 §3 test vector.
  pg_auth::Scram scram("pencil", "user", "rOprNGfwEbeRWgbNEkqO");
  expect(scram.client_first() == "n,,n=user,r=rOprNGfwEbeRWgbNEkqO", "client-first");
  const std::string server_first =
      "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
  auto final_message = scram.client_final(server_first);
  expect(final_message &&
             *final_message ==
                 "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                 "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
         "client-final matches RFC 7677");
  expect(scram.verify_server_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="),
         "server signature verified");
  expect(!scram.verify_server_final("v=AAAATRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="),
         "forged server signature refused");

  pg_auth::Scram other("pencil", "", "abc");
  other.client_first();
  expect(!other.client_final("r=xyz123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"),
         "server nonce must extend ours");
  expect(!other.client_final("r=abcdef,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=10"),
         "too few iterations refused");
  expect(!other.client_final("r=abcdef,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=99999999"),
         "absurd iteration count refused");

  expect(pg_auth::md5_response("postgres", "secret", std::string("\x01\x02\x03\x04", 4)) ==
             "md5bb41a296aab6baccb36ff243a562abff",
         "md5 response");
}

// ── db_guard ────────────────────────────────────────────────────────────────

std::vector<db_guard::Rule> builtins() {
  std::vector<db_guard::Rule> rules;
  for (const auto &name : db_guard::builtin_names()) {
    db_guard::Rule r;
    r.name = name;
    r.kind = "builtin";
    r.builtin = true;
    rules.push_back(r);
  }
  return rules;
}

void test_guard() {
  const auto rules = builtins();
  auto hit = [&rules](const std::string &sql) { return db_guard::first_match(sql, rules); };

  expect(hit("DROP TABLE users") == "drop", "drop table");
  expect(hit("  drop   schema x cascade") == "drop", "lower-case drop");
  expect(hit("/* x */DROP TABLE t") == "drop", "comment before drop");
  expect(hit("SELECT 'DROP TABLE t'") == "", "drop inside a string");
  expect(hit("SELECT 1 -- DROP TABLE t") == "", "drop inside a comment");
  expect(hit("SELECT $$DROP TABLE t$$") == "", "drop inside dollar quotes");
  expect(hit("SELECT $tag$ ; DROP TABLE t; $tag$") == "", "semicolon inside dollar quotes");
  expect(hit("SELECT 1; DROP TABLE t") == "drop", "second statement checked");
  expect(hit("SELECT E'\\' ; DROP TABLE t; --'") == "", "E-string with escaped quote");
  expect(hit("SELECT \"drop\" FROM t") == "", "quoted identifier is not a keyword");
  expect(hit("TRUNCATE orders") == "truncate", "truncate");

  expect(hit("DELETE FROM orders") == "delete_without_where", "delete without where");
  expect(hit("delete from orders where id = 1") == "", "delete with where");
  expect(hit("WITH d AS (DELETE FROM t) SELECT 1") == "delete_without_where", "delete in a CTE");
  expect(hit("WITH d AS (DELETE FROM t WHERE x) SELECT 1 WHERE true") == "", "CTE delete with where");
  expect(hit("DELETE FROM t USING u WHERE t.id = u.id") == "", "delete using where");
  expect(hit("EXPLAIN ANALYZE DELETE FROM t") == "delete_without_where", "explain analyze runs it");
  expect(hit("CREATE TABLE c (id int REFERENCES p ON DELETE CASCADE)") == "", "on delete cascade");

  expect(hit("UPDATE accounts SET balance = 0") == "update_without_where", "update without where");
  expect(hit("UPDATE public.accounts AS a SET x = 1 WHERE a.id = 2") == "", "update with where");
  expect(hit("UPDATE ONLY t SET x = (SELECT 1 WHERE true)") == "update_without_where",
         "WHERE in a sub-select does not count");
  expect(hit("SELECT * FROM t FOR UPDATE") == "", "for update");
  expect(hit("INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET x = 2") == "", "upsert");
  expect(hit("GRANT UPDATE ON t TO bob") == "role_change", "grant is a role change, not an update");

  expect(hit("ALTER ROLE app SUPERUSER") == "role_change", "alter role");
  expect(hit("CREATE USER eve PASSWORD 'x'") == "role_change", "create user");
  expect(hit("SET ROLE postgres") == "role_change", "set role");
  expect(hit("SET SESSION AUTHORIZATION postgres") == "role_change", "set session authorization");
  expect(hit("SET search_path TO app") == "", "other SET statements pass");
  expect(hit("ALTER SYSTEM SET fsync = off") == "alter_system", "alter system");
  expect(hit("COPY t TO PROGRAM 'curl evil'") == "copy_program", "copy program");
  expect(hit("COPY t TO STDOUT") == "", "copy to stdout");
  expect(hit("DO $$ BEGIN EXECUTE 'DR' || 'OP TABLE t'; END $$") == "do_block", "do block");
  expect(hit("SELECT * FROM users WHERE id = 1") == "", "plain select");

  // Disabled built-in.
  auto relaxed = rules;
  relaxed[0].enabled = false;  // drop
  expect(db_guard::first_match("DROP TABLE t", relaxed) == "", "disabled rule does not fire");

  // Custom rules.
  std::vector<db_guard::Rule> custom = {
      {"no_vacuum_full", "statement", "VACUUM FULL", true, false, 0},
      {"payroll", "schema", "payroll", true, false, 0}};
  expect(db_guard::first_match("vacuum full big_table", custom) == "no_vacuum_full", "statement rule");
  expect(db_guard::first_match("VACUUM big_table", custom) == "", "statement prefix must match");
  expect(db_guard::first_match("SELECT * FROM payroll.salaries", custom) == "payroll", "schema rule");
  expect(db_guard::first_match("SELECT * FROM \"payroll\".salaries", custom) == "payroll",
         "quoted schema");
  expect(db_guard::first_match("SET search_path TO payroll", custom) == "payroll", "search_path");
  expect(db_guard::first_match("SELECT payroll FROM t", custom) == "", "a column of that name");
}

// ── pg_relay ────────────────────────────────────────────────────────────────

pg_relay::Guard test_guard_fn() {
  const auto rules = builtins();
  return [rules](const std::string &sql) { return db_guard::first_match(sql, rules); };
}

void test_relay_simple() {
  pg_relay::Relay relay(test_guard_fn());
  pg_relay::Output out;
  relay.on_client(msg(pg_wire::query_message("SELECT 1")), 100, out);
  expect(out.toUpstream == pg_wire::query_message("SELECT 1"), "query forwarded untouched");
  relay.on_server(msg(data_row()), 105, out);
  relay.on_server(msg(complete("SELECT 1")), 110, out);
  relay.on_server(msg(pg_wire::ready_for_query()), 120, out);
  expect(out.events.size() == 1, "one event per query");
  const auto &ev = out.events[0];
  expect(ev.sql == "SELECT 1" && ev.mode == "simple" && ev.rows == 1 && ev.command == "SELECT" &&
             ev.durationMs == 20 && ev.error.empty(),
         "simple query event");
  expect(out.toClient == data_row() + complete("SELECT 1") + pg_wire::ready_for_query(),
         "server answers forwarded untouched");
  expect(relay.pending() == 0, "nothing pending");

  pg_relay::Output err;
  relay.on_client(msg(pg_wire::query_message("SELECT * FROM nope")), 0, err);
  relay.on_server(msg(server_error("relation \"nope\" does not exist")), 1, err);
  relay.on_server(msg(pg_wire::ready_for_query()), 2, err);
  expect(err.events.size() == 1 && err.events[0].sqlstate == "42P01", "error recorded");
}

void test_relay_blocked_simple() {
  pg_relay::Relay relay(test_guard_fn());
  pg_relay::Output out;
  relay.on_client(msg(pg_wire::query_message("DROP TABLE users")), 0, out);
  expect(out.toUpstream == pg_wire::sync_message(), "blocked query replaced by a Sync");
  expect(out.events.size() == 1 && out.events[0].blocked && out.events[0].rule == "drop",
         "blocked event");
  expect(out.toClient.empty(), "nothing to the client yet");
  relay.on_server(msg(pg_wire::ready_for_query('I')), 1, out);
  pg_wire::Message first;
  std::string sent = out.toClient;
  expect(pg_wire::take_message(sent, first) == pg_wire::Frame::Ok && first.type == 'E',
         "error injected first");
  expect(pg_wire::field(pg_wire::parse_fields(first), 'C') == "42501", "insufficient_privilege");
  pg_wire::Message second;
  expect(pg_wire::take_message(sent, second) == pg_wire::Frame::Ok && second.type == 'Z',
         "then ReadyForQuery");
  expect(out.events.size() == 1, "no extra event for the substituted Sync");
}

void test_relay_extended() {
  pg_relay::Relay relay(test_guard_fn());
  pg_relay::Output out;
  relay.on_client(msg(parse_msg("s1", "UPDATE t SET x = $1 WHERE id = $2")), 0, out);
  relay.on_client(msg(bind_msg("", "s1", 2)), 0, out);
  relay.on_client(msg(execute_msg("")), 10, out);
  relay.on_client(msg(pg_wire::sync_message()), 10, out);
  // Pipelined second batch reusing the statement.
  relay.on_client(msg(bind_msg("", "s1", 2)), 11, out);
  relay.on_client(msg(execute_msg("")), 11, out);
  relay.on_client(msg(pg_wire::sync_message()), 11, out);
  expect(out.events.empty(), "no event before answers");

  relay.on_server(msg(pg_wire::message('1', "")), 20, out);  // ParseComplete
  relay.on_server(msg(pg_wire::message('2', "")), 20, out);  // BindComplete
  relay.on_server(msg(complete("UPDATE 3")), 25, out);
  relay.on_server(msg(pg_wire::ready_for_query()), 26, out);
  relay.on_server(msg(pg_wire::message('2', "")), 30, out);
  relay.on_server(msg(server_error("deadlock")), 31, out);
  relay.on_server(msg(pg_wire::ready_for_query()), 32, out);

  expect(out.events.size() == 2, "one event per Execute");
  if (out.events.size() == 2) {
    expect(out.events[0].sql == "UPDATE t SET x = $1 WHERE id = $2" && out.events[0].rows == 3 &&
               out.events[0].parameters == 2 && out.events[0].mode == "extended" &&
               out.events[0].durationMs == 15,
           "first execute");
    expect(out.events[1].error == "deadlock" && out.events[1].durationMs == 20,
           "second execute carries the error");
    expect(out.events[0].sql.find("secret") == std::string::npos, "parameter values never recorded");
  }
  expect(relay.pending() == 0, "nothing pending after both ReadyForQuery");
}

void test_relay_blocked_parse() {
  pg_relay::Relay relay(test_guard_fn());
  pg_relay::Output out;
  relay.on_client(msg(parse_msg("", "TRUNCATE orders")), 0, out);
  relay.on_client(msg(bind_msg("", "", 0)), 0, out);
  relay.on_client(msg(pg_wire::message('D', std::string("P\0", 2))), 0, out);
  relay.on_client(msg(execute_msg("")), 0, out);
  expect(out.toUpstream.empty(), "nothing of the refused batch goes upstream");
  relay.on_client(msg(pg_wire::sync_message()), 0, out);
  expect(out.toUpstream == pg_wire::sync_message(), "only the Sync goes upstream");
  expect(out.events.size() == 1 && out.events[0].rule == "truncate", "blocked parse event");
  relay.on_server(msg(pg_wire::ready_for_query()), 1, out);
  std::string sent = out.toClient;
  pg_wire::Message m;
  expect(pg_wire::take_message(sent, m) == pg_wire::Frame::Ok && m.type == 'E', "error injected");
  expect(pg_wire::take_message(sent, m) == pg_wire::Frame::Ok && m.type == 'Z', "ready after");

  // The session carries on normally afterwards.
  pg_relay::Output next;
  relay.on_client(msg(pg_wire::query_message("SELECT 2")), 0, next);
  expect(next.toUpstream == pg_wire::query_message("SELECT 2"), "next query flows");
}

void test_relay_abandon() {
  pg_relay::Relay relay;
  pg_relay::Output out;
  relay.on_client(msg(pg_wire::query_message("SELECT pg_sleep(60)")), 0, out);
  const auto cut = relay.abandon(500, "interrupted: session terminated");
  expect(cut.size() == 1 && cut[0].sql == "SELECT pg_sleep(60)" && cut[0].durationMs == 500 &&
             cut[0].error == "interrupted: session terminated",
         "in-flight query reported when the connection goes");
  expect(relay.pending() == 0, "nothing left after abandon");
}

void test_relay_unguarded() {
  pg_relay::Relay relay;  // resource without the guard
  pg_relay::Output out;
  relay.on_client(msg(pg_wire::query_message("DROP TABLE t")), 0, out);
  expect(out.toUpstream == pg_wire::query_message("DROP TABLE t"), "no guard: forwarded");
  relay.on_server(msg(complete("DROP TABLE")), 1, out);
  relay.on_server(msg(pg_wire::ready_for_query()), 2, out);
  expect(out.events.size() == 1 && !out.events[0].blocked && out.events[0].command == "DROP TABLE",
         "still journaled");
}

// ── db_dynamic (pure) ───────────────────────────────────────────────────────

void test_dynamic_sql() {
  using namespace db_dynamic;
  expect(quote_ident("a\"b") == "\"a\"\"b\"", "identifier quoting");
  expect(quote_literal("it's") == "'it''s'", "literal quoting");

  expect(valid_role_name("app_rw"), "plain role name");
  expect(!valid_role_name("App"), "upper case refused");
  expect(!valid_role_name("pg_read_all_data"), "pg_ roles refused");
  expect(!valid_role_name("ef_12345678"), "ef_ (the proxy's own) refused");
  expect(!valid_role_name("1x") && !valid_role_name("") && !valid_role_name(std::string(64, 'a')),
         "bad shapes refused");
  std::vector<std::string> roles;
  expect(parse_role_list(" app_rw, app_ro ,app_rw", roles) && roles.size() == 2 && roles[1] == "app_ro",
         "role list trimmed and de-duplicated");
  expect(!parse_role_list("app; DROP ROLE x", roles), "injection refused");
  expect(parse_role_list("", roles) && roles.empty(), "empty list allowed");
  expect(grant_sql({"app_rw", "app_ro"}, "ef_1") == "GRANT \"app_rw\", \"app_ro\" TO \"ef_1\"", "grant");

  // The verifier must be what PostgreSQL would derive from the password:
  // checked against the RFC 7677 exchange, whose signature and proof only
  // match if StoredKey and ServerKey are right.
  const auto salt = pg_auth::unbase64("W22ZaJ0SNY7soEsUEjb6gQ==");
  const std::string verifier = scram_verifier("pencil", *salt, 4096);
  expect(verifier.rfind("SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$", 0) == 0, "verifier header");
  const size_t dollar = verifier.rfind('$');
  const size_t colon = verifier.find(':', dollar);
  const auto stored_key = pg_auth::unbase64(verifier.substr(dollar + 1, colon - dollar - 1));
  const auto server_key = pg_auth::unbase64(verifier.substr(colon + 1));
  const std::string nonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
  const std::string auth_message = "n=user,r=rOprNGfwEbeRWgbNEkqO,r=" + nonce +
                                   ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=" + nonce;
  expect(server_key && pg_auth::base64(pg_auth::hmac_sha256(*server_key, auth_message)) ==
                           "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
         "ServerKey reproduces the RFC server signature");
  const auto proof = pg_auth::unbase64("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
  bool stored_ok = false;
  if (stored_key && proof) {
    const std::string signature = pg_auth::hmac_sha256(*stored_key, auth_message);
    std::string client_key = *proof;
    for (size_t i = 0; i < client_key.size(); ++i) client_key[i] = static_cast<char>(client_key[i] ^ signature[i]);
    stored_ok = pg_auth::digest(EVP_sha256(), client_key) == *stored_key;
  }
  expect(stored_ok, "StoredKey accepts the RFC client proof");

  const std::string create = create_role_sql("ef_ab12cd34", verifier, "2026-11-05T10:00:00Z");
  expect(create.find("PASSWORD 'SCRAM-SHA-256$") != std::string::npos, "only the verifier is sent");
  expect(create.find("pencil") == std::string::npos, "the clear password never appears");
  expect(create.find("VALID UNTIL '2026-11-05T10:00:00Z'") != std::string::npos, "validity bound");
  expect(create.find("NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS") != std::string::npos,
         "no elevated attribute");
  expect(terminate_backends_sql("ef_x").find("usename = 'ef_x'") != std::string::npos, "terminate");
}
}  // namespace

int main() {
  test_framing();
  test_startup();
  test_parsers();
  test_auth();
  test_guard();
  test_relay_simple();
  test_relay_blocked_simple();
  test_relay_extended();
  test_relay_blocked_parse();
  test_relay_abandon();
  test_dynamic_sql();
  test_relay_unguarded();
  if (failures) {
    std::cerr << failures << " db proxy test(s) failed" << std::endl;
    return 1;
  }
  std::cout << "db proxy tests passed" << std::endl;
  return 0;
}
