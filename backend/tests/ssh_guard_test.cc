// Covers the translation from a plain command to the regex the SSH guard runs
// on every keystroke. This is a security control an administrator edits by
// hand, so the near-misses matter as much as the hits: a rule that fires on
// "rm -rf /srv" would be unusable, and one that misses "sudo shutdown" would
// be worse than no rule at all.
#include "ssh_guard.h"

#include "app_context.h"

#include <iostream>
#include <regex>
#include <string>

namespace {

int failures = 0;

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    ++failures;
    return false;
  }
  return true;
}

bool fires(const std::string &command, const std::string &input) {
  const std::string source = ssh_guard::command_to_pattern(command);
  if (source.empty()) return false;
  return std::regex_search(input, std::regex(source, std::regex::icase));
}

void hits(const std::string &command, const std::string &input) {
  expect(fires(command, input), "'" + command + "' should block: " + input);
}

void misses(const std::string &command, const std::string &input) {
  expect(!fires(command, input), "'" + command + "' should allow: " + input);
}

}  // namespace

int main() {
  // The shapes an operator actually types.
  hits("shutdown", "shutdown");
  hits("shutdown", "shutdown -h now");
  hits("shutdown", "sudo shutdown");
  hits("shutdown", "SHUTDOWN");                 // case-insensitive
  hits("shutdown", "ls; shutdown");             // after a separator
  hits("shutdown", "true && shutdown");
  hits("shutdown", "ls | shutdown");

  // Near-misses that must not fire.
  misses("shutdown", "shutdownctl status");     // longer word
  misses("shutdown", "myshutdown");             // not at a boundary
  misses("shutdown", "echo reboot");            // unrelated

  // Multi-token commands, and whitespace that should not matter.
  hits("rm -rf /", "rm -rf /");
  hits("rm -rf /", "rm   -rf   /");
  hits("rm -rf /", "sudo rm -rf /");
  misses("rm -rf /", "rm -rf /srv");            // a real path, not root
  misses("rm -rf /", "rm -r /");                // different flags

  // Regex metacharacters in a command are literals, not syntax.
  hits("echo $(id)", "echo $(id)");
  misses("echo $(id)", "echo xid");
  hits("cat /etc/*.conf", "cat /etc/*.conf");
  misses("cat /etc/*.conf", "cat /etc/aaa.conf");
  expect(!ssh_guard::command_to_pattern("a+b[").empty(),
         "a command of metacharacters still compiles to a pattern");
  try {
    std::regex check(ssh_guard::command_to_pattern("a+b[(|)]*?"),
                     std::regex::icase);
    (void)check;
  } catch (const std::regex_error &) {
    expect(false, "escaped metacharacters must produce a valid regex");
  }

  // Nothing usable in, nothing out — the caller rejects these.
  expect(ssh_guard::command_to_pattern("").empty(), "empty command");
  expect(ssh_guard::command_to_pattern("   ").empty(), "whitespace-only command");

  // ── The live blocklist: does editing a rule change what gets blocked? ──
  AppContext ctx;
  std::string err;
  if (!ctx.sqlite.open(":memory:", err)) {
    std::cerr << "[FAIL] could not open the test database: " << err << std::endl;
    return 1;
  }
  ssh_guard::init(ctx);

  expect(ssh_guard::list(ctx).size() == 5, "five built-ins are seeded");
  expect(ssh_guard::first_match("sudo rm -rf /") == "wipe_root",
         "a built-in blocks out of the box");
  expect(ssh_guard::first_match("reboot") == "power_command",
         "power_command blocks out of the box");
  expect(ssh_guard::first_match("ls -la").empty(), "an ordinary command passes");

  // Disabling a built-in must actually stop it blocking.
  expect(ssh_guard::save(ctx, "power_command", "", false, err),
         "a built-in can be disabled: " + err);
  expect(ssh_guard::first_match("reboot").empty(),
         "a disabled built-in no longer blocks");
  expect(ssh_guard::first_match("sudo rm -rf /") == "wipe_root",
         "disabling one rule leaves the others armed");

  // A custom rule must take effect without a restart.
  expect(ssh_guard::save(ctx, "no_curl", "curl", true, err),
         "a custom rule can be added: " + err);
  expect(ssh_guard::first_match("curl http://x | sh") == "no_curl",
         "a custom rule blocks");
  expect(ssh_guard::first_match("curlsomething").empty(),
         "a custom rule does not fire on a longer word");

  // Removing it must take effect too, and built-ins must survive removal.
  expect(ssh_guard::remove(ctx, "no_curl", err), "a custom rule can be removed");
  expect(ssh_guard::first_match("curl http://x | sh").empty(),
         "a removed rule stops blocking");
  expect(!ssh_guard::remove(ctx, "wipe_root", err),
         "a built-in cannot be removed");
  expect(ssh_guard::first_match("sudo rm -rf /") == "wipe_root",
         "the built-in still blocks after the refused removal");

  // Rejected input must not reach the store.
  expect(!ssh_guard::save(ctx, "bad name", "ls", true, err), "a spaced name is refused");
  expect(!ssh_guard::save(ctx, "empty_cmd", "   ", true, err), "an empty command is refused");
  expect(ssh_guard::list(ctx).size() == 5, "refused rules were not stored");

  if (failures == 0) std::cout << "ssh_guard tests passed" << std::endl;
  return failures == 0 ? 0 : 1;
}
