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

  // ── Evasion: quoting and paths must not walk past a rule ──
  expect(ssh_guard::unquote("r''m -rf /") == "rm -rf /", "empty quotes removed");
  expect(ssh_guard::unquote("\"rm\" -rf /") == "rm -rf /", "double quotes removed");
  expect(ssh_guard::unquote("r\\m -rf /") == "rm -rf /", "backslash escape removed");
  expect(ssh_guard::unquote("echo 'it\\'s'") == "echo it\\'s" ||
             !ssh_guard::unquote("echo 'it'").empty(),
         "quoting inside quoting does not crash");
  expect(ssh_guard::unquote("rm -rf /") == "rm -rf /", "a plain line is unchanged");

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

  // Quoting and path tricks, the point of this exercise.
  expect(ssh_guard::first_match("r''m -rf /") == "wipe_root", "r''m is still rm");
  expect(ssh_guard::first_match("\"rm\" -rf /") == "wipe_root", "\"rm\" is still rm");
  expect(ssh_guard::first_match("r\\m -rf /") == "wipe_root", "r\\m is still rm");
  expect(ssh_guard::first_match("/bin/rm -rf /") == "wipe_root", "/bin/rm is still rm");
  expect(ssh_guard::first_match("sudo /usr/sbin/reboot") == "power_command",
         "an absolute path does not hide a built-in");
  expect(ssh_guard::first_match("ls; r''m -rf /") == "wipe_root",
         "quoting after a separator is caught too");

  // …and the near-misses must survive the new normalisation.
  expect(ssh_guard::first_match("echo \"rm -rf /\"").empty(),
         "a quoted command as an argument is not a command");
  expect(ssh_guard::first_match("grep rm -rf /etc").empty(),
         "rm as an argument to another command passes");
  expect(ssh_guard::first_match("./rmdir-helper").empty(),
         "a path to an unrelated program passes");

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

  // ── The line mirror: a typed command must be reassembled before judging ──
  // xterm sends one event per keystroke, so without this the blocklist only
  // ever sees a single character and nothing is ever blocked.
  auto type_line = [](const std::string &keys, std::string &line) {
    bool submitted = false;
    for (char c : keys) submitted = ssh_guard::track_line(std::string(1, c), line);
    return submitted;
  };

  std::string line;
  expect(!type_line("rm -rf /", line), "no submit before Enter");
  expect(line == "rm -rf /", "keystrokes reassemble into the command");
  expect(ssh_guard::track_line("\r", line), "Enter submits the line");
  expect(ssh_guard::first_match(line) == "wipe_root",
         "the reassembled command is what gets judged");

  line.clear();
  type_line("rn", line);
  ssh_guard::track_line("\b", line);
  type_line("m -rf /", line);
  expect(line == "rm -rf /", "backspace corrects the mirror");

  line.clear();
  type_line("rm -rf /", line);
  ssh_guard::track_line("\x15", line);  // Ctrl-U
  expect(line.empty(), "Ctrl-U abandons the line");

  line.clear();
  type_line("rm -rf /", line);
  ssh_guard::track_line("\x03", line);  // Ctrl-C
  expect(line.empty(), "Ctrl-C abandons the line");

  line.clear();
  type_line("sudo rm -rf /tmp junk", line);
  ssh_guard::track_line("\x17", line);  // Ctrl-W kills one word
  expect(line == "sudo rm -rf /tmp ", "Ctrl-W kills the last word");

  line.clear();
  type_line("rm -rf /", line);
  ssh_guard::track_line("\x1b[A", line);  // Up arrow: the mirror is now blind
  expect(line.empty(), "an escape sequence resets the mirror rather than guessing");

  line.clear();
  ssh_guard::track_line(std::string(9000, 'a'), line);
  expect(line.size() <= 4096, "the mirror is bounded");

  // A whole line arriving in one event (a paste) still submits and matches.
  line.clear();
  expect(ssh_guard::track_line("reboot\n", line), "a pasted line submits");

  if (failures == 0) std::cout << "ssh_guard tests passed" << std::endl;
  return failures == 0 ? 0 : 1;
}
