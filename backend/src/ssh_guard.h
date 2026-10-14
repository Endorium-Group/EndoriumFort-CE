// ─── EndoriumFort — SSH command guard: the blocklist behind enableCommandGuard ─
// A resource with `enableCommandGuard` runs every keystroke batch through this
// list before it reaches the remote shell. The five built-in rules ship enabled
// and can be switched off one at a time, but never deleted: an operator can
// relax the guard deliberately, not lose a protection by editing a list.
//
// Administrators add their own entries as plain commands ("shutdown",
// "rm -rf /"), which are escaped into the same regex shape as the built-ins.
// Raw regular expressions are deliberately not accepted: a bad one silently
// blocks everything or nothing, and it is evaluated on every keystroke.
//
// This is core, not premium. The guard itself has no license feature, so its
// configuration must stay reachable from the Community edition.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct AppContext;

namespace ssh_guard {

struct Rule {
  std::string name;     // identity; stable across edits
  std::string command;  // as typed by the admin; empty for built-ins
  bool enabled = true;
  bool builtin = false;
  int64_t updatedAt = 0;
};

// Creates the table and seeds the built-ins, then compiles the active set.
void init(AppContext &ctx);

// Every rule, built-ins first, then custom ones by name.
std::vector<Rule> list(AppContext &ctx);

// Adds or updates a custom rule, or toggles a built-in. Returns false and sets
// `error` on a rejected name or command.
bool save(AppContext &ctx, const std::string &name, const std::string &command,
          bool enabled, std::string &error);

// Removes a custom rule. Built-ins cannot be removed, only disabled.
bool remove(AppContext &ctx, const std::string &name, std::string &error);

// Hot path, called for every input event on a guarded session: the name of the
// first rule that matches, or an empty string. Safe from any thread.
std::string first_match(const std::string &input);

// The regex source a plain command is translated into. Exposed for tests.
std::string command_to_pattern(const std::string &command);

}  // namespace ssh_guard
