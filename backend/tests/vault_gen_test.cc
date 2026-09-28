// Unit tests for the vault credential generators (pro/vault.h). These are the
// pure, dependency-free helpers behind dynamic secrets + rotation.

#include "pro/vault.h"

#include <cctype>
#include <iostream>
#include <set>
#include <string>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

bool has_class(const std::string &s, int (*pred)(int)) {
  for (unsigned char c : s)
    if (pred(c)) return true;
  return false;
}

int is_symbol(int c) {
  return std::ispunct(c) ? 1 : 0;
}

}  // namespace

int main() {
  bool ok = true;

  // Password policy: default length, and min-length floor at 12.
  const std::string pw = vault::generate_strong_password();
  ok &= expect(pw.size() == 24, "default password length should be 24");
  ok &= expect(vault::generate_strong_password(4).size() == 12,
               "password length should be floored at 12");
  ok &= expect(vault::generate_strong_password(40).size() == 40,
               "password should honour requested length");

  // Complexity: at least one upper, lower, digit and symbol.
  ok &= expect(has_class(pw, [](int c) { return std::isupper(c) ? 1 : 0; }),
               "password should contain an uppercase letter");
  ok &= expect(has_class(pw, [](int c) { return std::islower(c) ? 1 : 0; }),
               "password should contain a lowercase letter");
  ok &= expect(has_class(pw, [](int c) { return std::isdigit(c) ? 1 : 0; }),
               "password should contain a digit");
  ok &= expect(has_class(pw, is_symbol), "password should contain a symbol");

  // No whitespace or quotes (must survive shell/base64 transport safely).
  ok &= expect(pw.find(' ') == std::string::npos, "password has no space");
  ok &= expect(pw.find('\'') == std::string::npos, "password has no quote");

  // Randomness: repeated generation should differ.
  std::set<std::string> seen;
  for (int i = 0; i < 50; ++i) seen.insert(vault::generate_strong_password());
  ok &= expect(seen.size() >= 48, "generated passwords should be distinct");

  // Ephemeral username format: ef_ + 8 lowercase hex chars.
  const std::string u = vault::generate_ephemeral_username();
  ok &= expect(u.size() == 11, "ephemeral username length should be 11");
  ok &= expect(u.rfind("ef_", 0) == 0, "ephemeral username should start with ef_");
  bool hex_ok = true;
  for (size_t i = 3; i < u.size(); ++i) {
    const char c = u[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) hex_ok = false;
  }
  ok &= expect(hex_ok, "ephemeral username suffix should be lowercase hex");

  if (!ok) return 1;
  std::cout << "All vault generator tests passed." << std::endl;
  return 0;
}
