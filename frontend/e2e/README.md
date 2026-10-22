# End-to-end tests

Playwright drives the real interface against a **throwaway bastion**: an empty
data directory, so the tests never touch a real or shared server. Global setup
finishes the factory admin's first login (new password + TOTP), creates an
operator (`op1`), resources and, with a Pro license, a JIT policy on
`zone:e2e`. It also starts a fake SSH server (`fake-ssh.mjs`) the resources
point to, so SSH sessions are real without any real host.

| Test | Checks |
|---|---|
| `auth` | password + two-factor sign-in; a wrong code is refused |
| `ssh-resume` | reloading the page resumes the same SSH shell, output included |
| `access-request` (Pro) | critical resource: request with a reason, approval, purpose asked at connection; web resource asks for the reason |
| `appearance` (Pro) | tab title and pre-sign-in message reach the login page |
| `getting-started` | the map's guide shows only what is left; operators never see it |
| `session-expiry` | a banner warns before the sign-in token ends; signing in again (before or after) comes back to the same page; server errors show in French |
| `confirm-dialog` | sensitive actions confirm in a dialog: a double click or Enter never confirms, Escape cancels, a server error stays in the dialog, deleting a resource asks to type its name |

## Running

1. Start a fresh bastion (it is wiped when stopped; restart it before each run):

   ```bash
   E2E_BACKEND_BIN=/path/to/endoriumfort_backend E2E_LICENSE_FILE=/path/to/license.lic npm run e2e:backend
   ```

   Without `E2E_LICENSE_FILE` the Pro tests are skipped. On Windows the backend
   runs in WSL: `wsl -d Debian -- env E2E_BACKEND_BIN=... bash e2e/start-backend.sh`.

2. In `frontend/`, run the tests (the interface is started on port 5175):

   ```bash
   npm run e2e
   ```

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `E2E_API` | `http://localhost:8095` | the throwaway bastion |
| `E2E_UI_PORT` | `5175` | port of the interface started for the tests |
| `E2E_SSH_HOST` | `127.0.0.1` | address of this machine **as seen from the bastion** (for the fake SSH server); with the backend in WSL (NAT), the Windows host address, e.g. `172.20.64.1` |
| `E2E_SSH_PORT` | `2222` | fake SSH server port |
| `E2E_BROWSER_CHANNEL` | `msedge` (Windows), `chrome` | installed browser to use; `chromium` uses Playwright's own (`npx playwright install chromium`) |

Reports: `playwright-report/` (HTML), traces and screenshots of failures in `test-results/`.
