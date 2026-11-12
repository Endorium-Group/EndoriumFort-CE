# Self-hosted runner for the Linux jobs

The repository is private, so every GitHub-hosted minute counts against the
plan's quota. The Linux jobs can run instead on a machine of ours, for free:
a runner in a container, on any Linux host with Docker (a WSL distribution
works).

## Which jobs go where

Each Linux job has

```yaml
runs-on: ${{ github.actor != 'dependabot[bot]' && vars.LINUX_RUNNER && fromJSON(vars.LINUX_RUNNER) || 'ubuntu-latest' }}
```

- The repository variable **`LINUX_RUNNER`** decides: set it to
  `["self-hosted","wsl"]` to send the jobs to the runner, delete it to send
  them back to GitHub. No code change either way.
- **Dependabot pull requests stay on GitHub**: they run dependency code nobody
  has reviewed yet, and the runner has the host's Docker socket.
- **Stay on GitHub regardless**: macOS and Windows jobs, license signing
  (`sign-license.yml`), Dependabot auto-merge, and the Docker Compose smoke
  gate (it publishes ports 80/443 and uses fixed container names, which would
  collide with the host's own stack).

If the runner is offline while `LINUX_RUNNER` is set, jobs wait in the queue
(up to 24 hours). Delete the variable to unblock them on GitHub.

## Install

On the host, once:

```bash
# 1. The runner itself, outside the repository (pick the latest version on
#    https://github.com/actions/runner/releases and check its SHA-256).
mkdir -p ~/actions-runner && cd ~/actions-runner
curl -fsSLO https://github.com/actions/runner/releases/download/v2.338.2/actions-runner-linux-x64-2.338.2.tar.gz
tar xzf actions-runner-linux-x64-2.338.2.tar.gz && rm actions-runner-linux-x64-2.338.2.tar.gz

# 2. Build the image and register (needs `gh` logged in as a repository admin).
.github/runner/runner.sh register

# 3. Start it. It restarts with Docker from then on.
.github/runner/runner.sh start

# 4. Send the jobs to it.
gh variable set LINUX_RUNNER --body '["self-hosted","wsl"]'
```

Other commands: `runner.sh logs`, `runner.sh stop`, `runner.sh remove`.

On WSL the runner only works while the distribution is running; with systemd
enabled, Docker (and so the runner) starts with it.

## How it is built

- **Ubuntu 24.04 image** with what the workflows expect from `ubuntu-latest`
  (git, jq, gh, cmake, compilers, Docker CLI with buildx) and passwordless
  `sudo`, because jobs install their packages with `sudo apt-get`. Those
  installs stay in the container, not on the host.
- **Same paths on both sides.** The runner directory is mounted at its host
  path. Jobs with `container:` are started by the host's Docker daemon, which
  mounts the workspace and the runner's tools by their host paths.
- **`HOME` is the runner directory**, three levels above the workspace as on
  hosted runners: `actions/cache` stores paths relative to the workspace, so a
  cache saved on GitHub restores where the action looks for it.
- **Same uid as the host user**, so the workspace stays the user's. A job hook
  hands back the files that root-run job containers leave behind.
- **Tool cache** (`setup-node`, `setup-go`, `setup-ruby`, CodeQL…) in the
  `gh-runner-toolcache` volume at `/opt/hostedtoolcache`, where prebuilt
  toolchains expect it.
- **Multi-arch images** (`linux/arm64`) need QEMU registered on the host:
  `ls /proc/sys/fs/binfmt_misc/qemu-aarch64`, else
  `docker run --privileged --rm tonistiigi/binfmt --install arm64`.

## Security

The runner can reach the host's Docker daemon, which is root on the host.
Only run it for this private repository, keep Dependabot jobs on GitHub as
above, and never enable it for a public repository or for pull requests from
forks.
