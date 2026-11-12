# Self-hosted GitHub Actions runner for the Linux jobs (see README.md here).
#
# The runner binaries are NOT in the image: they live on the host and are
# mounted at the same path inside the container. Jobs that run in their own
# container (`container:`) are started by the host's Docker daemon, which
# mounts the workspace and the runner's externals by their host paths — so
# those paths must be identical on both sides.
FROM ubuntu:24.04

ARG RUNNER_UID=1000
ARG DOCKER_GID=1001

ENV DEBIAN_FRONTEND=noninteractive

# What the workflows expect to find on ubuntu-latest and do not install
# themselves, plus the runner's own dependencies (installdependencies.sh).
RUN apt-get update && apt-get install -y --no-install-recommends \
      sudo ca-certificates curl wget git git-lfs jq unzip zip xz-utils zstd gh openssl sqlite3 \
      gnupg lsb-release software-properties-common \
      build-essential cmake pkg-config python3 python3-pip python3-venv \
      docker.io docker-buildx docker-compose-v2 \
      libicu74 libkrb5-3 liblttng-ust1t64 libssl3t64 zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Same uid as the host user, so files written in the workspace stay theirs;
# passwordless sudo, as on GitHub-hosted runners (jobs run `sudo apt-get`).
RUN userdel -r ubuntu 2>/dev/null || true \
    && groupmod -g ${DOCKER_GID} docker 2>/dev/null || groupadd -g ${DOCKER_GID} docker \
    && useradd -m -u ${RUNNER_UID} -G docker,sudo -s /bin/bash runner \
    && echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner \
    && chmod 0440 /etc/sudoers.d/runner \
    && mkdir -p /opt/hostedtoolcache && chown runner:runner /opt/hostedtoolcache

# ruby/setup-ruby and friends only use their prebuilt binaries from here.
ENV RUNNER_TOOL_CACHE=/opt/hostedtoolcache \
    AGENT_TOOLSDIRECTORY=/opt/hostedtoolcache \
    ImageOS=ubuntu24

USER runner
