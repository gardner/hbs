# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:trixie-slim

WORKDIR /tmp

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    LANG=C.UTF-8

# Base deps + security tools + monitoring tools
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && apt-get --no-install-recommends install -y \
    curl ca-certificates jq git unzip tar xz-utils gzip \
    clamav clamav-daemon clamav-freshclam yara file gosu \
    procps htop time

# Install gitleaks (static binary)
ENV GITLEAKS_VERSION=8.29.0
RUN arch=$(dpkg --print-architecture) && \
    curl -sSL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && rm -f /tmp/gitleaks.tar.gz

ENV CODEQL_VERSION=2.23.3
RUN if [ "$(dpkg --print-architecture)" != "amd64" ]; then \
      echo "WARNING: CodeQL CLI is only available for linux/amd64; skipping install."; \
    else \
      curl -sSL -o /tmp/codeql.zip \
        "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" && \
      mkdir -p /opt && unzip -q /tmp/codeql.zip -d /opt && rm /tmp/codeql.zip && \
      ln -sf /opt/codeql/codeql /usr/local/bin/codeql && \
      /opt/codeql/codeql version; \
    fi

ENV PATH="/opt/codeql:${PATH}"

# Freshclam config: allow update at runtime; don't crash on mirror quirks
RUN sed -i 's/^Example/# Example/' /etc/clamav/freshclam.conf || true

RUN freshclam

WORKDIR /app

# Create workspace + CodeQL work directory + unprivileged user
RUN useradd -m scanner && mkdir -p /work /tmp/codeql_work && chown -R scanner:scanner /work /app /tmp/codeql_work
USER scanner

RUN codeql pack download codeql/cpp-queries codeql/python-queries codeql/javascript-queries codeql/java-queries codeql/csharp-queries codeql/go-queries codeql/ruby-queries

# Rule files, scripts, app
COPY --chown=scanner:scanner pyproject.toml uv.lock /app/
RUN uv sync

ENV PATH=/home/scanner/.local/bin:$PATH


COPY --chown=scanner:scanner rules/ rules/
COPY --chown=scanner:scanner config/ config/
COPY --chown=scanner:scanner scan.py entrypoint.sh run_scans.sh dlcodeql.sh ./
RUN chmod +x entrypoint.sh run_scans.sh dlcodeql.sh

VOLUME ["/work"]  # reports/cache live here

# ENTRYPOINT ["./entrypoint.sh"]

USER root

CMD /bin/bash

# docker run --rm -v "$PWD/out:/work" hbs:latest --formula zstd