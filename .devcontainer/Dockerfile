FROM mcr.microsoft.com/devcontainers/base:ubuntu

# Install leeway build tool
RUN bash -c 'set -euo pipefail && \
    LATEST_LEEWAY_VERSION=$(curl -s https://api.github.com/repos/gitpod-io/leeway/releases/latest | jq -r ".tag_name" | sed "s/^v//") && \
    echo "Installing leeway version: $LATEST_LEEWAY_VERSION" && \
    curl -L -o /tmp/leeway.tar.gz "https://github.com/gitpod-io/leeway/releases/download/v${LATEST_LEEWAY_VERSION}/leeway_Linux_x86_64.tar.gz" && \
    tar -xzf /tmp/leeway.tar.gz -C /tmp && \
    install -m 755 /tmp/leeway /usr/local/bin/ && \
    rm /tmp/leeway.tar.gz /tmp/leeway'
