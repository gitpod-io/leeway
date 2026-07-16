FROM mcr.microsoft.com/devcontainers/base:ubuntu

# Install leeway build tool
RUN bash -c 'set -euo pipefail && \
    LATEST_LEEWAY_VERSION=$(curl -s https://api.github.com/repos/gitpod-io/leeway/releases/latest | jq -r ".tag_name" | sed "s/^v//") && \
    echo "Installing leeway version: $LATEST_LEEWAY_VERSION" && \
    curl -L -o /tmp/leeway.tar.gz "https://github.com/gitpod-io/leeway/releases/download/v${LATEST_LEEWAY_VERSION}/leeway_Linux_x86_64.tar.gz" && \
    tar -xzf /tmp/leeway.tar.gz -C /tmp && \
    install -m 755 /tmp/leeway /usr/local/bin/ && \
    rm /tmp/leeway.tar.gz /tmp/leeway'

# Install Node.js
ENV NODE_MAJOR=20
ADD https://raw.githubusercontent.com/gitpod-io/workspace-images/main/base/install-packages /usr/bin/install-packages
RUN chmod +x /usr/bin/install-packages
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \
    install-packages nodejs && \
    rm -rf /usr/include/node/openssl/archs/{aix64-gcc-as,BSD-x86,BSD-x86_64,darwin64-arm64-cc,darwin64-x86_64-cc,darwin-i386-cc,linux32-s390x,linux64-loongarch64,linux64-mips64,linux64-riscv64,linux64-s390x,linux-armv4,linux-ppc64le,solaris64-x86_64-gcc,solaris-x86-gcc,VC-WIN32} && \
    rm -rf /usr/share/doc/nodejs && \
    rm -rf ./.npm/_cacache
        
# Install claude-code globally
RUN npm i -g @anthropic-ai/claude-code