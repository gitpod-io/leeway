FROM ubuntu:jammy

# Install latest Leeway release
ENV GO_PLATFORM=linux-amd64
RUN apt-get update && apt-get install -y curl && \
    LATEST_LEEWAY_VERSION=$(curl -s https://api.github.com/repos/gitpod-io/leeway/releases/latest | grep '"tag_name"' | sed 's/.*"tag_name": "v\([^"]*\)".*/\1/') && \
    curl -L -o /tmp/leeway.tar.gz https://github.com/gitpod-io/leeway/releases/download/v${LATEST_LEEWAY_VERSION}/leeway_Linux_${GO_PLATFORM#linux-}.tar.gz && \
    tar -xzf /tmp/leeway.tar.gz -C /tmp && \
    install -m 755 /tmp/leeway /usr/local/bin/ && \
    rm /tmp/leeway.tar.gz && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
