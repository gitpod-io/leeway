FROM ubuntu:jammy

ADD https://raw.githubusercontent.com/gitpod-io/workspace-images/main/base/install-packages /usr/bin/install-packages
RUN chmod +x /usr/bin/install-packages

RUN install-packages \
    zip unzip \
    jq \
    curl \
    ca-certificates \
    file \
    git \
    sudo \
    node.js

ENV GO_VERSION=1.24.0
RUN echo "TARGETPLATFORM=${TARGETPLATFORM:-linux/amd64}" && \
    case "${TARGETPLATFORM:-linux/amd64}" in \
    "linux/arm64") \
      echo "GO_PLATFORM=linux-arm64" > /tmp/go_platform.env \
      ;; \
    *) \
      echo "GO_PLATFORM=linux-amd64" > /tmp/go_platform.env \
      ;; \
    esac

# Install Go and add it to PATH
RUN . /tmp/go_platform.env && \
    curl -fsSL https://dl.google.com/go/go$GO_VERSION.$GO_PLATFORM.tar.gz | tar -C /usr/local -xzs

ENV SHFMT_VERSION=3.10.0
RUN curl -sSL -o /usr/local/bin/shfmt "https://github.com/mvdan/sh/releases/download/v${SHFMT_VERSION}/shfmt_v${SHFMT_VERSION}_linux_amd64" && \
    chmod 755 /usr/local/bin/shfmt

USER gitpod

# Set Go environment variables
ENV GOROOT=/usr/local/go
ENV PATH=$GOROOT/bin:$PATH
ENV GOPATH=/home/gitpod/go
ENV PATH=$GOPATH/bin:$PATH

# install VS Code Go tools for use with gopls as per https://github.com/golang/vscode-go/blob/master/docs/tools.md
# also https://github.com/golang/vscode-go/blob/27bbf42a1523cadb19fad21e0f9d7c316b625684/src/goTools.ts#L139
RUN go install -v github.com/uudashr/gopkgs/cmd/gopkgs@v2 \
    && go install -v github.com/ramya-rao-a/go-outline@latest \
    && go install -v github.com/cweill/gotests/gotests@latest \
    && go install -v github.com/fatih/gomodifytags@latest \
    && go install -v github.com/josharian/impl@latest \
    && go install -v github.com/haya14busa/goplay/cmd/goplay@latest \
    && go install -v github.com/go-delve/delve/cmd/dlv@latest \
    && go install -v github.com/golangci/golangci-lint/cmd/golangci-lint@latest \
    && go install -v golang.org/x/tools/gopls@latest \
    && go install -v honnef.co/go/tools/cmd/staticcheck@latest
