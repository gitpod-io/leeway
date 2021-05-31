FROM gitpod/workspace-full

ENV rebuild=0

USER root
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/bin v1.39.0