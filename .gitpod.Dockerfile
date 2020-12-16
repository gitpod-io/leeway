FROM gitpod/workspace-full

USER root
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/bin v1.33.0