#!/bin/bash
# This script downloads and installs the latest version of leeway

set -euo pipefail

# Get the latest leeway version from GitHub API
LATEST_LEEWAY_VERSION=$(curl -s https://api.github.com/repos/gitpod-io/leeway/releases/latest | jq -r '.tag_name' | sed 's/^v//')

# Ensure we got a valid version
if [ -z "$LATEST_LEEWAY_VERSION" ]; then
    echo "Error: Could not determine latest leeway version" >&2
    exit 1
fi

echo "Installing leeway version: $LATEST_LEEWAY_VERSION"

# Download the latest leeway release
curl -L -o /tmp/leeway.tar.gz "https://github.com/gitpod-io/leeway/releases/download/v${LATEST_LEEWAY_VERSION}/leeway_Linux_x86_64.tar.gz"

# Extract the tarball
tar -xzf /tmp/leeway.tar.gz -C /tmp

# Install leeway to /usr/local/bin
sudo install -m 755 /tmp/leeway /usr/local/bin/

# Clean up temporary files
rm /tmp/leeway.tar.gz /tmp/leeway
