#!/bin/bash
# Helper script to run leeway from source with go run
# Usage: ./leeway-dev.sh build :package --otel-endpoint=localhost:4318

cd "$(dirname "$0")"
exec go run . "$@"
