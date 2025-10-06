#!/usr/bin/env bash
set -euo pipefail

if ! JAVA8_HOME=$(/usr/libexec/java_home -v 1.8 2>/dev/null); then
  echo "Java 8 runtime not found. Install it or adjust this script." >&2
  exit 1
fi

export JAVA_HOME="$JAVA8_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

exec ./gradlew run "$@"
