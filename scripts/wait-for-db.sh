#!/bin/sh
set -eu

host="$1"
port="$2"

until nc -z "$host" "$port"; do
  echo "waiting for database at ${host}:${port}"
  sleep 1
done
