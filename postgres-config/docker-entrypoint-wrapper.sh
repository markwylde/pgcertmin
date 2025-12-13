#!/bin/bash
# Fix permissions on log directory before starting postgres
chown -R postgres:postgres /var/log/postgresql 2>/dev/null || true
exec docker-entrypoint.sh "$@"
