#!/bin/bash
set -e

DIR="./local-certs"
mkdir -p $DIR

# 1. Create CA
openssl genrsa -out $DIR/ca.key 2048
openssl req -new -x509 -days 365 -key $DIR/ca.key -out $DIR/ca.crt -subj "/CN=Local-CA"

# 2. Server Cert
openssl genrsa -out $DIR/server.key 2048
openssl req -new -key $DIR/server.key -out $DIR/server.csr -subj "/CN=localhost"
openssl x509 -req -in $DIR/server.csr -CA $DIR/ca.crt -CAkey $DIR/ca.key -CAcreateserial -out $DIR/server.crt -days 365 -sha256

# 3. Client Cert (for puzed-app)
openssl genrsa -out $DIR/client.key 2048
# CN matches the DB User 'puzed-app' or just 'puzed-app' user mapping
openssl req -new -key $DIR/client.key -out $DIR/client.csr -subj "/CN=puzed-app"
openssl x509 -req -in $DIR/client.csr -CA $DIR/ca.crt -CAkey $DIR/ca.key -CAcreateserial -out $DIR/client.crt -days 365 -sha256

# Permissions (Postgres needs strict permissions on key file?)
# Docker handling of permissions can be tricky, but let's try strict.
chmod 600 $DIR/server.key
chmod 600 $DIR/client.key
chmod 600 $DIR/ca.key

echo "Certs generated in $DIR"
