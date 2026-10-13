#!/usr/bin/env bash
# Fetch Amazon RDS's certificate-authority bundle into backend/certs/ (make rds-ca).
#
# The API and dbadmin images verify the database's certificate against it (sslmode verify-full).
# The download is checked before it replaces the committed file: it must parse as PEM
# certificates, every one an Amazon RDS CA, at least one of them for this project's Region.
# Review the diff and commit it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
URL="https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem"
OUT="$ROOT/backend/certs/rds-global-bundle.pem"
REGION="${REGION:-us-east-2}"

die() { printf 'rds-ca: %s\n' "$*" >&2; exit 1; }
command -v openssl >/dev/null || die "openssl is required"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsS --proto '=https' --tlsv1.2 -o "$tmp" "$URL" || die "could not download $URL"

subjects="$(openssl crl2pkcs7 -nocrl -certfile "$tmp" 2>/dev/null | openssl pkcs7 -print_certs -noout 2>/dev/null | grep '^subject=' || true)"
count="$(printf '%s\n' "$subjects" | grep -c '^subject=' || true)"
[[ "$count" -gt 0 ]] || die "the download is not a PEM certificate bundle"
others="$(printf '%s\n' "$subjects" | grep -vc 'Amazon Web Services' || true)"
[[ "$others" -eq 0 ]] || die "the bundle contains $others certificate(s) not issued to Amazon Web Services"
printf '%s\n' "$subjects" | grep -q "$REGION" || die "no CA in the bundle names $REGION"

mv "$tmp" "$OUT"
trap - EXIT
chmod 0644 "$OUT"
printf 'rds-ca: %s certificates, sha256 %s\n' "$count" "$(sha256sum "$OUT" | cut -d' ' -f1)"
printf 'rds-ca: review and commit backend/certs/rds-global-bundle.pem\n'
