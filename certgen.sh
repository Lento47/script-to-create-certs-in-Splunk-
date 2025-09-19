#!/usr/bin/env bash
set -euo pipefail

##############################################
# Splunk TLS one-shot setup (Linux)
# - Root CA + Server cert with SAN IPs
# - splunkd combined PEM for inter-Splunk/KV
# - Separate cert+key for Splunk Web
# - Safe validators (PKCS#1/PKCS#8)
##############################################

# --- Config ---
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
CERT_DIR="$SPLUNK_HOME/etc/auth/mycerts"
SPLUNK_USER="${SPLUNK_USER:-splunk}"

# Cert subjects
CA_CN="${CA_CN:-splunk-ca}"
SERVER_CN="${SERVER_CN:-splunk-server}"

# Validity (days)
DAYS_VALID="${DAYS_VALID:-1095}"

# SAN IPs (comma-separated). Edit if needed.
SAN_IPS="${SAN_IPS:-10.236.10.166,10.236.10.228,10.236.10.16,10.236.8.188}"

# File names
CA_KEY="myCAPrivateKey.key"
CA_CSR="myCACertificate.csr"
CA_PEM="myCACertificate.pem"
CA_SRL="myCACertificate.srl"

SVR_KEY_ENC="myServerPrivateKey.key"
SVR_KEY_DEC="myServerPrivateKey-decrypted.key"
SVR_CSR="myServerCertificate.csr"
SVR_PEM="myServerCertificate.pem"

# Output bundles
WEB_BUNDLE="mySplunkWebCert.pem"          # (we keep it for convenience)
SPLUNKD_COMBINED="splunkd-combined.pem"   # REQUIRED by splunkd

# --- Helpers ---
msg() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
ok()  { echo -e "\e[1;32m[ OK ]\e[0m $*"; }
err() { echo -e "\e[1;31m[ERR]\e[0m $*"; exit 1; }

require_bin() {
  command -v "$1" >/dev/null 2>&1 || err "Missing binary: $1"
}

# We use Splunk's OpenSSL wrapper to ensure compatible OpenSSL is used.
OPENSSL() {
  "$SPLUNK_HOME/bin/splunk" cmd openssl "$@"
}

validate_combined() {
  local file="$1"
  [[ -f "$file" ]] || err "Combined file not found: $file"

  if ! grep -q "BEGIN CERTIFICATE" "$file"; then
    err "Combined $file invalid: missing CERTIFICATE block"
  fi

  if ! egrep -q "BEGIN (RSA )?PRIVATE KEY" "$file"; then
    err "Combined $file invalid: missing PRIVATE KEY block (RSA or PKCS#8)"
  fi

  ok "Structure looks good: $file"
}

# Build SAN config on the fly
build_san_cnf() {
  local cnf="$CERT_DIR/san.cnf"
  local ip_list="$SAN_IPS"
  IFS=',' read -ra ARR <<<"$ip_list"

  cat > "$cnf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C = US
ST = California
O = MyCompany
CN = $SERVER_CN

[req_ext]
subjectAltName = @alt_names

[alt_names]
EOF

  local i=1
  for ip in "${ARR[@]}"; do
    echo "IP.$i = ${ip// /}" >> "$cnf"
    ((i++))
  done

  echo "$cnf"
}

# --- Pre-flight ---
require_bin sudo
require_bin grep
require_bin egrep
require_bin sed
require_bin curl

[[ -x "$SPLUNK_HOME/bin/splunk" ]] || err "Splunk not found at $SPLUNK_HOME"

echo
read -rsp "Enter password for Root CA private key: " CA_PW; echo
read -rsp "Enter password for Server private key: " SVR_PW; echo

# --- Create dir ---
msg "Creating certificate directory: $CERT_DIR"
sudo mkdir -p "$CERT_DIR"
sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$CERT_DIR"

cd "$CERT_DIR"

# --- Generate CA ---
if [[ ! -f "$CA_KEY" || ! -f "$CA_PEM" ]]; then
  msg "Generating Root CA private key..."
  OPENSSL genrsa -aes256 -passout pass:"$CA_PW" -out "$CA_KEY" 2048

  msg "Generating Root CA CSR..."
  OPENSSL req -new -key "$CA_KEY" -passin pass:"$CA_PW" -out "$CA_CSR" \
    -subj "/C=US/ST=California/O=MyCompany/CN=$CA_CN"

  msg "Generating Root CA certificate ($DAYS_VALID days)..."
  OPENSSL x509 -req -in "$CA_CSR" -sha512 \
    -signkey "$CA_KEY" -passin pass:"$CA_PW" \
    -CAcreateserial -out "$CA_PEM" -days "$DAYS_VALID"
else
  ok "Using existing CA: $CA_PEM"
fi

# --- Generate server key/cert ---
if [[ ! -f "$SVR_KEY_ENC" ]]; then
  msg "Generating Server private key (encrypted)..."
  OPENSSL genrsa -aes256 -passout pass:"$SVR_PW" -out "$SVR_KEY_ENC" 2048
else
  ok "Using existing server key: $SVR_KEY_ENC"
fi

msg "Generating decrypted Server private key (for Splunk usage, no prompt)..."
OPENSSL rsa -in "$SVR_KEY_ENC" -passin pass:"$SVR_PW" -out "$SVR_KEY_DEC"

msg "Creating SAN config with IPs: $SAN_IPS"
SAN_CNF="$(build_san_cnf)"

msg "Generating Server CSR with SANs..."
OPENSSL req -new -key "$SVR_KEY_ENC" -passin pass:"$SVR_PW" -out "$SVR_CSR" -config "$SAN_CNF"

msg "Signing Server certificate with CA ($DAYS_VALID days)..."
OPENSSL x509 -req -in "$SVR_CSR" -sha256 \
  -CA "$CA_PEM" -CAkey "$CA_KEY" -passin pass:"$CA_PW" -CAcreateserial \
  -out "$SVR_PEM" -days "$DAYS_VALID" -extensions req_ext -extfile "$SAN_CNF"

# --- Verify SANs are present ---
msg "Verifying SANs present in server certificate..."
OPENSSL x509 -in "$SVR_PEM" -text -noout | grep -A2 "Subject Alternative Name" || {
  echo "WARNING: Could not display SANs. Inspect $SVR_PEM manually."
}

# --- Build combined PEMs ---
msg "Building splunkd combined PEM (ORDER: cert + key + CA)..."
cat "$SVR_PEM" "$SVR_KEY_DEC" "$CA_PEM" > "$SPLUNKD_COMBINED"
validate_combined "$SPLUNKD_COMBINED"

msg "Building (optional) Web convenience bundle (same order)..."
cat "$SVR_PEM" "$SVR_KEY_DEC" "$CA_PEM" > "$WEB_BUNDLE"
validate_combined "$WEB_BUNDLE"

# --- Permissions ---
msg "Locking down permissions..."
sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$CERT_DIR"/*
sudo chmod 600 "$CERT_DIR"/*

# --- Configure Splunk: splunkd (inter-Splunk/KV/etc) ---
SVRCONF="$SPLUNK_HOME/etc/system/local/server.conf"
msg "Configuring $SVRCONF ..."
sudo mkdir -p "$(dirname "$SVRCONF")"
sudo bash -c "cat > '$SVRCONF'" <<EOF
[sslConfig]
enableSplunkdSSL = true
serverCert       = $CERT_DIR/$SPLUNKD_COMBINED
sslRootCAPath    = $CERT_DIR/$CA_PEM
sslVersions      = tls1.2
requireClientCert = false
EOF

# --- Configure Splunk: Web ---
WEBCONF="$SPLUNK_HOME/etc/system/local/web.conf"
msg "Configuring $WEBCONF ..."
sudo mkdir -p "$(dirname "$WEBCONF")"
sudo bash -c "cat > '$WEBCONF'" <<EOF
[settings]
enableSplunkWebSSL = true
serverCert  = $CERT_DIR/$SVR_PEM
privKeyPath = $CERT_DIR/$SVR_KEY_DEC
EOF

# --- Optional hardening for Splunk Python HTTPS ---
LAUNCHCONF="$SPLUNK_HOME/etc/splunk-launch.conf"
msg "Ensuring PYTHONHTTPSVERIFY=1 in $LAUNCHCONF ..."
sudo sed -i '/^PYTHONHTTPSVERIFY=/d' "$LAUNCHCONF" || true
echo 'PYTHONHTTPSVERIFY=1' | sudo tee -a "$LAUNCHCONF" >/dev/null

sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$SVRCONF" "$WEBCONF" "$LAUNCHCONF"
sudo chmod 600 "$SVRCONF" "$WEBCONF" "$LAUNCHCONF"

# --- Restart Splunk ---
msg "Restarting Splunk..."
sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" restart

# --- Verify ---
msg "Verifying Splunk Web (expect self-signed warning in browsers)..."
if curl -skI "https://$(hostname -I | awk '{print $1}'):8000" >/dev/null; then
  ok "Splunk Web responded on 8000 (HTTPS)"
else
  echo "WARN: Could not reach Splunk Web on 8000. Check firewalls/web.conf."
fi

msg "Verifying splunkd TLS on 8089 using CA trust..."
if "$SPLUNK_HOME/bin/splunk" cmd openssl s_client \
    -connect "$(hostname -I | awk '{print $1}')":8089 \
    -CAfile "$CERT_DIR/$CA_PEM" </dev/null 2>/dev/null | head -n1 | grep -q 'CONNECTED'; then
  ok "splunkd (8089) TLS looks good"
else
  echo "WARN: splunkd TLS check failed. Inspect $SPLUNK_HOME/var/log/splunk/splunkd.log"
fi

# KV Store health (uses splunkd TLS underneath)
msg "Checking KV Store status..."
if sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" show kvstore-status >/dev/null 2>&1; then
  ok "KV Store command executed. Review output above for 'ready' state."
else
  echo "WARN: KV Store status check failed; ensure splunkd is fully up."
fi

echo
ok "TLS setup complete.
- splunkd combined: $CERT_DIR/$SPLUNKD_COMBINED
- CA trust       : $CERT_DIR/$CA_PEM
- Web cert/key   : $CERT_DIR/$SVR_PEM / $CERT_DIR/$SVR_KEY_DEC

Distribute to other nodes (same paths/owner/perms):
  $CERT_DIR/$CA_PEM
  $CERT_DIR/$SVR_PEM
  $CERT_DIR/$SVR_KEY_DEC
  $CERT_DIR/$SPLUNKD_COMBINED

Then restart Splunk on each node."
