#!/usr/bin/env bash
set -euo pipefail

##############################################
# Splunk TLS setup (Root CA + leafs + optional remote CSR signing)
# - Keeps existing server.conf/web.conf; only updates needed keys
# - Fixes permissions so $SPLUNK_USER can read existing keys
# - RANDFILE in /tmp to avoid "unable to write 'random state'"
# - SELinux context restore on cert dir if enforcing
# NOTE: This version uses ABSOLUTE PATHS for all key/cert outputs to avoid
#       failures when `splunk cmd` changes the working directory.
##############################################

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
ok()  { echo -e "\e[1;32m[ OK ]\e[0m $*"; }
warn(){ echo -e "\e[1;33m[WARN]\e[0m $*"; }
err() { echo -e "\e[1;31m[ERR ]\e[0m $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || err "Missing binary: $1"; }

ask_def() {
  local p="$1" d="${2:-}" a
  if [[ -n "$d" ]]; then read -r -p "$p [$d]: " a || true; echo "${a:-$d}";
  else read -r -p "$p: " a || true; echo "$a"; fi
}
ask_yn() {
  local p="$1" d="$2" a show="[y/N]"; [[ "${d,,}" == "y" ]] && show="[Y/n]"
  read -r -p "$p $show: " a || true; a="${a:-$d}"
  [[ "${a,,}" =~ ^y(es)?$ ]] && echo "y" || echo "n"
}

# --- sed-based INI updater (section-scoped; only sets/updates specific keys) ---
ini_set() {
  local file="$1" section="$2" key="$3" value="$4"
  local esc_section esc_key esc_value
  esc_section="$(printf '%s' "$section" | sed 's/[.[*^$\/]/\\&/g')"
  esc_key="$(printf '%s' "$key" | sed 's/[.[*^$\/]/\\&/g')"
  # Escape & / and \ in replacement values
  esc_value="$(printf '%s' "$value" | sed 's/[&\/\\]/\\&/g')"
  sudo touch "$file"
  if ! grep -qE "^\[$esc_section\]\s*$" "$file"; then
    printf '\n[%s]\n%s = %s\n' "$section" "$key" "$value" | sudo tee -a "$file" >/dev/null; return
  fi
  if sed -n "/^\[$esc_section\]\s*$/,/^\[/{p}" "$file" | grep -qE "^[[:space:]]*$esc_key[[:space:]]*="; then
    sudo sed -i -E "/^\[$esc_section\]\s*$/,/^\[/{s|^[[:space:]]*$esc_key[[:space:]]*=.*|$key = $esc_value|}" "$file"
  else
    sudo sed -i -E "/^\[$esc_section\]\s*$/a $key = $esc_value" "$file"
  fi
}
ini_set_many(){ local f="$1" s="$2"; shift 2; while (($#)); do ini_set "$f" "$s" "$1" "$2"; shift 2; done; }

# wrappers
OPENSSL()  { sudo -u "$SPLUNK_USER" openssl "$@"; }  # run OpenSSL explicitly as the Splunk user
OSSL()     { openssl "$@"; }                                # system openssl (caller user)

validate_combined(){
  local f="$1"
  [[ -f "$f" ]] || err "Missing combined file: $f"
  grep -q "BEGIN CERTIFICATE" "$f" || err "No CERTIFICATE block in $f"
  grep -Eq "BEGIN (RSA )?PRIVATE KEY" "$f" || err "No PRIVATE KEY block in $f"
}

mk_san_cnf(){
  local path="$1" cn="$2" ips="$3" dns="$4"
  IFS=',' read -ra IPA<<<"${ips}"; IFS=',' read -ra DNA<<<"${dns}"
  cat > "$path" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
[dn]
C  = ${C_VAL}
ST = ${ST_VAL}
L  = ${L_VAL}
O  = ${O_VAL}
$( [[ -n "${OU_VAL}" ]] && echo "OU = ${OU_VAL}" )
CN = ${cn}
[req_ext]
subjectAltName = @alt_names
[alt_names]
EOF
  local i=1; for ip in "${IPA[@]}"; do ip="${ip// /}"; [[ -z "$ip" ]]||echo "IP.$i = $ip" >> "$path"; ((i++)); done
  local j=1; for dn in "${DNA[@]}"; do dn="${dn// /}"; [[ -z "$dn" ]]||echo "DNS.$j = $dn" >> "$path"; ((j++)); done
}

ens_own600(){ # usage: ens_own600 user:group file...
  local ug="$1"; shift
  for f in "$@"; do [[ -e "$f" ]] || continue; sudo chown "$ug" "$f" || true; sudo chmod 600 "$f" || true; done
}

umask 077
need sudo; need sed; need grep; need ssh; need rsync; need curl; need openssl

# ---- prompts ----
SPLUNK_HOME="$(ask_def "SPLUNK_HOME" "/opt/splunk")"; [[ -x "$SPLUNK_HOME/bin/splunk" ]] || err "Splunk not found at $SPLUNK_HOME"
SPLUNK_USER="$(ask_def "Splunk UNIX user" "splunk")"
CERT_DIR="$(ask_def "Certificate directory" "$SPLUNK_HOME/etc/auth/mycerts")"

info "X.509 Subject"
C_VAL="$(ask_def "  Country (C)" "US")"
ST_VAL="$(ask_def "  State/Province (ST)" "California")"
L_VAL="$(ask_def "  Locality/City (L)" "San Jose")"
O_VAL="$(ask_def "  Organization (O)" "MyCompany")"
OU_VAL="$(ask_def "  Organizational Unit (OU, optional)" "")"
CA_CN="$(ask_def "  CA Common Name (CN for Root CA)" "splunk-ca")"
SERVER_CN="$(ask_def "  Server Common Name (CN for THIS node)" "splunk-server")"

info "Subject Alternative Names (SANs)"
SAN_IPS="$(ask_def "  IPs (comma-separated, at least one)" "10.236.10.166,10.236.10.228,10.236.10.16,10.236.8.188")"
SAN_DNS="$(ask_def "  DNS names (comma-separated, optional)" "")"
[[ -z "${SAN_IPS//,/}" && -z "${SAN_DNS//,/}" ]] && err "Need at least one SAN (IP or DNS)."

DAYS_VALID="$(ask_def "Certificate validity (days)" "1095")"
TLS_VER="$(ask_def "TLS version for splunkd" "tls1.2")"
REQUIRE_MTLS="$(ask_yn "Enable mTLS (require client certs) for inter-Splunk?" "n")"
CFG_WEB="$(ask_yn "Configure Splunk Web (TLS on 8000)?" "y")"
SET_PYVERIFY="$(ask_yn "Set PYTHONHTTPSVERIFY=1?" "y")"
USE_DECRYPTED="$(ask_yn "Use decrypted server private key (no password prompts)?" "y")"

AUTO_SYNC="$(ask_yn "Auto-sync to remote nodes (generate CSR remotely, sign here)?" "n")"
SSH_HOSTS=""; SSH_USER="root"; SSH_PORT="22"; SSH_KEY=""
REMOTE_SPLUNK_USER="$SPLUNK_USER"; REMOTE_SUDO="y"
if [[ "$AUTO_SYNC" == "y" ]]; then
  SSH_HOSTS="$(ask_def "  Remote hosts (comma-separated)" "10.236.10.16,10.236.10.228")"
  SSH_USER="$(ask_def "  SSH user" "root")"
  SSH_PORT="$(ask_def "  SSH port" "22")"
  SSH_KEY="$(ask_def "  SSH key path (empty = default)" "")"
  REMOTE_SPLUNK_USER="$(ask_def "  Remote Splunk UNIX user" "$SPLUNK_USER")"
  REMOTE_SUDO="$(ask_yn "  Use sudo on remotes?" "y")"
fi

# ---- dirs & RANDFILE (use /tmp to avoid permission/SELinux issues) ----
sudo mkdir -p "$CERT_DIR"
sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$CERT_DIR"
sudo chmod 700 "$CERT_DIR"

RANDFILE="/tmp/.rnd-$SPLUNK_USER"
touch "$RANDFILE" 2>/dev/null || true
sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$RANDFILE" 2>/dev/null || true
sudo chmod 600 "$RANDFILE" 2>/dev/null || true
export RANDFILE

# SELinux contexts (if enforcing)
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]]; then
  info "SELinux enforcing: restoring contexts on $CERT_DIR"
  command -v restorecon >/dev/null 2>&1 && sudo restorecon -Rv "$CERT_DIR" || true
fi

# ---- filenames (ABSOLUTE paths) ----
CA_KEY="$CERT_DIR/myCAPrivateKey.key"; CA_CSR="$CERT_DIR/myCACertificate.csr"; CA_PEM="$CERT_DIR/myCACertificate.pem"; CA_SRL="$CERT_DIR/myCACertificate.srl"
SVR_KEY_ENC="$CERT_DIR/myServerPrivateKey.key"; SVR_KEY_DEC="$CERT_DIR/myServerPrivateKey-decrypted.key"
SVR_CSR="$CERT_DIR/myServerCertificate.csr"; SVR_PEM="$CERT_DIR/myServerCertificate.pem"
SPLUNKD_COMBINED="$CERT_DIR/splunkd-combined.pem"; WEB_BUNDLE="$CERT_DIR/mySplunkWebCert.pem"
SAN_CNF="$CERT_DIR/san.cnf"

# ---- passwords ----
echo; read -rsp "Enter password for Root CA private key (new or existing): " CA_PW; echo
read -rsp "Enter password for Server private key: " SVR_PW; echo

# ---- Root CA (reuse or create) ----
if [[ -f "$CA_PEM" ]]; then
  ok "Found existing CA at $CA_PEM (will reuse for cluster)"
  ens_own600 "$SPLUNK_USER:$SPLUNK_USER" "$CA_PEM" "$CA_KEY" "$CA_SRL" "$CA_CSR"
  [[ -f "$CA_KEY" ]] || err "Existing CA cert found but $CA_KEY is missing (required to sign CSRs). Place it in $CERT_DIR."
else
  info "Generating Root CA..."
  OPENSSL genrsa -aes256 -passout pass:"$CA_PW" -out "$CA_KEY" 2048
  OPENSSL req -new -key "$CA_KEY" -passin pass:"$CA_PW" -out "$CA_CSR" \
    -subj "/C=$C_VAL/ST=$ST_VAL/L=$L_VAL/O=$O_VAL$( [[ -n "$OU_VAL" ]] && printf "/OU=%s" "$OU_VAL" )/CN=$CA_CN"
  OPENSSL x509 -req -in "$CA_CSR" -sha512 -signkey "$CA_KEY" -passin pass:"$CA_PW" \
    -CAcreateserial -out "$CA_PEM" -days "$DAYS_VALID"
  ens_own600 "$SPLUNK_USER:$SPLUNK_USER" "$CA_PEM" "$CA_KEY" "$CA_SRL" "$CA_CSR"
fi

# Show CA fingerprint (caller openssl)
OSSL x509 -in "$CA_PEM" -noout -subject -issuer -serial -fingerprint -sha256 | sed 's/^/[CA] /'
echo

# ---- Ensure existing server key material is readable by $SPLUNK_USER ----
if [[ -f "$SVR_KEY_ENC" ]]; then
  sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$SVR_KEY_ENC" || true
  sudo chmod 600 "$SVR_KEY_ENC" || true
fi
if [[ -f "$SVR_KEY_DEC" ]]; then
  sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$SVR_KEY_DEC" || true
  sudo chmod 600 "$SVR_KEY_DEC" || true
fi

# ---- Local server key/cert ----
# If an encrypted key already exists and user wants decrypted, verify password first.
if [[ -f "$SVR_KEY_ENC" && "$USE_DECRYPTED" == "y" ]]; then
  if ! sudo -u "$SPLUNK_USER" openssl rsa -in "$SVR_KEY_ENC" -passin pass:"$SVR_PW" -noout >/dev/null 2>&1; then
    warn "Existing server key found, but the password you entered does not decrypt it."
    if [[ "$(ask_yn "Recreate server key with the password you just entered? (will back up and reissue)" "n")" == "y" ]]; then
      ts="$(date +%s)"
      sudo mv -f "$SVR_KEY_ENC" "$SVR_KEY_ENC.bak.$ts" 2>/dev/null || true
      [[ -f "$SVR_KEY_DEC" ]] && sudo mv -f "$SVR_KEY_DEC" "$SVR_KEY_DEC.bak.$ts" 2>/dev/null || true
      [[ -f "$SVR_CSR" ]] && sudo mv -f "$SVR_CSR" "$SVR_CSR.bak.$ts" 2>/dev/null || true
      [[ -f "$SVR_PEM" ]] && sudo mv -f "$SVR_PEM" "$SVR_PEM.bak.$ts" 2>/dev/null || true
    else
      warn "Proceeding without decryption; splunkd will prompt for a passphrase at restart."
      USE_DECRYPTED="n"
    fi
  fi
fi

if [[ ! -f "$SVR_KEY_ENC" ]]; then
  info "Generating local server private key..."
  sudo -u "$SPLUNK_USER" openssl genrsa -aes256 -passout pass:"$SVR_PW" -out "$SVR_KEY_ENC" 2048
fi

# Create decrypted key if requested
if [[ "$USE_DECRYPTED" == "y" ]]; then
  info "Creating decrypted key (for splunkd/web)..."
  sudo -u "$SPLUNK_USER" openssl rsa -in "$SVR_KEY_ENC" -passin pass:"$SVR_PW" -out "$SVR_KEY_DEC"
  sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$SVR_KEY_DEC" || true
  sudo chmod 600 "$SVR_KEY_DEC" || true
  KEY_TO_USE="$SVR_KEY_DEC"
else
  KEY_TO_USE="$SVR_KEY_ENC"
fi

mk_san_cnf "$SAN_CNF" "$SERVER_CN" "$SAN_IPS" "$SAN_DNS"
# ensure Splunk user can read SAN config before running openssl req
sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$SAN_CNF" || true
sudo chmod 600 "$SAN_CNF" || true

info "Creating CSR (local) with SANs..."
OPENSSL req -new -key "$SVR_KEY_ENC" -passin pass:"$SVR_PW" -out "$SVR_CSR" -config "$SAN_CNF"

info "Signing local server certificate with local CA..."
OPENSSL x509 -req -in "$SVR_CSR" -sha256 -CA "$CA_PEM" -CAkey "$CA_KEY" -passin pass:"$CA_PW" \
  -CAcreateserial -out "$SVR_PEM" -days "$DAYS_VALID" -extensions req_ext -extfile "$SAN_CNF"

# Combineds (ORDER: leaf + key + CA)
cat "$SVR_PEM" "$KEY_TO_USE" "$CA_PEM" > "$SPLUNKD_COMBINED"; validate_combined "$SPLUNKD_COMBINED"
cat "$SVR_PEM" "$KEY_TO_USE" "$CA_PEM" > "$WEB_BUNDLE";      validate_combined "$WEB_BUNDLE"
ens_own600 "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNKD_COMBINED" "$WEB_BUNDLE" "$SVR_PEM" "$SVR_KEY_ENC"
[[ -f "$SVR_KEY_DEC" ]] && ens_own600 "$SPLUNK_USER:$SPLUNK_USER" "$SVR_KEY_DEC"

# Restore SELinux contexts again (new files)
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]]; then
  command -v restorecon >/dev/null 2>&1 && sudo restorecon -Rv "$CERT_DIR" || true
fi

# ---- safe-update server.conf (local; only specific keys) ----
SVRCONF="$SPLUNK_HOME/etc/system/local/server.conf"
sudo mkdir -p "$(dirname "$SVRCONF")"; sudo touch "$SVRCONF"
sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$SVRCONF"; sudo chmod 600 "$SVRCONF"

ini_set_many "$SVRCONF" "sslConfig" \
  "enableSplunkdSSL" "true" \
  "serverCert"       "$SPLUNKD_COMBINED" \
  "sslRootCAPath"    "$CA_PEM" \
  "sslVersions"      "$TLS_VER" \
  "requireClientCert" "$( [[ "$REQUIRE_MTLS" == "y" ]] && echo true || echo false )"

# ---- Splunk Web (optional; safe update) ----
if [[ "$CFG_WEB" == "y" ]]; then
  WEBCONF="$SPLUNK_HOME/etc/system/local/web.conf"
  sudo mkdir -p "$(dirname "$WEBCONF")"; sudo touch "$WEBCONF"
  sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$WEBCONF"; sudo chmod 600 "$WEBCONF"
  ini_set_many "$WEBCONF" "settings" \
    "enableSplunkWebSSL" "true" \
    "serverCert" "$SVR_PEM" \
    "privKeyPath" "$KEY_TO_USE"
  if [[ "$USE_DECRYPTED" == "n" ]]; then
    ini_set "$WEBCONF" "settings" "sslPassword" "$SVR_PW"
  fi
fi

# ---- PYTHONHTTPSVERIFY (optional) ----
if [[ "$SET_PYVERIFY" == "y" ]]; then
  LAUNCHCONF="$SPLUNK_HOME/etc/splunk-launch.conf"
  sudo sed -i '/^PYTHONHTTPSVERIFY=/d' "$LAUNCHCONF" || true
  echo 'PYTHONHTTPSVERIFY=1' | sudo tee -a "$LAUNCHCONF" >/dev/null
  sudo chown "$SPLUNK_USER:$SPLUNK_USER" "$LAUNCHCONF" || true
  sudo chmod 600 "$LAUNCHCONF" || true
fi

# ---- restart helpers ----
restart_splunk_local(){
  if command -v systemctl >/dev/null 2>&1 && systemctl status Splunkd >/dev/null 2>&1; then
    info "Restarting Splunk via systemd (Splunkd)..."
    sudo systemctl restart Splunkd
  else
    info "Restarting Splunk via CLI..."
    sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" restart
  fi
}

# ---- restart local & check ----
restart_splunk_local

LOCAL_IP="$(hostname -I | awk '{print $1}')"
info "Check splunkd TLS (8089, local)"
if openssl s_client -connect "$LOCAL_IP:8089" -CAfile "$CA_PEM" </dev/null 2>/dev/null | head -n1 | grep -q CONNECTED; then
  ok "splunkd TLS ok on $LOCAL_IP:8089"
else
  warn "splunkd TLS check failed on $LOCAL_IP:8089"
fi

if [[ "$CFG_WEB" == "y" ]]; then
  info "Check Web TLS (8000, local)"; curl -skI "https://$LOCAL_IP:8000" >/dev/null && ok "Web TLS up on 8000" || warn "Web 8000 check failed"
fi

# ---- remote CSR/sign/sync (optional) ----
if [[ "$AUTO_SYNC" == "y" && -n "${SSH_HOSTS// /}" ]]; then
  info "Begin remote CSR/sign/sync (CA hub = THIS node)"
  IFS=',' read -ra HOSTS <<<"$SSH_HOSTS"
  RSH_OPTS="-o StrictHostKeyChecking=no -p $SSH_PORT"; [[ -n "$SSH_KEY" ]] && RSH_OPTS="$RSH_OPTS -i $SSH_KEY"

  for H in "${HOSTS[@]}"; do
    H="${H// /}"; [[ -z "$H" ]] && continue
    info "Preparing $H"
    ssh $RSH_OPTS "$SSH_USER@$H" "set -e; $( [[ "$REMOTE_SUDO" == "y" ]] && echo sudo ) mkdir -p '$CERT_DIR' '$SPLUNK_HOME/etc/system/local'; $( [[ "$REMOTE_SUDO" == "y" ]] && echo sudo ) chown -R '$REMOTE_SPLUNK_USER:$REMOTE_SPLUNK_USER' '$CERT_DIR' '$SPLUNK_HOME/etc/system/local'; $( [[ "$REMOTE_SUDO" == "y" ]] && echo sudo ) chmod 700 '$CERT_DIR'"
    rsync -az -e "ssh $RSH_OPTS" "$CA_PEM" "$SSH_USER@$H:$CERT_DIR/"
  done

  for H in "${HOSTS[@]}"; do
    H="${H// /}"; [[ -z "$H" ]] && continue
    info "Remote key/CSR on $H"
    read -r -d '' REM_SCRIPT <<'RS'
set -e
CERT_DIR="$1"; SPLUNK_HOME="$2"; SERVER_CN="$3"; SVR_PW="$4"; USE_DECRYPTED="$5"; SAN_IPS="$6"; SAN_DNS="$7"; REMOTE_SPLUNK_USER="$8"
RANDFILE="/tmp/.rnd-$REMOTE_SPLUNK_USER"; touch "$RANDFILE" 2>/dev/null || true; chmod 600 "$RANDFILE" 2>/dev/null || true
export RANDFILE
SAN_CNF="$CERT_DIR/san-remote.cnf"
cat > "$SAN_CNF" <<EOF
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
# make SAN config readable by the Splunk user before openssl req
chown "$REMOTE_SPLUNK_USER:$REMOTE_SPLUNK_USER" "$SAN_CNF" || true
chmod 600 "$SAN_CNF" || true
i=1; IFS=','; for ip in $SAN_IPS; do ip="${ip// /}"; [ -z "$ip" ] || echo "IP.$i = $ip" >> "$SAN_CNF"; i=$((i+1)); done
j=1; IFS=','; for dn in $SAN_DNS; do dn="${dn// /}"; [ -z "$dn" ] || echo "DNS.$j = $dn" >> "$SAN_CNF"; j=$((j+1)); done
# Ensure existing keys readable by Splunk user
if [ -f "$CERT_DIR/myServerPrivateKey.key" ]; then chown "$REMOTE_SPLUNK_USER:$REMOTE_SPLUNK_USER" "$CERT_DIR/myServerPrivateKey.key" || true; chmod 600 "$CERT_DIR/myServerPrivateKey.key" || true; fi
if [ -f "$CERT_DIR/myServerPrivateKey-decrypted.key" ]; then chown "$REMOTE_SPLUNK_USER:$REMOTE_SPLUNK_USER" "$CERT_DIR/myServerPrivateKey-decrypted.key" || true; chmod 600 "$CERT_DIR/myServerPrivateKey-decrypted.key" || true; fi
if [ ! -f "$CERT_DIR/myServerPrivateKey.key" ]; then
  "sudo -u "$REMOTE_SPLUNK_USER" openssl genrsa -aes256 -passout pass:"$SVR_PW" -out "$CERT_DIR/myServerPrivateKey.key" 2048
fi
if [ "$USE_DECRYPTED" = "y" ]; then
  "sudo -u "$REMOTE_SPLUNK_USER" openssl rsa -in "$CERT_DIR/myServerPrivateKey.key" -passin pass:"$SVR_PW" -out "$CERT_DIR/myServerPrivateKey-decrypted.key"
  chown "$REMOTE_SPLUNK_USER:$REMOTE_SPLUNK_USER" "$CERT_DIR/myServerPrivateKey-decrypted.key" || true; chmod 600 "$CERT_DIR/myServerPrivateKey-decrypted.key" || true
fi
"sudo -u "$REMOTE_SPLUNK_USER" openssl req -new -key "$CERT_DIR/myServerPrivateKey.key" -passin pass:"$SVR_PW" -out "$CERT_DIR/myServerCertificate.csr" -config "$SAN_CNF"
chown "$REMOTE_SPLUNK_USER:$REMOTE_SPLUNK_USER" "$CERT_DIR"/* || true; chmod 600 "$CERT_DIR"/* || true; chmod 700 "$CERT_DIR" || true
RS
    # Use a host-specific CN for clarity (optional)
    REM_CN="splunk-$H"
    SUDO_CMD=""; [[ "$REMOTE_SUDO" == "y" ]] && SUDO_CMD="sudo"
    ssh $RSH_OPTS "$SSH_USER@$H" "$SUDO_CMD bash -s" <<EOF
$REM_SCRIPT
"$CERT_DIR" "$SPLUNK_HOME" "$REM_CN" "$SVR_PW" "$USE_DECRYPTED" "$SAN_IPS" "$SAN_DNS" "$REMOTE_SPLUNK_USER"
EOF
    rsync -az -e "ssh $RSH_OPTS" "$SSH_USER@$H:$CERT_DIR/myServerCertificate.csr" "$CERT_DIR/CSR-$H.csr"
    info "Signing $H CSR with local CA"
    OPENSSL x509 -req -in "$CERT_DIR/CSR-$H.csr" -sha256 -CA "$CA_PEM" -CAkey "$CA_KEY" -passin pass:"$CA_PW" \
      -CAcreateserial -out "$CERT_DIR/leaf-$H.pem" -days "$DAYS_VALID" -extensions req_ext -extfile "$SAN_CNF"
    info "Pushing signed leaf & building combined on $H"
    rsync -az -e "ssh $RSH_OPTS" "$CERT_DIR/leaf-$H.pem" "$SSH_USER@$H:$CERT_DIR/myServerCertificate.pem"
    ssh $RSH_OPTS "$SSH_USER@$H" "$SUDO_CMD bash -lc '
      set -e
      KEY_TO_USE="'"$CERT_DIR"/myServerPrivateKey.key"'
      [ -f '"$CERT_DIR"/myServerPrivateKey-decrypted.key' ] && KEY_TO_USE='"$CERT_DIR"/myServerPrivateKey-decrypted.key'
      cat '"$CERT_DIR"/myServerCertificate.pem' "$KEY_TO_USE" '"$CERT_DIR"/myCACertificate.pem' > '"$CERT_DIR"/splunkd-combined.pem'
      chown '"$REMOTE_SPLUNK_USER":"$REMOTE_SPLUNK_USER"' '"$CERT_DIR"/'* || true; chmod 600 '"$CERT_DIR"/'* || true; chmod 700 '"$CERT_DIR"' || true
    '"
    # minimal config updates on remote
    read -r -d '' REM_INI <<'RINI'
set -e
file="$1"; section="$2"; key="$3"; value="$4"
esc_section="$(printf '%s' "$section" | sed 's/[.[*^$\/]/\\&/g')"
esc_key="$(printf '%s' "$key" | sed 's/[.[*^$\/]/\\&/g')"
esc_value="$(printf '%s' "$value" | sed 's/[&\/\\]/\\&/g')"
touch "$file"
if ! grep -qE "^\[$esc_section\]\s*$" "$file"; then
  printf '\n[%s]\n%s = %s\n' "$section" "$key" "$value" >> "$file"; exit 0
fi
if sed -n "/^\[$esc_section\]\s*$/,/^\[/{p}" "$file" | grep -qE "^[[:space:]]*$esc_key[[:space:]]*="; then
  sed -i -E "/^\[$esc_section\]\s*$/,/^\[/{s|^[[:space:]]*$esc_key[[:space:]]*=.*|$key = $esc_value|}" "$file"
else
  sed -i -E "/^\[$esc_section\]\s*$/a $key = $esc_value" "$file"
fi
RINI
    ssh $RSH_OPTS "$SSH_USER@$H" "cat > /tmp/ini_set.sh <<'EOS'
$REM_INI
EOS
$SUDO_CMD chmod +x /tmp/ini_set.sh"
    ssh $RSH_OPTS "$SSH_USER@$H" bash -lc "'
      $SUDO_CMD /tmp/ini_set.sh $SPLUNK_HOME/etc/system/local/server.conf sslConfig enableSplunkdSSL true
      $SUDO_CMD /tmp/ini_set.sh $SPLUNK_HOME/etc/system/local/server.conf sslConfig serverCert $CERT_DIR/splunkd-combined.pem
      $SUDO_CMD /tmp/ini_set.sh $SPLUNK_HOME/etc/system/local/server.conf sslConfig sslRootCAPath $CERT_DIR/myCACertificate.pem
      $SUDO_CMD /tmp/ini_set.sh $SPLUNK_HOME/etc/system/local/server.conf sslConfig sslVersions $TLS_VER
      $SUDO_CMD /tmp/ini_set.sh $SPLUNK_HOME/etc/system/local/server.conf sslConfig requireClientCert $( [[ "$REQUIRE_MTLS" == "y" ]] && echo true || echo false )
      $SUDO_CMD chown $REMOTE_SPLUNK_USER:$REMOTE_SPLUNK_USER $SPLUNK_HOME/etc/system/local/*.conf || true
      $SUDO_CMD chmod 600 $SPLUNK_HOME/etc/system/local/*.conf || true
      if command -v systemctl >/dev/null 2>&1 && systemctl status Splunkd >/dev/null 2>&1; then $SUDO_CMD systemctl restart Splunkd; else $SUDO_CMD -u $REMOTE_SPLUNK_USER $SPLUNK_HOME/bin/splunk restart; fi
    '"
    ok "Remote $H complete."
  done
else
  info "Remote sync skipped."
fi

echo
info "Effective sslConfig (local):"
"$SPLUNK_HOME/bin/splunk" btool server list sslConfig --debug | grep -Ei 'enableSplunkdSSL|serverCert|sslRootCAPath|requireClientCert|sslVersions' || true

echo
ok "TLS setup complete.
- Absolute paths used for all key/cert outputs (fixes Permission denied when splunk cmd changes CWD)
- Ownership normalization so $SPLUNK_USER can read keys
- RANDFILE moved to /tmp to avoid permission issues
- Only necessary keys updated in server.conf/web.conf (no full overwrite)
- Combined PEMs: leaf + key + CA
"

