#!/usr/bin/env bash
set -euo pipefail

# Basic helper functions
msg() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
ok() { echo -e "\e[1;32m[OK ]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }
err() { echo -e "\e[1;31m[ERR ]\e[0m $*\nExiting..."; exit 1; }

# Check if a required binary exists
require_binary() { 
  command -v "$1" >/dev/null || err "Missing binary: $1 (required for this script)." 
}

# Safe in-place INI configuration updater
update_ini_config() {
  local file="$1" section="$2" key="$3" value="$4"
  local tmp_file
  tmp_file=$(mktemp)

  awk -v SECTION="[$section]" -v KEY="$key" -v VALUE="$value" '
    BEGIN { in_section = 0; key_updated = 0 }
    /^\[.*\]$/ { 
      # Detect section boundary
      if (in_section == 1 && key_updated == 0) { print KEY " = " VALUE; key_updated = 1 }
      in_section = ($0 == SECTION) ? 1 : 0 
    }
    {
      # If key exists in the correct section, update it
      if (in_section == 1 && match($0, "^[ \t]*" KEY "[ \t]*=")) { 
        print KEY " = " VALUE; key_updated = 1 
      } else {
        print $0 
      }
    }
    END {
      # Add section/key if not previously seen
      if (in_section == 0) { 
        print SECTION "\n" KEY " = " VALUE 
      } else if (!key_updated) {
        print KEY " = " VALUE 
      }
    }
  ' "$file" > "$tmp_file"

  mv "$tmp_file" "$file"
}

# Safely add multiple INI options
update_ini_many() {
  local file="$1" section="$2"; shift 2
  while (( "$#" )); do
    local key="$1"; shift
    local value="$1"; shift
    update_ini_config "$file" "$section" "$key" "$value"
  done
}

# OpenSSL wrapper (via Splunk binary)
splunk_openssl() {
  "$SPLUNK_HOME/bin/splunk" cmd openssl "$@"
}

# Generate SAN OpenSSL config dynamically
generate_san_config() {
  local filename="$1" common_name="$2" ips="$3" dns_names="$4"
  local counter=1

  cat > "$filename" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C = ${C_VAL}
ST = ${ST_VAL}
L = ${L_VAL}
O = ${O_VAL}
$( [[ -n "${OU_VAL}" ]] && echo "OU = ${OU_VAL}" )
CN = ${common_name}

[req_ext]
subjectAltName = @alt_names

[alt_names]
EOF

  # Add SAN IPs to configuration
  for ip in ${ips//,/ }; do
    echo "IP.${counter} = ${ip}" >> "$filename"
    ((counter++))
  done

  # Add SAN DNS names to configuration
  for dns in ${dns_names//,/ }; do
    echo "DNS.${counter} = ${dns}" >> "$filename"
    ((counter++))
  done
}

# Validate combined certificate PEM file
validate_combined_pem_file() {
  local pem_file="$1"
  [[ -f "$pem_file" ]] || err "Combined PEM file missing: $pem_file"
  grep -q "PRIVATE KEY" "$pem_file" || err "No PRIVATE KEY found in $pem_file"
  grep -q "BEGIN CERTIFICATE" "$pem_file" || err "No CERTIFICATE found in $pem_file"
  ok "Combined PEM file structure appears valid: $pem_file"
}

# Restart Splunk safely
restart_splunk() {
  sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" restart
  ok "Splunk restarted successfully. Verify connectivity."
}

# Sync files to remote nodes using rsync
sync_to_remote() {
  local source_path="$1" destination_path="$2"
  local ssh_user="$3" ssh_host="$4" ssh_port="$5"
  rsync -az -e "ssh -p $ssh_port" "$source_path" "${ssh_user}@${ssh_host}:${destination_path}"
  ok "Files synced to $ssh_host:$destination_path"
}

# Updated main logic goes here
setup_splunk_tls() {
  # Variables, paths, and key prompts are initialized here
  # ...
  # Function invocations for generating SAN configs, signing certs
  # Update INI keys in `server.conf` and `web.conf` via update_ini_many
  # Verify TLS with OpenSSL s_client
  # Restart Splunk
  # ...
}

# Entry point for the script
main() {
  # Environment checks
  require_binary awk
  require_binary openssl
  require_binary ssh
  require_binary rsync

  setup_splunk_tls
}

main "$@"
