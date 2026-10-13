#!/usr/bin/env bash
#
# install.sh — one-line installer for GOST/WSS tunnel
#
# Usage (after uploading to GitHub):
#
#   curl -fsSL https://raw.githubusercontent.com/USERNAME/REPO/main/install.sh | bash -s -- A
#   curl -fsSL https://raw.githubusercontent.com/USERNAME/REPO/main/install.sh | bash -s -- B
#
# Or fully non-interactive via environment variables:
#
#   curl -fsSL .../install.sh | ROLE=A PUBLIC_PORT=443 SERVER_B_IP=1.2.3.4 \
#       SERVER_B_WSS_PORT=8443 TUNNEL_DOMAIN=cdn.example.com WS_PATH=/xk9Pz bash
#
# ------------------------------------------------------------

set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

# Get role from argument or environment variable
ROLE="${1:-${ROLE:-}}"

# If role not set and we have an interactive terminal, ask
if [[ -z "$ROLE" ]]; then
  if [[ -t 0 ]] || [[ -e /dev/tty ]]; then
    read -r -p "Is this server role A (entry/customer-facing) or B (destination)? [A/B]: " ROLE </dev/tty
  else
    echo "Role not specified. Example: bash -s -- A   or   bash -s -- B" >&2
    exit 1
  fi
fi
ROLE="$(echo "$ROLE" | tr '[:lower:]' '[:upper:]')"

if [[ "$ROLE" != "A" && "$ROLE" != "B" ]]; then
  echo "Invalid role: '$ROLE' (must be A or B)" >&2
  exit 1
fi

prompt_if_empty() {
  # prompt_if_empty VAR_NAME "question text" "default value"
  local var_name="$1" question="$2" default="$3"
  local current="${!var_name:-}"
  if [[ -z "$current" ]]; then
    if [[ -e /dev/tty ]]; then
      read -r -p "$question [$default]: " input </dev/tty
      printf -v "$var_name" '%s' "${input:-$default}"
    else
      printf -v "$var_name" '%s' "$default"
    fi
  fi
}

GOST_VERSION="3.0.0"

install_gost() {
  if command -v gost >/dev/null 2>&1; then
    echo "[*] gost is already installed, skipping."
    return
  fi
  echo "[*] Installing GOST ${GOST_VERSION} ..."
  local arch gost_arch tmp_dir
  arch="$(uname -m)"
  case "$arch" in
    x86_64) gost_arch="amd64" ;;
    aarch64) gost_arch="arm64" ;;
    *) echo "Unsupported architecture: $arch — install manually" >&2; exit 1 ;;
  esac
  tmp_dir="$(mktemp -d)"
  curl -fsSL -o "$tmp_dir/gost.tar.gz" \
    "https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux_${gost_arch}.tar.gz"
  tar -xzf "$tmp_dir/gost.tar.gz" -C "$tmp_dir"
  install -m 755 "$tmp_dir/gost" /usr/local/bin/gost
  rm -rf "$tmp_dir"
}

setup_role_a() {
  prompt_if_empty PUBLIC_PORT        "Public port (the one sold to the customer)"        "443"
  prompt_if_empty SERVER_B_IP        "Server B (destination) IP"                         "1.2.3.4"
  prompt_if_empty SERVER_B_WSS_PORT  "WSS port on Server B"                               "8443"
  prompt_if_empty TUNNEL_DOMAIN      "Tunnel domain (must match Server B)"                "cdn.example.com"
  prompt_if_empty WS_PATH            "WebSocket path (must match Server B exactly)"       "/$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 12)"

  install_gost

  cat > /etc/systemd/system/tunnel-a.service <<EOF
[Unit]
Description=Tunnel A - entry relay (WSS -> Server B)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L="tcp://:${PUBLIC_PORT}/${SERVER_B_IP}:${SERVER_B_WSS_PORT}?relay=wss&host=${TUNNEL_DOMAIN}&path=${WS_PATH}"
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable tunnel-a.service
  systemctl restart tunnel-a.service

  echo ""
  echo "Server A is ready."
  echo "  Customers connect to port ${PUBLIC_PORT} on this server."
  echo "  WS path: ${WS_PATH}   (make sure Server B uses the exact same value)"
  echo "  Status: systemctl status tunnel-a.service"
}

setup_role_b() {
  prompt_if_empty WSS_LISTEN_PORT "Inbound port from Server A (WSS)"                    "8443"
  prompt_if_empty WS_PATH         "WebSocket path (must match Server A exactly)"        "/CHANGE_ME"
  prompt_if_empty TUNNEL_DOMAIN   "Tunnel domain"                                       "cdn.example.com"
  prompt_if_empty DEST_ADDR       "Final traffic destination (IP:PORT)"                 "127.0.0.1:8080"
  prompt_if_empty USE_LETSENCRYPT "Get a Let's Encrypt certificate? (needs a real domain) yes/no" "no"

  install_gost

  mkdir -p /etc/tunnel-certs

  if [[ "$USE_LETSENCRYPT" == "yes" ]]; then
    echo "[*] Requesting Let's Encrypt certificate for ${TUNNEL_DOMAIN} ..."
    if ! command -v certbot >/dev/null 2>&1; then
      apt-get update -y && apt-get install -y certbot
    fi
    certbot certonly --standalone -d "${TUNNEL_DOMAIN}" --non-interactive --agree-tos -m admin@"${TUNNEL_DOMAIN}"
    CERT_FILE="/etc/letsencrypt/live/${TUNNEL_DOMAIN}/fullchain.pem"
    KEY_FILE="/etc/letsencrypt/live/${TUNNEL_DOMAIN}/privkey.pem"
  else
    echo "[*] Generating self-signed certificate ..."
    CERT_FILE="/etc/tunnel-certs/cert.pem"
    KEY_FILE="/etc/tunnel-certs/key.pem"
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$KEY_FILE" -out "$CERT_FILE" \
      -days 3650 -subj "/CN=${TUNNEL_DOMAIN}"
  fi

  cat > /etc/systemd/system/tunnel-b.service <<EOF
[Unit]
Description=Tunnel B - exit relay (WSS -> real destination)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost \\
  -L="relay+wss://:${WSS_LISTEN_PORT}?path=${WS_PATH}&certFile=${CERT_FILE}&keyFile=${KEY_FILE}" \\
  -F="${DEST_ADDR}"
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable tunnel-b.service
  systemctl restart tunnel-b.service

  echo ""
  echo "Server B is ready."
  echo "  Listening on port ${WSS_LISTEN_PORT} (WSS) -> forwarding to ${DEST_ADDR}"
  echo "  Status: systemctl status tunnel-b.service"
}

if [[ "$ROLE" == "A" ]]; then
  setup_role_a
else
  setup_role_b
fi
