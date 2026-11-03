#!/usr/bin/env bash
# ==============================================================================
#  AmneziaWG + udp2raw (FakeTCP) Anti-Filter Tunnel v6.0 (BackPack Inspired)
#  - Self-Healing Watchdog (Auto-recovers frozen DPI sessions under 45s)
#  - Heavy Kernel, Conntrack & Socket Buffer Tuning (Anti-NAT Exhaustion)
#  - Advanced udp2raw flags (--fix-gro, --keep-rule, anti-RST protection)
#  - Dual-mode Port Forwarding (All Ports vs Specific Ports)
# ==============================================================================

set -uo pipefail

IFACE="awg0"
CFG_DIR="/etc/amnezia/amneziawg"
CFG="${CFG_DIR}/${IFACE}.conf"
META="${CFG_DIR}/${IFACE}.meta"
IR_ADDR="10.0.0.2"
FR_ADDR="10.0.0.1"
CIDR="30"
LOCAL_UDP_PORT="51820"
KEEP_TCP_PORTS="22,80,443,10052"

# ---------- رنگ‌ها و خروجی ----------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
  CYAN=$(tput setaf 6); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
  RED=$(tput setaf 1); BOLD=$(tput bold); RESET=$(tput sgr0)
else
  CYAN=""; YELLOW=""; GREEN=""; RED=""; BOLD=""; RESET=""
fi
info()  { echo "${CYAN}[*]${RESET} $*"; }
ok()    { echo "${GREEN}[+]${RESET} $*"; }
warn()  { echo "${YELLOW}[!]${RESET} $*"; }
err()   { echo "${RED}[x]${RESET} $*" >&2; }
die()   { err "$*"; exit 1; }

banner() {
  clear
  echo "${CYAN}${BOLD}"
  echo "=========================================================="
  echo "   AmneziaWG + udp2raw (FakeTCP) Tunnel v6.0"
  echo "   Self-Healing Watchdog | Conntrack Tuned | Anti-DPI"
  echo "=========================================================="
  echo "${RESET}"
}

[[ $EUID -eq 0 ]] || die "Please run this script as root (sudo -i)."

# ---------- توابع کمکی ----------
rnd() {
  local min=$1 max=$2 span=$(( $2 - $1 + 1 ))
  echo $(( min + ( $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % span ) ))
}

gen_pass() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

main_iface() {
  ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}'
}

pub_ip() { curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true; }

# ---------- نصب پیش‌نیازها ----------
detect_os() {
  . /etc/os-release 2>/dev/null || true
  OS_ID="${ID:-unknown}"
}

install_tools() {
  detect_os
  info "Installing system prerequisites & kernel headers..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl wget git iptables iproute2 openresolv tar conntrack \
      software-properties-common ca-certificates build-essential \
      "linux-headers-$(uname -r)" >/dev/null 2>&1 || \
  apt-get install -y -qq curl wget git iptables iproute2 tar conntrack \
      software-properties-common ca-certificates build-essential >/dev/null 2>&1

  if [[ "$OS_ID" == "ubuntu" ]]; then
    add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
    apt-get update -qq
    apt-get install -y -qq amneziawg amneziawg-tools >/dev/null 2>&1 || true
  fi

  if ! command -v awg >/dev/null 2>&1; then
    warn "Building amneziawg-tools from source..."
    rm -rf /tmp/awg-tools
    git clone -q --depth 1 https://github.com/amnezia-vpn/amneziawg-tools /tmp/awg-tools \
      || die "Cannot fetch amneziawg-tools."
    make -s -C /tmp/awg-tools/src -j"$(nproc)" >/dev/null \
      && make -s -C /tmp/awg-tools/src install >/dev/null \
      || die "Build of amneziawg-tools failed."
  fi
  ok "amneziawg-tools is ready."
}

install_udp2raw() {
  if command -v udp2raw >/dev/null 2>&1; then
    ok "udp2raw is already installed."
    return 0
  fi
  info "Downloading and installing udp2raw..."
  mkdir -p /tmp/udp2raw
  wget -q --tries=3 --timeout=15 https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz -O /tmp/udp2raw/udp2raw.tar.gz \
    || die "Failed to download udp2raw."
  tar -xzf /tmp/udp2raw/udp2raw.tar.gz -C /tmp/udp2raw
  cp /tmp/udp2raw/udp2raw_amd64 /usr/local/bin/udp2raw
  chmod +x /usr/local/bin/udp2raw
  rm -rf /tmp/udp2raw
  ok "udp2raw installed successfully."
}

kernel_ok() {
  modprobe amneziawg >/dev/null 2>&1
  ip link add dev awgtest type amneziawg >/dev/null 2>&1 || return 1
  ip link del awgtest >/dev/null 2>&1
  return 0
}

install_userspace() {
  command -v amneziawg-go >/dev/null 2>&1 && { ok "amneziawg-go already installed."; return 0; }
  warn "Kernel module unavailable. Building amneziawg-go userspace..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq golang-go >/dev/null 2>&1 || apt-get install -y -qq golang >/dev/null 2>&1
  command -v go >/dev/null 2>&1 || die "Go toolchain not available."
  rm -rf /tmp/awg-go
  git clone -q --depth 1 https://github.com/amnezia-vpn/amneziawg-go /tmp/awg-go \
    || die "Cannot fetch amneziawg-go."
  ( cd /tmp/awg-go && go build -o /usr/local/bin/amneziawg-go . ) >/dev/null 2>&1 \
    || die "Build of amneziawg-go failed."
  chmod +x /usr/local/bin/amneziawg-go
  [[ -e /dev/net/tun ]] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200 2>/dev/null; chmod 600 /dev/net/tun; }
  ok "amneziawg-go installed."
}

setup_backend() {
  if kernel_ok; then
    ok "Kernel module 'amneziawg' is active."
    echo "amneziawg" > /etc/modules-load.d/amneziawg.conf
    USERSPACE=0
  else
    install_userspace
    USERSPACE=1
  fi
  mkdir -p /etc/default
  if [[ $USERSPACE -eq 1 ]]; then
    cat > /etc/default/amneziawg <<'EOF'
WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
AWG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
WG_SUDO=1
EOF
  else
    : > /etc/default/amneziawg
  fi
}

# ---------- تیونینگ پیشرفته کرنل و Conntrack (مشابه BackPack) ----------
sysctl_tuning() {
  info "Applying heavy kernel, BBR, socket buffer & nf_conntrack optimizations..."
  modprobe nf_conntrack >/dev/null 2>&1 || true

  cat > /etc/sysctl.d/99-awg-optimizer.conf <<'EOF'
# IP Forwarding & RP Filter
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# BBR & Queue Discipline
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Socket & Network Buffers (High Throughput)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65536
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# TCP FastOpen, Keepalive & MTU Probing
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535

# Conntrack Tuning (Prevents NAT Table Full on Iran Server)
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 120

# File Descriptors Limit
fs.file-max = 2097152
EOF

  sysctl -q --system >/dev/null 2>&1 || true

  # افزایش ظرفیت جدول Hash در ماژول conntrack
  if [[ -f /sys/module/nf_conntrack/parameters/hashsize ]]; then
    echo 262144 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
  fi

  # افزایش محدودیت فایل‌های باز سیستم
  cat > /etc/security/limits.d/99-awg.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
  ok "Kernel & Conntrack optimizations applied."
}

# ---------- پروفایل مبهم‌سازی و توکن ----------
gen_profile() {
  JC=$(rnd 3 6)
  JMIN=$(rnd 40 80)
  JMAX=$(rnd $((JMIN + 50)) 500)
  S1=$(rnd 20 110)
  S2=$(rnd 20 110)
  while [[ $((S1 + 56)) -eq $S2 ]]; do S2=$(rnd 20 110); done
  S3=$(rnd 10 45)
  S4=$(rnd 10 25)
  H1=$(rnd 100000 2147483000); H2=$(rnd 100000 2147483000)
  H3=$(rnd 100000 2147483000); H4=$(rnd 100000 2147483000)
  while [[ "$H2" == "$H1" ]]; do H2=$(rnd 100000 2147483000); done
  while [[ "$H3" == "$H1" || "$H3" == "$H2" ]]; do H3=$(rnd 100000 2147483000); done
  while [[ "$H4" == "$H1" || "$H4" == "$H2" || "$H4" == "$H3" ]]; do H4=$(rnd 100000 2147483000); done
}

encode_token() {
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "v6.0" "$FOREIGN_IP" "$AWG_PORT" "$RAW_PORT" "$RAW_PASS" "$FR_PUB" "$PSK" \
    "$JC" "$JMIN" "$JMAX" "$S1" "$S2" "$S3" "$S4" "$H1" "$H2" "$H3" "$H4" \
    | base64 -w0
}

decode_token() {
  local raw; raw=$(echo "$1" | tr -d ' \n\r' | base64 -d 2>/dev/null) || die "Invalid token."
  IFS='|' read -r V FOREIGN_IP AWG_PORT RAW_PORT RAW_PASS FR_PUB PSK JC JMIN JMAX S1 S2 S3 S4 H1 H2 H3 H4 <<< "$raw"
  [[ "$V" == "v6.0" || "$V" == "v5.0" ]] || die "Token version mismatch (Expected v6.0)."
  [[ -n "$FR_PUB" && -n "$RAW_PORT" && -n "$RAW_PASS" ]] || die "Token is incomplete."
}

# ---------- سرویس‌های پیشرفته udp2raw ----------
setup_udp2raw_foreign() {
  cat > /etc/systemd/system/udp2raw.service <<EOF
[Unit]
Description=udp2raw FakeTCP Server (Foreign)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
LimitNOFILE=1048576
ExecStart=/usr/local/bin/udp2raw -s -l 0.0.0.0:${RAW_PORT} -r 127.0.0.1:${AWG_PORT} -k "${RAW_PASS}" --raw-mode faketcp -a --keep-rule --fix-gro --cipher-mode aes128cbc --auth-mode hmac_sha1 --seq-mode 4
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now udp2raw.service >/dev/null 2>&1
  ok "udp2raw FakeTCP Server active on TCP port ${RAW_PORT} (--fix-gro & --keep-rule enabled)."
}

setup_udp2raw_iran() {
  cat > /etc/systemd/system/udp2raw.service <<EOF
[Unit]
Description=udp2raw FakeTCP Client (Iran)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
LimitNOFILE=1048576
ExecStart=/usr/local/bin/udp2raw -c -l 127.0.0.1:${LOCAL_UDP_PORT} -r ${FOREIGN_IP}:${RAW_PORT} -k "${RAW_PASS}" --raw-mode faketcp -a --keep-rule --fix-gro --cipher-mode aes128cbc --auth-mode hmac_sha1 --seq-mode 4
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now udp2raw.service >/dev/null 2>&1
  sleep 2
  ok "udp2raw FakeTCP Client active on 127.0.0.1:${LOCAL_UDP_PORT} -> ${FOREIGN_IP}:${RAW_PORT}."
}

# ---------- واچ‌داگ خودترمیم (Self-Healing Watchdog) ----------
setup_watchdog() {
  info "Setting up Self-Healing Watchdog & Periodic Session Refresh..."
  cat > /usr/local/bin/awg-watchdog.sh <<EOF
#!/usr/bin/env bash
# Checks tunnel health; restarts udp2raw or awg0 if DPI freezes the TCP session.

TARGET_IP="${FR_ADDR}"
IFACE="${IFACE}"

# مرحله ۱: تست پینگ داخل تانل
if ping -c 3 -W 2 "\$TARGET_IP" >/dev/null 2>&1; then
  exit 0
fi

logger -t awg-watchdog "Ping to \$TARGET_IP failed! Step 1: Restarting udp2raw to rotate FakeTCP session..."
systemctl restart udp2raw.service
sleep 6

# مرحله ۲: تست مجدد بعد از ری‌استارت udp2raw
if ping -c 3 -W 2 "\$TARGET_IP" >/dev/null 2>&1; then
  logger -t awg-watchdog "Tunnel recovered after udp2raw restart."
  exit 0
fi

# مرحله ۳: ری‌استارت کامل اینترفیس AmneziaWG در صورت عدم رفع مشکل
logger -t awg-watchdog "Still down! Step 2: Restarting awg-quick@\$IFACE..."
systemctl restart "awg-quick@\${IFACE}.service"
EOF
  chmod +x /usr/local/bin/awg-watchdog.sh

  cat > /etc/systemd/system/awg-watchdog.service <<'EOF'
[Unit]
Description=AmneziaWG Self-Healing Watchdog Check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/awg-watchdog.sh
EOF

  cat > /etc/systemd/system/awg-watchdog.timer <<'EOF'
[Unit]
Description=Run AmneziaWG Watchdog every 45 seconds

[Timer]
OnBootSec=60
OnUnitActiveSec=45
AccuracySec=5

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now awg-watchdog.timer >/dev/null 2>&1
  ok "Self-Healing Watchdog enabled (checks tunnel every 45 seconds)."
}

# ---------- ساخت فایل کانفیگ AmneziaWG ----------
common_iface_block() {
  cat <<EOF
[Interface]
PrivateKey = ${PRIV}
Address = ${SELF_ADDR}/${CIDR}
ListenPort = ${LISTEN_PORT}
MTU = ${MTU}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
S3 = ${S3}
S4 = ${S4}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
EOF
}

write_iran_cfg() {
  local NIC=$1
  mkdir -p "$CFG_DIR"; chmod 700 "$CFG_DIR"
  LISTEN_PORT=$(rnd 30000 50000)

  local DNAT_RULES=""
  if [[ "$FWD_MODE" == "2" ]]; then
    DNAT_RULES="PostUp = iptables -t nat -A AWG_DNAT -p tcp -m multiport --dports ${CUSTOM_PORTS} -j DNAT --to-destination ${FR_ADDR}
PostUp = iptables -t nat -A AWG_DNAT -p udp -m multiport --dports ${CUSTOM_PORTS} -j DNAT --to-destination ${FR_ADDR}"
  else
    DNAT_RULES="PostUp = iptables -t nat -A AWG_DNAT -p tcp -m multiport ! --dports ${KEEP_TCP_PORTS} -j DNAT --to-destination ${FR_ADDR}
PostUp = iptables -t nat -A AWG_DNAT -p udp -m multiport ! --dports ${LOCAL_UDP_PORT},53 -j DNAT --to-destination ${FR_ADDR}"
  fi

  { common_iface_block
    cat <<EOF
PostUp = sysctl -qw net.ipv4.ip_forward=1
PostUp = iptables -t nat -N AWG_DNAT 2>/dev/null || true
PostUp = iptables -t nat -F AWG_DNAT

# حفاظت کامل از ارتباط سرور ایران با اینترنت، سرور خارج و DNS
PostUp = iptables -t nat -A AWG_DNAT -s ${FOREIGN_IP} -j RETURN
PostUp = iptables -t nat -A AWG_DNAT -d ${FOREIGN_IP} -j RETURN
PostUp = iptables -t nat -A AWG_DNAT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
PostUp = iptables -t nat -A AWG_DNAT -p udp --sport 53 -j RETURN
PostUp = iptables -t nat -A AWG_DNAT -p tcp --sport 53 -j RETURN

# اعمال قوانین فوروارد پورت
PostUp = iptables -t nat -C PREROUTING -i ${NIC} -j AWG_DNAT 2>/dev/null || iptables -t nat -I PREROUTING 1 -i ${NIC} -j AWG_DNAT
${DNAT_RULES}

# تنظیمات NAT و MSS Clamping دوطرفه
PostUp = iptables -t nat -C POSTROUTING -o %i -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %i -j MASQUERADE
PostUp = iptables -C FORWARD -i ${NIC} -o %i -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i ${NIC} -o %i -j ACCEPT
PostUp = iptables -C FORWARD -i %i -o ${NIC} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i %i -o ${NIC} -j ACCEPT
PostUp = iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = iptables -t mangle -C POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

PostDown = iptables -t nat -D PREROUTING -i ${NIC} -j AWG_DNAT 2>/dev/null || true
PostDown = iptables -t nat -F AWG_DNAT 2>/dev/null || true
PostDown = iptables -t nat -X AWG_DNAT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${NIC} -o %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i %i -o ${NIC} -j ACCEPT 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
PostDown = iptables -t mangle -D POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = ${FR_PUB}
PresharedKey = ${PSK}
AllowedIPs = ${FR_ADDR}/32
Endpoint = 127.0.0.1:${LOCAL_UDP_PORT}
PersistentKeepalive = 15
EOF
  } > "$CFG"
  chmod 600 "$CFG"
}

write_foreign_cfg() {
  local NIC=$1
  mkdir -p "$CFG_DIR"; chmod 700 "$CFG_DIR"
  LISTEN_PORT="$AWG_PORT"
  { common_iface_block
    cat <<EOF
PostUp = sysctl -qw net.ipv4.ip_forward=1
PostUp = iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i %i -j ACCEPT
PostUp = iptables -C FORWARD -o %i -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o %i -j ACCEPT
PostUp = iptables -t nat -C POSTROUTING -s ${IR_ADDR}/32 -o ${NIC} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${IR_ADDR}/32 -o ${NIC} -j MASQUERADE
PostUp = iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = iptables -t mangle -C POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -s ${IR_ADDR}/32 -o ${NIC} -j MASQUERADE 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
PostDown = iptables -t mangle -D POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
EOF
    if [[ -n "${IR_PUB:-}" ]]; then
      cat <<EOF

[Peer]
PublicKey = ${IR_PUB}
PresharedKey = ${PSK}
AllowedIPs = ${IR_ADDR}/32
PersistentKeepalive = 15
EOF
    fi
  } > "$CFG"
  chmod 600 "$CFG"
}

bring_up() {
  set -a; . /etc/default/amneziawg 2>/dev/null || true; set +a
  awg-quick down "$IFACE" >/dev/null 2>&1 || true
  ip link del "$IFACE" >/dev/null 2>&1 || true
  awg-quick up "$IFACE" || die "awg-quick failed to start ${IFACE}."
  if [[ -f /usr/lib/systemd/system/awg-quick@.service || -f /lib/systemd/system/awg-quick@.service ]]; then
    mkdir -p "/etc/systemd/system/awg-quick@${IFACE}.service.d"
    cat > "/etc/systemd/system/awg-quick@${IFACE}.service.d/override.conf" <<'EOF'
[Service]
EnvironmentFile=-/etc/default/amneziawg
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
EOF
    systemctl daemon-reload
    systemctl enable "awg-quick@${IFACE}" >/dev/null 2>&1 && ok "AmneziaWG service enabled on boot."
  fi
  ok "Interface ${IFACE} is up."
}

wait_handshake() {
  info "Waiting for handshake over FakeTCP (up to 25s)..."
  for _ in $(seq 1 25); do
    if awg show "$IFACE" latest-handshakes 2>/dev/null | awk '{if ($2+0 > 0) found=1} END{exit !found}'; then
      ok "Handshake established successfully over FakeTCP!"
      return 0
    fi
    sleep 1
  done
  warn "No handshake yet. Ensure Option 3 was run on Foreign server and TCP port ${RAW_PORT} is open."
  return 1
}

# ============================ منوی اصلی ============================
banner
cat <<EOF
Select an option:
  1 - IRAN server      (Run AFTER configuring Foreign server)
  2 - FOREIGN server   (Run FIRST)
  3 - FOREIGN: Add / Update Iran peer public key
  4 - Health Check & Diagnostics
  5 - Uninstall & Clean up
EOF
read -rp "Enter your choice: " CHOICE

case "$CHOICE" in
2)
  install_tools; install_udp2raw; setup_backend; sysctl_tuning
  NIC=$(main_iface); [[ -n "$NIC" ]] || die "Cannot detect default network interface."
  FOREIGN_IP=$(pub_ip)
  read -rp "Enter FOREIGN server public IP [${FOREIGN_IP:-none}]: " in_ip
  FOREIGN_IP=${in_ip:-$FOREIGN_IP}
  [[ -n "$FOREIGN_IP" ]] || die "Foreign IP is required."

  read -rp "FakeTCP listen port on Foreign server (must be free) [443]: " RAW_PORT
  RAW_PORT=${RAW_PORT:-443}
  AWG_PORT=$(rnd 25000 55000)
  RAW_PASS=$(gen_pass)
  MTU=1240

  gen_profile
  PRIV=$(awg genkey); FR_PUB=$(echo "$PRIV" | awg pubkey); PSK=$(awg genpsk)
  SELF_ADDR="$FR_ADDR"; IR_PUB=""

  setup_udp2raw_foreign
  write_foreign_cfg "$NIC"
  {
    echo "ROLE=foreign"; echo "NIC=${NIC}"; echo "AWG_PORT=${AWG_PORT}"
    echo "RAW_PORT=${RAW_PORT}"; echo "RAW_PASS=${RAW_PASS}"; echo "MTU=${MTU}"
    echo "PSK=${PSK}"
    echo "TOKEN=$(encode_token)"
  } > "$META"; chmod 600 "$META"
  bring_up

  echo
  ok "Foreign server configured (v6.0 FakeTCP on port ${RAW_PORT})."
  echo "${YELLOW}${BOLD}Copy this token and paste it on the IRAN server (Option 1):${RESET}"
  echo "${CYAN}$(encode_token)${RESET}"
  echo
  ;;

1)
  install_tools; install_udp2raw; setup_backend; sysctl_tuning
  NIC=$(main_iface); [[ -n "$NIC" ]] || die "Cannot detect default network interface."
  echo "Paste the token generated by the FOREIGN server:"
  read -rp "> " TOKEN
  decode_token "$TOKEN"
  MTU=1240

  echo ""
  echo "${CYAN}Select Port Forwarding Mode:${RESET}"
  echo "  1 - Forward ALL ports except management ports (Default)"
  echo "  2 - Forward ONLY specific ports (Recommended for lower sensitivity)"
  read -rp "Enter 1 or 2 [1]: " FWD_MODE
  FWD_MODE=${FWD_MODE:-1}

  CUSTOM_PORTS=""
  if [[ "$FWD_MODE" == "2" ]]; then
    read -rp "Enter comma-separated ports to forward (e.g., 2053,2083,8443,443): " CUSTOM_PORTS
    CUSTOM_PORTS=$(echo "$CUSTOM_PORTS" | tr ' ' ',')
    [[ -n "$CUSTOM_PORTS" ]] || die "Port list cannot be empty."
  else
    read -rp "TCP ports to KEEP on Iran server [${KEEP_TCP_PORTS}]: " kp
    KEEP_TCP_PORTS=${kp:-$KEEP_TCP_PORTS}
  fi

  PRIV=$(awg genkey); IR_PUB=$(echo "$PRIV" | awg pubkey)
  SELF_ADDR="$IR_ADDR"

  setup_udp2raw_iran
  write_iran_cfg "$NIC"
  {
    echo "ROLE=iran"; echo "NIC=${NIC}"; echo "RAW_PORT=${RAW_PORT}"
    echo "FOREIGN_IP=${FOREIGN_IP}"; echo "MTU=${MTU}"; echo "FWD_MODE=${FWD_MODE}"
  } > "$META"; chmod 600 "$META"
  bring_up
  setup_watchdog

  echo
  ok "Iran server configured with Self-Healing Watchdog!"
  echo "${YELLOW}${BOLD}Copy this Iran Public Key and paste it on the FOREIGN server (Option 3):${RESET}"
  echo "${CYAN}${IR_PUB}${RESET}"
  echo
  ;;

3)
  [[ -f "$CFG" ]] || die "No config at ${CFG}. Run Option 2 first."
  read -rp "Enter IRAN server public key: " IR_PUB
  [[ -n "$IR_PUB" ]] || die "Key is required."
  PSK_LINE=$(sed -n 's/^PSK=//p' "$META" 2>/dev/null | head -n1)
  [[ -n "$PSK_LINE" ]] || PSK_LINE=$(awk '/^PresharedKey/{print $3; exit}' "$CFG")
  [[ -n "$PSK_LINE" ]] || die "Could not recover PresharedKey."

  awk '/^\[Peer\]/{exit} {print}' "$CFG" > "${CFG}.new"
  cat >> "${CFG}.new" <<EOF

[Peer]
PublicKey = ${IR_PUB}
PresharedKey = ${PSK_LINE}
AllowedIPs = ${IR_ADDR}/32
PersistentKeepalive = 15
EOF
  mv "${CFG}.new" "$CFG"; chmod 600 "$CFG"
  set -a; . /etc/default/amneziawg 2>/dev/null || true; set +a
  awg-quick down "$IFACE" >/dev/null 2>&1 || true
  awg-quick up "$IFACE" || die "Restart failed."
  systemctl restart udp2raw.service >/dev/null 2>&1 || true
  ok "Iran peer added! Verifying connection..."
  wait_handshake || true
  ;;

4)
  echo "${CYAN}${BOLD}=== 1. AmneziaWG Interface Status ===${RESET}"
  awg show "$IFACE" 2>/dev/null || warn "AmneziaWG is not running."
  echo ""
  echo "${CYAN}${BOLD}=== 2. udp2raw FakeTCP Status ===${RESET}"
  systemctl is-active --quiet udp2raw.service && ok "udp2raw service is ACTIVE." || err "udp2raw service is DOWN!"
  echo ""
  echo "${CYAN}${BOLD}=== 3. Watchdog Timer Status ===${RESET}"
  systemctl is-active --quiet awg-watchdog.timer && ok "Self-Healing Watchdog is ACTIVE." || warn "Watchdog not active (Normal on Foreign server)."
  echo ""
  echo "${CYAN}${BOLD}=== 4. Conntrack Usage (NAT Table) ===${RESET}"
  CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "N/A")
  CT_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "N/A")
  echo "Active Connections: ${CT_COUNT} / Max Allowed: ${CT_MAX}"
  echo ""
  echo "${CYAN}${BOLD}=== 5. Tunnel Ping & Latency Test ===${RESET}"
  ping -c 4 -W 2 10.0.0.1 2>/dev/null || ping -c 4 -W 2 10.0.0.2 2>/dev/null || err "Tunnel Ping Failed!"
  ;;

5)
  systemctl disable --now awg-watchdog.timer awg-watchdog.service >/dev/null 2>&1 || true
  systemctl disable --now "awg-quick@${IFACE}" >/dev/null 2>&1 || true
  systemctl disable --now udp2raw.service >/dev/null 2>&1 || true
  awg-quick down "$IFACE" >/dev/null 2>&1 || true
  rm -rf "$CFG_DIR" /etc/sysctl.d/99-awg-optimizer.conf /etc/modules-load.d/amneziawg.conf \
         /etc/systemd/system/udp2raw.service /etc/systemd/system/awg-watchdog.service \
         /etc/systemd/system/awg-watchdog.timer /usr/local/bin/awg-watchdog.sh \
         /etc/security/limits.d/99-awg.conf
  systemctl daemon-reload
  ok "Uninstalled and cleaned up all services, rules, and configs."
  ;;
*)
  die "Invalid choice."
  ;;
esac
