#!/bin/bash
# ==============================================================================
# AmneziaWG + udp2raw (FakeTCP) - v7.0 TRUE REVERSE TUNNEL EDITION
# Designed for High-Volume (1-4 TB/day) - Anti Iran-Access Architecture
# Direction: Foreign Server (Client/Dialer) ===> Iran Server (Server/Listener)
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo)."
  exit 1
fi

CONFIG_DIR="/etc/amnezia/amneziawg"
CONF_FILE="$CONFIG_DIR/awg0.conf"
UDP2RAW_BIN="/usr/local/bin/udp2raw"
SECRET_FILE="$CONFIG_DIR/reverse_secret.key"

# Shared Junk Parameters for AmneziaWG
JC=4; JMIN=50; JMAX=100; S1=86; S2=54; S3=28; S4=12
H1=919699952; H2=135319215; H3=263726462; H4=912570109

# Default User Ports from your panel
DEFAULT_PORTS="2053,2829,2020,2021,2022,2023,2024,54134,1080,2086,50320,50321,222,2525,2028"

tune_kernel() {
    echo "[*] Applying High-Throughput Kernel & Conntrack Tuning..."
    cat <<EOF > /etc/sysctl.d/99-awg-reverse.conf
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
EOF
    sysctl --system >/dev/null 2>&1 || true
}

install_dependencies() {
    echo "[*] Checking dependencies..."
    if ! command -v awg >/dev/null 2>&1; then
        apt-get update && apt-get install -y software-properties-common curl wget iptables net-tools psmisc
        add-apt-repository -y ppa:amnezia/ppa
        apt-get update && apt-get install -y amneziawg amneziawg-tools
    fi

    if [ ! -f "$UDP2RAW_BIN" ]; then
        echo "[*] Downloading udp2raw..."
        wget -qO /tmp/udp2raw.tar.gz https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz
        tar -xzf /tmp/udp2raw.tar.gz -C /tmp
        mv /tmp/udp2raw_amd64 "$UDP2RAW_BIN"
        chmod +x "$UDP2RAW_BIN"
        rm -f /tmp/udp2raw*
    fi
    mkdir -p "$CONFIG_DIR"
}

cleanup_all() {
    echo "[*] Cleaning up previous services and rules..."
    systemctl stop awg-watchdog.timer awg-watchdog.service 2>/dev/null || true
    systemctl disable awg-watchdog.timer awg-watchdog.service 2>/dev/null || true
    rm -f /etc/systemd/system/awg-watchdog.* /usr/local/bin/awg-watchdog.sh

    systemctl stop awg-quick@awg0 2>/dev/null || true
    systemctl disable awg-quick@awg0 2>/dev/null || true
    ip link del awg0 2>/dev/null || true

    systemctl stop udp2raw.service 2>/dev/null || true
    systemctl disable udp2raw.service 2>/dev/null || true
    killall -9 udp2raw 2>/dev/null || true

    iptables -t nat -F AWG_DNAT 2>/dev/null || true
    systemctl daemon-reload
}

setup_iran_listener() {
    cleanup_all
    install_dependencies
    tune_kernel

    echo ""
    echo "=== IRAN SERVER SETUP (PASSIVE REVERSE LISTENER) ==="
    read -p "Enter FakeTCP Listening Port on Iran [Default: 443]: " FAKETCP_PORT
    FAKETCP_PORT=${FAKETCP_PORT:-443}

    read -p "Enter Ports to Forward [Press Enter for your 15 Panel Ports]: " FORWARD_PORTS
    FORWARD_PORTS=${FORWARD_PORTS:-$DEFAULT_PORTS}

    # Check if FakeTCP port is busy
    if netstat -tunlp | grep -q ":$FAKETCP_PORT "; then
        echo "[!] Warning: Port $FAKETCP_PORT is currently in use! Attempting to free it..."
        fuser -k "${FAKETCP_PORT}/tcp" 2>/dev/null || true
        sleep 1
    fi

    # Generate Keys
    umask 077
    awg genkey | tee "$CONFIG_DIR/privatekey" | awg pubkey > "$CONFIG_DIR/publickey"
    awg genpsk > "$CONFIG_DIR/psk"
    IRAN_PRIV=$(cat "$CONFIG_DIR/privatekey")
    IRAN_PUB=$(cat "$CONFIG_DIR/publickey")
    PSK=$(cat "$CONFIG_DIR/psk")
    UDP2RAW_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
    echo "$UDP2RAW_PASS" > "$SECRET_FILE"
    echo "$FAKETCP_PORT" > "$CONFIG_DIR/faketcp_port"
    echo "$FORWARD_PORTS" > "$CONFIG_DIR/forward_ports"

    # Setup udp2raw SERVER on Iran
    cat <<EOF > /etc/systemd/system/udp2raw.service
[Unit]
Description=udp2raw FakeTCP Server (Iran Reverse Listener)
After=network.target

[Service]
Type=simple
User=root
ExecStart=$UDP2RAW_BIN -s -l 0.0.0.0:$FAKETCP_PORT -r 127.0.0.1:34443 -k $UDP2RAW_PASS --raw-mode faketcp -a --keep-rule --fix-gro --cipher-mode aes128cbc --auth-mode hmac_sha1 --seq-mode 4
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now udp2raw.service

    echo ""
    echo "=================================================================="
    echo "[+] Iran Server is now waiting in PASSIVE mode on TCP Port $FAKETCP_PORT"
    echo "[!] Run Option 2 on FOREIGN Server and give it these details:"
    echo "------------------------------------------------------------------"
    echo "1. Iran Public Key : $IRAN_PUB"
    echo "2. Preshared Key   : $PSK"
    echo "3. udp2raw Password: $UDP2RAW_PASS"
    echo "4. Iran FakeTCP Port: $FAKETCP_PORT"
    echo "=================================================================="
}

setup_foreign_dialer() {
    cleanup_all
    install_dependencies
    tune_kernel

    echo ""
    echo "=== FOREIGN SERVER SETUP (ACTIVE REVERSE DIALER) ==="
    read -p "Enter IRAN Server IP Address: " IRAN_IP
    read -p "Enter IRAN FakeTCP Port [Default: 443]: " FAKETCP_PORT
    FAKETCP_PORT=${FAKETCP_PORT:-443}
    read -p "Paste IRAN Public Key: " IRAN_PUB
    read -p "Paste Preshared Key (PSK): " PSK
    read -p "Paste udp2raw Password: " UDP2RAW_PASS

    umask 077
    awg genkey | tee "$CONFIG_DIR/privatekey" | awg pubkey > "$CONFIG_DIR/publickey"
    FOREIGN_PRIV=$(cat "$CONFIG_DIR/privatekey")
    FOREIGN_PUB=$(cat "$CONFIG_DIR/publickey")

    # Setup udp2raw CLIENT on Foreign (Dials Iran!)
    cat <<EOF > /etc/systemd/system/udp2raw.service
[Unit]
Description=udp2raw FakeTCP Client (Foreign Reverse Dialer)
After=network.target

[Service]
Type=simple
User=root
ExecStart=$UDP2RAW_BIN -c -l 127.0.0.1:51820 -r ${IRAN_IP}:${FAKETCP_PORT} -k $UDP2RAW_PASS --raw-mode faketcp -a --keep-rule --fix-gro --cipher-mode aes128cbc --auth-mode hmac_sha1 --seq-mode 4
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now udp2raw.service

    # Setup AmneziaWG on Foreign (Initiates handshake to local udp2raw -> Iran)
    cat <<EOF > "$CONF_FILE"
[Interface]
PrivateKey = $FOREIGN_PRIV
Address = 10.0.0.1/30
MTU = 1240
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
S3 = $S3
S4 = $S4
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4

PostUp = iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

[Peer]
PublicKey = $IRAN_PUB
PresharedKey = $PSK
Endpoint = 127.0.0.1:51820
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 10
EOF

    systemctl enable --now awg-quick@awg0

    # Setup Watchdog on FOREIGN Server (keeps reverse tunnel alive from outside)
    cat <<'EOF' > /usr/local/bin/awg-watchdog.sh
#!/bin/bash
if ! ping -c 3 -W 2 10.0.0.2 >/dev/null 2>&1; then
    systemctl restart udp2raw.service
    sleep 2
    systemctl restart awg-quick@awg0
fi
EOF
    chmod +x /usr/local/bin/awg-watchdog.sh

    cat <<EOF > /etc/systemd/system/awg-watchdog.service
[Unit]
Description=Reverse Tunnel Watchdog (Foreign Side)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/awg-watchdog.sh
EOF

    cat <<EOF > /etc/systemd/system/awg-watchdog.timer
[Unit]
Description=Run Reverse Watchdog every 45s
[Timer]
OnBootSec=45s
OnUnitActiveSec=45s
[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now awg-watchdog.timer

    echo ""
    echo "=================================================================="
    echo "[+] Foreign Server Configured & Dialing Iran!"
    echo "[!] Copy this FOREIGN Public Key and run Option 3 on IRAN Server:"
    echo "------------------------------------------------------------------"
    echo "$FOREIGN_PUB"
    echo "=================================================================="
}

finalize_iran_listener() {
    echo ""
    echo "=== FINALIZE IRAN SERVER ==="
    read -p "Paste FOREIGN Public Key: " FOREIGN_PUB

    IRAN_PRIV=$(cat "$CONFIG_DIR/privatekey")
    PSK=$(cat "$CONFIG_DIR/psk")
    FORWARD_PORTS=$(cat "$CONFIG_DIR/forward_ports")
    DEFAULT_IF=$(ip route | grep default | awk '{print $5}' | head -n1)

    cat <<EOF > "$CONF_FILE"
[Interface]
PrivateKey = $IRAN_PRIV
Address = 10.0.0.2/30
ListenPort = 34443
MTU = 1240
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
S3 = $S3
S4 = $S4
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4

PostUp = sysctl -qw net.ipv4.ip_forward=1
PostUp = iptables -t nat -N AWG_DNAT 2>/dev/null || true
PostUp = iptables -t nat -F AWG_DNAT
PostUp = iptables -t nat -A AWG_DNAT -p tcp -m multiport --dports $FORWARD_PORTS -j DNAT --to-destination 10.0.0.1
PostUp = iptables -t nat -A AWG_DNAT -p udp -m multiport --dports $FORWARD_PORTS -j DNAT --to-destination 10.0.0.1
PostUp = iptables -t nat -C PREROUTING -i $DEFAULT_IF -j AWG_DNAT 2>/dev/null || iptables -t nat -I PREROUTING 1 -i $DEFAULT_IF -j AWG_DNAT
PostUp = iptables -t nat -C POSTROUTING -o awg0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o awg0 -j MASQUERADE
PostUp = iptables -I FORWARD 1 -i $DEFAULT_IF -o awg0 -j ACCEPT
PostUp = iptables -I FORWARD 1 -i awg0 -o $DEFAULT_IF -j ACCEPT
PostUp = iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

PostDown = iptables -t nat -F AWG_DNAT 2>/dev/null || true

[Peer]
PublicKey = $FOREIGN_PUB
PresharedKey = $PSK
AllowedIPs = 10.0.0.1/32
EOF

    systemctl enable --now awg-quick@awg0
    echo ""
    echo "[+] IRAN Reverse Listener Finalized!"
    echo "[*] Waiting 5 seconds for Foreign server to handshake..."
    sleep 5
    awg show awg0
    echo ""
    echo "[*] Testing tunnel ping to Foreign (10.0.0.1)..."
    ping -c 4 10.0.0.1 || echo "[!] If ping didn't reply immediately, wait 15s for Foreign Keepalive to hit Iran."
}

echo "==============================================================="
echo "   AmneziaWG + udp2raw v7.0 (TRUE REVERSE TUNNEL ARCHITECTURE) "
echo "==============================================================="
echo " 1) Setup IRAN Server (Step 1 - Passive Listener)"
echo " 2) Setup FOREIGN Server (Step 2 - Active Dialer)"
echo " 3) Finalize IRAN Server (Step 3 - Link Foreign Key & Ports)"
echo " 4) Check Status & Ping"
echo " 5) Uninstall & Clean All"
echo "==============================================================="
read -p "Select option [1-5]: " OPT

case $OPT in
    1) setup_iran_listener ;;
    2) setup_foreign_dialer ;;
    3) finalize_iran_listener ;;
    4) 
       awg show awg0
       systemctl status udp2raw.service --no-pager -l
       ;;
    5) cleanup_all && echo "[+] Cleaned up successfully." ;;
    *) echo "Invalid option" ;;
esac
