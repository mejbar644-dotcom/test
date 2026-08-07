#!/bin/bash

CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
RESET=$(tput sgr0)

echo -e "${CYAN}"
echo "===================================="
echo "          GitHub: Netplas"
echo "   Secure Obfuscated Tunnel Script"
echo "===================================="
echo -e "${RESET}"

# بررسی نصب بودن ابزارهای ضروری
if ! command -v wg &> /dev/null || ! command -v iptables &> /dev/null; then
    echo "[*] Installing WireGuard and iptables..."
    apt-get update && apt-get install -y wireguard iptables wget tar
fi

# نصب خودکار ابزار Gost (نسخه پایدار جدید)
if [ ! -f /usr/local/bin/gost ]; then
    echo "[*] Downloading and installing Gost..."
    wget -q -O /tmp/gost.tar.gz https://github.com/go-gost/gost/releases/download/v3.2.6/gost_3.2.6_linux_amd64.tar.gz
    tar -xzf /tmp/gost.tar.gz -C /tmp/
    # در نسخه جدید ممکن است نام فایل خروجی gost باشد
    if [ -f /tmp/gost ]; then
        mv /tmp/gost /usr/local/bin/
    elif [ -f /tmp/gost_*_linux_amd64/gost ]; then
        mv /tmp/gost_*_linux_amd64/gost /usr/local/bin/
    fi
    chmod +x /usr/local/bin/gost
    rm -rf /tmp/gost.tar.gz /tmp/gost_*
fi

echo "Select an option:"
echo "1 - IRAN Server Configuration"
echo "2 - FOREIGN Server Configuration"
echo "3 - Uninstall & Remove Tunnel & Gost"
read -p "Enter your choice (1, 2 or 3): " LOCATION

if [[ "$LOCATION" == "3" ]]; then
    echo -e "${RED}[*] Uninstalling and cleaning up tunnel and Gost...${RESET}"
    systemctl stop gost-tunnel 2>/dev/null
    rm -f /etc/systemd/system/gost-tunnel.service
    systemctl daemon-reload
    ip link set wg0 down 2>/dev/null
    ip link del wg0 2>/dev/null
    rm -rf /etc/wireguard /usr/local/bin/gost
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    sysctl -w net.ipv4.ip_forward=0
    echo -e "${GREEN}[+] Everything removed successfully!${RESET}"
    exit 0
fi

read -p "Enter IRAN server IP: " IP_IRAN
read -p "Enter FOREIGN server IP: " IP_FOREIGN

read -p "Enter WireGuard Port (Default 51820): " WG_PORT
WG_PORT=${WG_PORT:-51820}

read -p "Enter Obfuscation/TLS Port for Gost (Default 443): " GOST_PORT
GOST_PORT=${GOST_PORT:-443}

MAIN_INTERFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)

# حذف اینترفیس و سرویس قبلی در صورت وجود
ip link del wg0 2>/dev/null
systemctl stop gost-tunnel 2>/dev/null

if [[ "$LOCATION" == "1" ]]; then
    echo -e "${YELLOW}[*] Configuring IRAN server with TLS Obfuscation...${RESET}"

    PrivKey=$(wg genkey)
    PubKey=$(echo "$PrivKey" | wg pubkey)

    echo -e "${YELLOW}[?] Please run the Foreign server script first and copy its Public Key.${RESET}"
    read -p "Enter FOREIGN server Public Key: " FOREIGN_PUBKEY

    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # ساخت اینترفیس وایرگارد
    ip link add dev wg0 type wireguard
    ip address add 10.0.0.2/30 dev wg0 2>/dev/null
    mkdir -p /etc/wireguard
    echo "$PrivKey" > /etc/wireguard/private.key
    
    wg set wg0 listen-port $((WG_PORT + 1)) private-key /etc/wireguard/private.key
    wg set wg0 peer "$FOREIGN_PUBKEY" endpoint "127.0.0.1:$((WG_PORT + 1))" allowed-ips 0.0.0.0/0 persistent-keepalive 25
    ip link set dev wg0 up

    # ساخت سرویس Gost برای ایران
    cat << EOF > /etc/systemd/system/gost-tunnel.service
[Unit]
Description=Gost Tunnel Client for Iran
After=network.target

[Service]
ExecStart=/usr/local/bin/gost -L "udp://127.0.0.1:$((WG_PORT + 1))/127.0.0.1:$((WG_PORT + 1))?net=tcp" -F "relay+tls://$IP_FOREIGN:$GOST_PORT"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable gost-tunnel
    systemctl restart gost-tunnel

    # قوانین فایروال و فوروارد پورت‌ها
    iptables -t nat -F
    iptables -t nat -A PREROUTING -i $MAIN_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.0.0.1
    iptables -t nat -A PREROUTING -i $MAIN_INTERFACE -p udp -j DNAT --to-destination 10.0.0.1
    iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
    iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE

    echo -e "${GREEN}[+] Iran server configured and secured successfully!${RESET}"
    echo "Your Iran Server Public Key: $PubKey"

elif [[ "$LOCATION" == "2" ]]; then
    echo -e "${YELLOW}[*] Configuring FOREIGN server with TLS Obfuscation...${RESET}"

    PrivKey=$(wg genkey)
    PubKey=$(echo "$PrivKey" | wg pubkey)

    echo -e "Your Foreign Server Public Key is: ${CYAN}$PubKey${RESET}"
    read -p "Press Enter after you have saved this key..."

    read -p "Enter IRAN server Public Key: " IRAN_PUBKEY

    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # ساخت اینترفیس وایرگارد سرور خارج
    ip link add dev wg0 type wireguard
    ip address add 10.0.0.1/30 dev wg0 2>/dev/null
    mkdir -p /etc/wireguard
    echo "$PrivKey" > /etc/wireguard/private.key
    
    wg set wg0 listen-port $((WG_PORT + 1)) private-key /etc/wireguard/private.key
    wg set wg0 peer "$IRAN_PUBKEY" endpoint "127.0.0.1:$((WG_PORT + 1))" allowed-ips 0.0.0.0/0 persistent-keepalive 25
    ip link set dev wg0 up

    # ساخت سرویس Gost روی سرور خارج
    cat << EOF > /etc/systemd/system/gost-tunnel.service
[Unit]
Description=Gost Tunnel Server for Foreign
After=network.target

[Service]
ExecStart=/usr/local/bin/gost -L "relay+tls://:$GOST_PORT" -F "udp://127.0.0.1:$((WG_PORT + 1))"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable gost-tunnel
    systemctl restart gost-tunnel

    # باز کردن پورت Gost روی فایروال و تنظیمات MASQUERADE
    iptables -A INPUT -p tcp --dport $GOST_PORT -j ACCEPT
    iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -A FORWARD -o wg0 -j ACCEPT
    iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE

    echo -e "${GREEN}[+] Foreign server configured and secured successfully!${RESET}"

else
    echo -e "${RED}[!] Invalid selection. Please enter 1, 2 or 3.${RESET}"
    exit 1
fi
