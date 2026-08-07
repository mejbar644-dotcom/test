#!/bin/bash

CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)

echo -e "${CYAN}"
echo "===================================="
echo "        GitHub: netplas (Secured)"
echo "    WireGuard Secure Tunnel Script"
echo "===================================="
echo -e "${RESET}"

# بررسی نصب بودن wireguard و iptables
if ! command -v wg &> /dev/null; then
    echo "[*] Installing WireGuard and iptables..."
    apt-get update && apt-get install -y wireguard iptables iproute2
fi

echo "Select server location:"
echo "1 - IRAN"
echo "2 - FOREIGN"
read -p "Enter 1 or 2: " LOCATION

read -p "Enter IRAN server IP: " IP_IRAN
read -p "Enter FOREIGN server IP: " IP_FOREIGN

# استفاده از پورت‌های تصادفی یا غیرمتعارف برای فرار از اسکن پورت
read -p "Enter WireGuard Port (Default 51820 or custom high port): " WG_PORT
WG_PORT=${WG_PORT:-51820}

MAIN_INTERFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)

# حذف اینترفیس قبلی در صورت وجود
ip link del wg0 2>/dev/null

if [[ "$LOCATION" == "1" ]]; then
    echo -e "${YELLOW}[*] Configuring IRAN server securely...${RESET}"

    PrivKey=$(wg genkey)
    PubKey=$(echo "$PrivKey" | wg pubkey)

    echo -e "${YELLOW}[?] Please run the Foreign server script first and copy its Public Key.${RESET}"
    read -p "Enter FOREIGN server Public Key: " FOREIGN_PUBKEY

    # فعال‌سازی IP Forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf

    # ساخت اینترفیس وایرگارد
    ip link add dev wg0 type wireguard
    ip address add 10.0.0.2/30 dev wg0
    mkdir -p /etc/wireguard
    echo "$PrivKey" > /etc/wireguard/private.key
    chmod 600 /etc/wireguard/private.key
    
    wg set wg0 listen-port $WG_PORT private-key /etc/wireguard/private.key
    wg set wg0 peer "$FOREIGN_PUBKEY" endpoint "$IP_FOREIGN:$WG_PORT" allowed-ips 0.0.0.0/0 persistent-keepalive 25
    ip link set dev wg0 up

    # پاکسازی قوانین قبلی برای جلوگیری از تداخل
    iptables -F -t nat
    iptables -X -t nat

    # سخت‌سازی فایروال: مسدودسازی دسترسی مستقیم به پورت تانل به جز آی‌پی سرور خارج
    iptables -A INPUT -p udp --dport $WG_PORT -s "$IP_FOREIGN" -j ACCEPT
    iptables -A INPUT -p udp --dport $WG_PORT -j DROP

    # قوانین فوروارد و NAT (محدود کردن پورت SSH برای امنیت بیشتر)
    iptables -t nat -A PREROUTING -i $MAIN_INTERFACE -p tcp ! --dport 22 -j DNAT --to-destination 10.0.0.1
    iptables -t nat -A PREROUTING -i $MAIN_INTERFACE -p udp -j DNAT --to-destination 10.0.0.1
    iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
    iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE

    echo -e "${GREEN}[+] Iran server configured and hardened successfully!${RESET}"
    echo "Your Iran Server Public Key: $PubKey"

elif [[ "$LOCATION" == "2" ]]; then
    echo -e "${YELLOW}[*] Configuring FOREIGN server securely...${RESET}"

    PrivKey=$(wg genkey)
    PubKey=$(echo "$PrivKey" | wg pubkey)

    echo -e "Your Foreign Server Public Key is: ${CYAN}$PubKey${RESET}"
    read -p "Press Enter after you have saved this key..."

    read -p "Enter IRAN server Public Key: " IRAN_PUBKEY

    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf

    # ساخت اینترفیس وایرگارد
    ip link add dev wg0 type wireguard
    ip address add 10.0.0.1/30 dev wg0
    mkdir -p /etc/wireguard
    echo "$PrivKey" > /etc/wireguard/private.key
    chmod 600 /etc/wireguard/private.key

    wg set wg0 listen-port $WG_PORT private-key /etc/wireguard/private.key
    wg set wg0 peer "$IRAN_PUBKEY" endpoint "$IP_IRAN:$WG_PORT" allowed-ips 0.0.0.0/0 persistent-keepalive 25
    ip link set dev wg0 up

    # سخت‌سازی فایروال سرور خارج (فقط اجازه به سرور ایران)
    iptables -A INPUT -p udp --dport $WG_PORT -s "$IP_IRAN" -j ACCEPT
    iptables -A INPUT -p udp --dport $WG_PORT -j DROP

    iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE

    echo -e "${GREEN}[+] Foreign server configured and hardened successfully!${RESET}"

else
    echo -e "${YELLOW}[!] Invalid selection. Please enter 1 or 2.${RESET}"
    exit 1
fi
