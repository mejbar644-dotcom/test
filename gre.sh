#!/bin/bash

CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)

clear
echo -e "${CYAN}"
echo "===================================="
echo "        GitHub: AbrDade"
echo "   GRE Tunnel Safe Version"
echo "===================================="
echo -e "${RESET}"

echo "Select server location:"
echo "1 - IRAN"
echo "2 - FOREIGN"
read -p "Enter 1 or 2: " LOCATION

read -p "Enter IRAN server IP: " IP_IRAN
read -p "Enter FOREIGN server IP: " IP_FOREIGN

# پورت‌هایی که می‌خوای فوروارد بشن (اینجا محدود کن)
# مثال: 80 443 8080 2052 2082 2086 2095 2096
PORTS="2053 2829 2020 2021 2022 2023 2024 54134 1080 2086 50320 50321 222 2525 2028 8443 2288 2088"

if [[ "$LOCATION" == "1" ]]; then
    echo -e "${GREEN}[*] Configuring IRAN server...${RESET}"

    # پاک کردن قوانین قبلی برای جلوگیری از تداخل
    ip link del AbrDade-m2 2>/dev/null
    iptables -t nat -F PREROUTING 2>/dev/null
    iptables -t nat -F POSTROUTING 2>/dev/null

    # ساخت تانل GRE
    ip tunnel add AbrDade-m2 mode gre local $IP_IRAN remote $IP_FOREIGN ttl 255
    ip link set AbrDade-m2 up
    ip addr add 132.168.30.2/30 dev AbrDade-m2
    ip link set AbrDade-m2 mtu 1400

    # فعال کردن IP Forward
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # فقط پورت‌های مشخص شده رو فوروارد کن (نه همه ترافیک)
    for port in $PORTS; do
        iptables -t nat -A PREROUTING -p tcp --dport $port -j DNAT --to-destination 132.168.30.1:$port
        iptables -t nat -A PREROUTING -p udp --dport $port -j DNAT --to-destination 132.168.30.1:$port
        echo -e "${YELLOW}[+] Forwarded port $port${RESET}"
    done

    # MASQUERADE فقط برای ترافیک تانل
    iptables -t nat -A POSTROUTING -o AbrDade-m2 -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 132.168.30.0/30 -j MASQUERADE

    echo -e "${GREEN}[✓] IRAN server configured successfully.${RESET}"
    echo -e "${YELLOW}Note: Only selected ports are forwarded. Iran server internet access remains intact.${RESET}"

elif [[ "$LOCATION" == "2" ]]; then
    echo -e "${GREEN}[*] Configuring FOREIGN server...${RESET}"

    # پاک کردن تانل قبلی
    ip link del AbrDade-m2 2>/dev/null

    # ساخت تانل GRE
    ip tunnel add AbrDade-m2 mode gre local $IP_FOREIGN remote $IP_IRAN ttl 255
    ip link set AbrDade-m2 up
    ip addr add 132.168.30.1/30 dev AbrDade-m2
    ip link set AbrDade-m2 mtu 1400

    # اختیاری: بستن ICMP (اگر می‌خوای باز باشه این خط رو پاک کن)
    # iptables -A INPUT -p icmp -j DROP

    echo -e "${GREEN}[✓] FOREIGN server configured successfully.${RESET}"

else
    echo -e "${RED}[!] Invalid selection. Please enter 1 or 2.${RESET}"
    exit 1
fi

echo ""
echo -e "${CYAN}Tunnel interface: AbrDade-m2${RESET}"
echo -e "${CYAN}Iran side IP   : 132.168.30.2${RESET}"
echo -e "${CYAN}Foreign side IP: 132.168.30.1${RESET}"
