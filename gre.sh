#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

APP_NAME="port-tunnel"
INSTALL_DIR="/usr/local/lib/$APP_NAME"
BIN_PATH="$INSTALL_DIR/core"
CONFIG_DIR="/etc/$APP_NAME"
SERVICE_DIR="/etc/systemd/system"

clear
echo -e "${CYAN}${BOLD}"
echo "=============================================="
echo "          PORT TUNNEL INSTALLER"
echo "=============================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root (sudo).${NC}"
    exit 1
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

# ------------------ Go Core ------------------
write_core() {
cat > "$INSTALL_DIR/main.go" << 'EOF'
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Mode       string            `json:"mode"`
	BindAddr   string            `json:"bind_addr,omitempty"`
	ServerAddr string            `json:"server_addr,omitempty"`
	Token      string            `json:"token"`
	Services   map[string]string `json:"services"`
}

const (
	tAuth  = 1
	tOpen  = 3
	tData  = 5
	tClose = 6
	tPing  = 7
	tPong  = 8
)

type Frame struct {
	Type   byte
	Stream uint32
	Data   []byte
}

func writeFrame(w io.Writer, f Frame) error {
	header := make([]byte, 9)
	header[0] = f.Type
	binary.BigEndian.PutUint32(header[1:5], f.Stream)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(f.Data)))
	_, err := w.Write(append(header, f.Data...))
	return err
}

func readFrame(r io.Reader) (Frame, error) {
	header := make([]byte, 9)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	length := binary.BigEndian.Uint32(header[5:9])
	data := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Type: header[0], Stream: binary.BigEndian.Uint32(header[1:5]), Data: data}, nil
}

func deriveKey(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func deriveIV(seed []byte, suffix string) []byte {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte(suffix))
	return h.Sum(nil)[:16]
}

func wrapConn(conn net.Conn, key, ivIn, ivOut []byte) (io.Reader, io.Writer) {
	blockR, _ := aes.NewCipher(key)
	blockW, _ := aes.NewCipher(key)
	r := cipher.StreamReader{S: cipher.NewCTR(blockR, ivIn), R: conn}
	w := &cipher.StreamWriter{S: cipher.NewCTR(blockW, ivOut), W: conn}
	return r, w
}

func setNoDelay(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
}

func runServer(cfg Config) {
	ln, err := net.Listen("tcp", cfg.BindAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[Server] Listening on", cfg.BindAddr)

	var nextID uint32 = 1

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleServerConn(conn, cfg, &nextID)
	}
}

func handleServerConn(conn net.Conn, cfg Config, nextID *uint32) {
	defer conn.Close()
	setNoDelay(conn)

	marker := make([]byte, 1)
	if _, err := io.ReadFull(conn, marker); err != nil || marker[0] != 1 {
		return
	}

	seed := make([]byte, 32)
	if _, err := io.ReadFull(conn, seed); err != nil {
		return
	}

	key := deriveKey(cfg.Token)
	ivIn := deriveIV(seed, "c2s")
	ivOut := deriveIV(seed, "s2c")
	r, w := wrapConn(conn, key, ivIn, ivOut)
	br := bufio.NewReaderSize(r, 128*1024)

	auth, err := readFrame(br)
	if err != nil || auth.Type != tAuth || string(auth.Data) != cfg.Token {
		log.Println("[Server] Auth failed")
		return
	}
	log.Println("[Server] Client authenticated")

	streams := make(map[uint32]net.Conn)
	var streamsMu sync.Mutex
	var writeMu sync.Mutex

	send := func(f Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeFrame(w, f)
	}

	for name, addr := range cfg.Services {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Println("[Server] Listen error on", addr, ":", err)
			continue
		}
		log.Println("[Server] Service:", name, "->", addr)

		go func(serviceName string, listener net.Listener) {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				setNoDelay(c)
				id := atomic.AddUint32(nextID, 1)

				streamsMu.Lock()
				streams[id] = c
				streamsMu.Unlock()

				if err := send(Frame{Type: tOpen, Stream: id, Data: []byte(serviceName)}); err != nil {
					c.Close()
					streamsMu.Lock()
					delete(streams, id)
					streamsMu.Unlock()
					continue
				}

				go func(streamID uint32, local net.Conn) {
					buf := make([]byte, 32*1024)
					for {
						n, err := local.Read(buf)
						if n > 0 {
							data := make([]byte, n)
							copy(data, buf[:n])
							if send(Frame{Type: tData, Stream: streamID, Data: data}) != nil {
								break
							}
						}
						if err != nil {
							break
						}
					}
					_ = send(Frame{Type: tClose, Stream: streamID})
					streamsMu.Lock()
					delete(streams, streamID)
					streamsMu.Unlock()
					local.Close()
				}(id, c)
			}
		}(name, ln)
	}

	for {
		f, err := readFrame(br)
		if err != nil {
			break
		}
		switch f.Type {
		case tData:
			streamsMu.Lock()
			c := streams[f.Stream]
			streamsMu.Unlock()
			if c != nil {
				_, _ = c.Write(f.Data)
			}
		case tClose:
			streamsMu.Lock()
			if c, ok := streams[f.Stream]; ok {
				c.Close()
				delete(streams, f.Stream)
			}
			streamsMu.Unlock()
		case tPing:
			_ = send(Frame{Type: tPong})
		}
	}

	streamsMu.Lock()
	for id, c := range streams {
		c.Close()
		delete(streams, id)
	}
	streamsMu.Unlock()
	log.Println("[Server] Client disconnected")
}

func runClient(cfg Config) {
	for {
		if err := clientOnce(cfg); err != nil {
			log.Println("[Client] Error:", err)
		}
		time.Sleep(3 * time.Second)
	}
}

func clientOnce(cfg Config) error {
	conn, err := net.DialTimeout("tcp", cfg.ServerAddr, 12*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	setNoDelay(conn)

	seed := make([]byte, 32)
	rand.Read(seed)

	if _, err := conn.Write([]byte{1}); err != nil {
		return err
	}
	if _, err := conn.Write(seed); err != nil {
		return err
	}

	key := deriveKey(cfg.Token)
	ivOut := deriveIV(seed, "c2s")
	ivIn := deriveIV(seed, "s2c")
	r, w := wrapConn(conn, key, ivIn, ivOut)
	br := bufio.NewReaderSize(r, 128*1024)

	var writeMu sync.Mutex
	send := func(f Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeFrame(w, f)
	}

	if err := send(Frame{Type: tAuth, Data: []byte(cfg.Token)}); err != nil {
		return err
	}
	log.Println("[Client] Connected to", cfg.ServerAddr)

	streams := make(map[uint32]net.Conn)
	var streamsMu sync.Mutex

	go func() {
		t := time.NewTicker(8 * time.Second)
		defer t.Stop()
		for range t.C {
			if send(Frame{Type: tPing}) != nil {
				return
			}
		}
	}()

	for {
		f, err := readFrame(br)
		if err != nil {
			break
		}
		switch f.Type {
		case tOpen:
			name := string(f.Data)
			addr, ok := cfg.Services[name]
			if !ok {
				_ = send(Frame{Type: tClose, Stream: f.Stream})
				continue
			}
			local, err := net.DialTimeout("tcp", addr, 6*time.Second)
			if err != nil {
				_ = send(Frame{Type: tClose, Stream: f.Stream})
				continue
			}
			setNoDelay(local)

			streamsMu.Lock()
			streams[f.Stream] = local
			streamsMu.Unlock()

			go func(streamID uint32, local net.Conn) {
				buf := make([]byte, 32*1024)
				for {
					n, err := local.Read(buf)
					if n > 0 {
						data := make([]byte, n)
						copy(data, buf[:n])
						if send(Frame{Type: tData, Stream: streamID, Data: data}) != nil {
							break
						}
					}
					if err != nil {
						break
					}
				}
				_ = send(Frame{Type: tClose, Stream: streamID})
				streamsMu.Lock()
				delete(streams, streamID)
				streamsMu.Unlock()
				local.Close()
			}(f.Stream, local)

		case tData:
			streamsMu.Lock()
			c := streams[f.Stream]
			streamsMu.Unlock()
			if c != nil {
				_, _ = c.Write(f.Data)
			}
		case tClose:
			streamsMu.Lock()
			if c, ok := streams[f.Stream]; ok {
				c.Close()
				delete(streams, f.Stream)
			}
			streamsMu.Unlock()
		}
	}

	streamsMu.Lock()
	for id, c := range streams {
		c.Close()
		delete(streams, id)
	}
	streamsMu.Unlock()
	return io.EOF
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: core <config.json>")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatal(err)
	}
	switch cfg.Mode {
	case "server":
		runServer(cfg)
	case "client":
		runClient(cfg)
	default:
		log.Fatal("invalid mode")
	}
}
EOF
}

# ------------------ Install Core ------------------
install_core() {
    echo -e "${BLUE}Preparing tunnel core...${NC}"

    if ! command -v go >/dev/null 2>&1; then
        echo -e "${YELLOW}Go not found, installing...${NC}"
        apt update -y >/dev/null 2>&1
        apt install -y golang-go >/dev/null 2>&1 || {
            echo -e "${RED}Failed to install Go.${NC}"
            exit 1
        }
    fi

    write_core
    cd "$INSTALL_DIR" || exit 1

    echo -e "${BLUE}Compiling core...${NC}"
    if GO111MODULE=off go build -ldflags="-s -w" -o "$BIN_PATH" main.go; then
        chmod +x "$BIN_PATH"
        echo -e "${GREEN}Core installed successfully.${NC}"
    else
        echo -e "${RED}Build failed.${NC}"
        exit 1
    fi
}

# ------------------ Create Service ------------------
create_service() {
    local name=$1
    local role=$2

    cat > "$SERVICE_DIR/${APP_NAME}-${name}.service" <<EOF
[Unit]
Description=Port Tunnel ($role) - $name
After=network.target

[Service]
Type=simple
ExecStart=$BIN_PATH $CONFIG_DIR/${name}.json
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${APP_NAME}-${name}" >/dev/null 2>&1
    systemctl restart "${APP_NAME}-${name}"
}

# ------------------ List Tunnels ------------------
list_tunnels() {
    ls "$CONFIG_DIR" 2>/dev/null | grep '\.json$' | sed 's/\.json$//'
}

# ------------------ Delete Tunnel ------------------
delete_tunnel() {
    echo -e "\n${YELLOW}${BOLD}=== Delete Tunnel ===${NC}\n"

    TUNNELS=($(list_tunnels))
    if [ ${#TUNNELS[@]} -eq 0 ]; then
        echo -e "${RED}No tunnels found.${NC}"
        return
    fi

    echo -e "${CYAN}Available tunnels:${NC}"
    for i in "${!TUNNELS[@]}"; do
        STATUS=$(systemctl is-active "${APP_NAME}-${TUNNELS[$i]}" 2>/dev/null || echo "inactive")
        if [ "$STATUS" == "active" ]; then
            echo -e "  $((i+1)). ${TUNNELS[$i]} - ${GREEN}Running${NC}"
        else
            echo -e "  $((i+1)). ${TUNNELS[$i]} - ${RED}Stopped${NC}"
        fi
    done

    echo ""
    read -p "Enter tunnel number to delete (0 to cancel): " SEL
    if [ "$SEL" == "0" ] || [ -z "$SEL" ]; then
        return
    fi

    IDX=$((SEL-1))
    if [ -z "${TUNNELS[$IDX]}" ]; then
        echo -e "${RED}Invalid selection.${NC}"
        return
    fi

    TNAME="${TUNNELS[$IDX]}"

    echo -e "${RED}Are you sure you want to delete tunnel '${TNAME}'? (y/n)${NC}"
    read -p "> " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo -e "${YELLOW}Cancelled.${NC}"
        return
    fi

    systemctl stop "${APP_NAME}-${TNAME}" >/dev/null 2>&1
    systemctl disable "${APP_NAME}-${TNAME}" >/dev/null 2>&1
    rm -f "$SERVICE_DIR/${APP_NAME}-${TNAME}.service"
    rm -f "$CONFIG_DIR/${TNAME}.json"
    systemctl daemon-reload

    echo -e "${GREEN}Tunnel '${TNAME}' deleted successfully.${NC}"
}

# ------------------ Iran Server ------------------
setup_iran() {
    echo -e "\n${YELLOW}${BOLD}=== Setup Iran Server ===${NC}\n"

    read -p "Tunnel name [main]: " TNAME
    TNAME=${TNAME:-main}

    read -p "Control port [2333]: " CPORT
    CPORT=${CPORT:-2333}

    read -p "Public ports (comma separated, e.g. 443,80,2053,2083,2087): " PORTS
    if [ -z "$PORTS" ]; then
        echo -e "${RED}At least one port is required.${NC}"
        return
    fi

    read -p "Token (leave empty for random): " TOKEN
    if [ -z "$TOKEN" ]; then
        TOKEN=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
    fi

    SERVICES="{"
    FIRST=1
    IFS=',' read -ra PARR <<< "$PORTS"
    for P in "${PARR[@]}"; do
        P=$(echo "$P" | xargs)
        [ -z "$P" ] && continue
        if [ $FIRST -eq 0 ]; then
            SERVICES+=","
        fi
        SERVICES+="\"$P\":\"0.0.0.0:$P\""
        FIRST=0
    done
    SERVICES+="}"

    cat > "$CONFIG_DIR/${TNAME}.json" <<EOF
{
  "mode": "server",
  "bind_addr": "0.0.0.0:$CPORT",
  "token": "$TOKEN",
  "services": $SERVICES
}
EOF

    create_service "$TNAME" "Iran-Server"

    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Iran Server tunnel created successfully${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "Name         : ${YELLOW}$TNAME${NC}"
    echo -e "Control Port : ${YELLOW}$CPORT${NC}"
    echo -e "Public Ports : ${YELLOW}$PORTS${NC}"
    echo -e "Token        : ${YELLOW}$TOKEN${NC}"
    echo -e "\n${CYAN}Use this Token and Control Port on the Foreign server.${NC}"
}

# ------------------ Foreign Client ------------------
setup_foreign() {
    echo -e "\n${YELLOW}${BOLD}=== Setup Foreign Client ===${NC}\n"

    read -p "Tunnel name [main]: " TNAME
    TNAME=${TNAME:-main}

    read -p "Iran server IP: " SIP
    if [ -z "$SIP" ]; then
        echo -e "${RED}Iran server IP is required.${NC}"
        return
    fi

    read -p "Control port [2333]: " CPORT
    CPORT=${CPORT:-2333}

    read -p "Token: " TOKEN
    if [ -z "$TOKEN" ]; then
        echo -e "${RED}Token is required.${NC}"
        return
    fi

    read -p "Local ports (comma separated, e.g. 443,80,2053,2083,2087): " PORTS
    if [ -z "$PORTS" ]; then
        echo -e "${RED}At least one port is required.${NC}"
        return
    fi

    SERVICES="{"
    FIRST=1
    IFS=',' read -ra PARR <<< "$PORTS"
    for P in "${PARR[@]}"; do
        P=$(echo "$P" | xargs)
        [ -z "$P" ] && continue
        if [ $FIRST -eq 0 ]; then
            SERVICES+=","
        fi
        SERVICES+="\"$P\":\"127.0.0.1:$P\""
        FIRST=0
    done
    SERVICES+="}"

    cat > "$CONFIG_DIR/${TNAME}.json" <<EOF
{
  "mode": "client",
  "server_addr": "$SIP:$CPORT",
  "token": "$TOKEN",
  "services": $SERVICES
}
EOF

    create_service "$TNAME" "Foreign-Client"

    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Foreign Client tunnel created successfully${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "Name        : ${YELLOW}$TNAME${NC}"
    echo -e "Connected to: ${YELLOW}$SIP:$CPORT${NC}"
    echo -e "Local Ports : ${YELLOW}$PORTS${NC}"
}

# ------------------ Main Menu ------------------
install_core

while true; do
    echo -e "\n${CYAN}${BOLD}============ MAIN MENU ============${NC}"
    echo -e "  1) Setup Iran Server"
    echo -e "  2) Setup Foreign Client"
    echo -e "  3) Delete Tunnel"
    echo -e "  4) List Tunnels"
    echo -e "  0) Exit"
    echo -e "${CYAN}===================================${NC}"
    read -p "Select option: " CHOICE

    case $CHOICE in
        1) setup_iran ;;
        2) setup_foreign ;;
        3) delete_tunnel ;;
        4)
            echo -e "\n${CYAN}Current tunnels:${NC}"
            TUNNELS=($(list_tunnels))
            if [ ${#TUNNELS[@]} -eq 0 ]; then
                echo -e "${RED}No tunnels found.${NC}"
            else
                for T in "${TUNNELS[@]}"; do
                    STATUS=$(systemctl is-active "${APP_NAME}-$T" 2>/dev/null || echo "inactive")
                    if [ "$STATUS" == "active" ]; then
                        echo -e "  - $T : ${GREEN}Running${NC}"
                    else
                        echo -e "  - $T : ${RED}Stopped${NC}"
                    fi
                done
            fi
            ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
done
