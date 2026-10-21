#!/usr/bin/env bash
# ============================================================================
#  tunnel v2 - TCP tunnel that looks like an ordinary HTTPS website
#  (TLS1.3, decoy web page for probes, pinned server key, HMAC auth,
#   fragmented ClientHello). Single file: embeds the Go source, builds it, and
#  configures certificates, systemd and firewall for you.
#
#  Run (interactive menu):
#     bash <(curl -fsSL https://raw.githubusercontent.com/USER/REPO/main/install.sh)
# ============================================================================
set -euo pipefail

GO_VERSION="${GO_VERSION:-1.24.0}"
BIN="/usr/local/bin/tunnel"
CONF="/etc/tunnel"
SHARE="/usr/local/share/tunnel"
HAVE_TTY=0
TMP=""

# ---------------------------------------------------------------- ui helpers
if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else R=""; G=""; Y=""; B=""; N=""; fi
info() { printf '%s\n' ">> $*"; }
ok()   { printf '%s\n' "${G}[ok]${N} $*"; }
warn() { printf '%s\n' "${Y}[!]${N} $*" >&2; }
err()  { printf '%s\n' "${R}[x]${N} $*" >&2; }
die()  { err "$*"; exit 1; }

# ask VAR "prompt" "default" [validator]   (env var with same name pre-fills it)
ask() {
  local var="$1" prompt="$2" def="${3:-}" check="${4:-}" ans
  ans="${!var:-}"
  while :; do
    if [ -z "$ans" ]; then
      if [ "$HAVE_TTY" = 1 ]; then
        if [ -n "$def" ]; then
          read -r -p "$prompt [$def]: " ans </dev/tty || die "input aborted"
          ans="${ans:-$def}"
        else
          read -r -p "$prompt: " ans </dev/tty || die "input aborted"
        fi
      else
        ans="$def"
      fi
    fi
    if [ -z "$check" ] || "$check" "$ans"; then break; fi
    err "invalid value: ${ans:-<empty>}"
    if [ "$HAVE_TTY" != 1 ]; then exit 1; fi
    ans=""
  done
  printf -v "$var" '%s' "$ans"
}

confirm() { # confirm "question"  -> returns 0 for yes
  if [ "${YES:-}" = 1 ]; then return 0; fi
  if [ "$HAVE_TTY" != 1 ]; then return 1; fi
  local a; read -r -p "$1 [y/N]: " a </dev/tty || return 1
  [[ "$a" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------- validators
valid_port()   { [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_host()   { local re='^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$'; [[ "$1" =~ $re ]]; }
valid_target() { local re='^[A-Za-z0-9._-]+:[0-9]{1,5}$'; [[ "$1" =~ $re ]] && valid_port "${1##*:}"; }
valid_ipv4()   { local re='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; [[ "$1" =~ $re ]]; }
valid_allow()  { local re='^([0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?)?$'; [[ "$1" =~ $re ]]; }
valid_token()  { [[ "${1//[[:space:]]/}" == TUNNEL2.* ]]; }
valid_url()    { local re='^(https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?/?)?$'; [[ "$1" =~ $re ]]; }
valid_yn()     { [[ "$1" =~ ^(yes|no|y|n)$ ]]; }

# ---------------------------------------------------------------- embedded Go source
emit_source() {
cat <<'TUNNEL_GO_SOURCE_EOF'
// tunnel v2 - a TCP tunnel that looks like an ordinary HTTPS website.
//
//   - Server listens on 443 with TLS 1.3. Anyone who does not present the secret
//     (HMAC cookie + secret URL path) just gets a normal-looking web page
//     (built-in nginx-style page, or a mirror of a real site) -> active-probe resistant.
//
//   - Client does not need a CA: it pins the server's public key (SHA-256 of SPKI),
//     so the SNI it sends can be ANY popular hostname.
//
//   - Client can fragment its TLS ClientHello into small TCP segments to confuse
//     DPI that only inspects the first packet.
//
//   - Standard library only.
//
//     tunnel gen    -out DIR -sni www.example.com        (prints PSK / URLPATH / PIN)
//     tunnel server -listen :443 -target 127.0.0.1:22 -cert cert.pem -key key.pem   (env: TUNNEL_PSK, TUNNEL_PATH, TUNNEL_DECOY)
//     tunnel client -listen 0.0.0.0:2222 -remote B:443 -sni www.example.com          (env: TUNNEL_PSK, TUNNEL_PATH, TUNNEL_PIN)
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 10 * time.Second
	keepAlive        = 30 * time.Second
	authWindow       = 5 * time.Minute
	userAgent        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "gen":
		cmdGen(os.Args[2:])
	case "server":
		cmdServer(os.Args[2:])
	case "client":
		cmdClient(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tunnel <gen|server|client> [flags]   (-h after the command for help)")
	os.Exit(2)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// ================================================================ server

type server struct {
	psk    []byte
	path   string
	target string
	decoy  http.Handler

	mu   sync.Mutex
	seen map[string]time.Time // nonce -> expiry (replay protection)
}

func cmdServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":443", "address to listen on")
	target := fs.String("target", "", "destination to forward to, e.g. 127.0.0.1:22 (fixed)")
	certF := fs.String("cert", "cert.pem", "TLS certificate")
	keyF := fs.String("key", "key.pem", "TLS private key")
	pskHex := fs.String("psk", os.Getenv("TUNNEL_PSK"), "pre-shared key, hex (or env TUNNEL_PSK)")
	path := fs.String("path", os.Getenv("TUNNEL_PATH"), "secret URL path (or env TUNNEL_PATH)")
	decoy := fs.String("decoy", os.Getenv("TUNNEL_DECOY"), "optional https://site to mirror for visitors (empty = built-in page)")
	maxConns := fs.Int("max-conns", 1024, "max concurrent connections")
	fs.Parse(args)

	if *target == "" {
		log.Fatal("-target is required")
	}
	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) < 16 {
		log.Fatal("invalid or missing PSK (hex, >=16 bytes)")
	}
	if !strings.HasPrefix(*path, "/") || len(*path) < 9 {
		log.Fatal("invalid or missing secret path")
	}
	cert, err := tls.LoadX509KeyPair(*certF, *keyF)
	check(err)
	dh, err := decoyHandler(*decoy)
	check(err)

	s := &server{psk: psk, path: *path, target: *target, decoy: dh, seen: map[string]time.Time{}}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go s.janitor(ctx)

	lc := net.ListenConfig{KeepAlive: keepAlive}
	raw, err := lc.Listen(ctx, "tcp", *listen)
	check(err)
	ln := tls.NewListener(&limitLn{Listener: raw, sem: make(chan struct{}, *maxConns)}, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { <-ctx.Done(); srv.Close() }()

	log.Printf("server on %s -> %s (HTTPS camouflage, decoy=%q)", *listen, *target, *decoy)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == s.path && s.authOK(r) {
		s.tunnel(w, r)
		return
	}
	s.decoy.ServeHTTP(w, r) // everybody else sees a normal website
}

func (s *server) authOK(r *http.Request) bool {
	c, err := r.Cookie("sid")
	if err != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 8+16+32 {
		return false
	}
	ts := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0)
	d := time.Since(ts)
	if d < 0 {
		d = -d
	}
	if d > authWindow {
		return false
	}
	if !hmac.Equal(mac(s.psk, raw[:24], s.path), raw[24:]) {
		return false
	}
	return s.fresh(string(raw[8:24])) // only authenticated nonces are stored
}

func (s *server) fresh(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.seen[nonce]; dup || len(s.seen) > 200000 {
		return false
	}
	s.seen[nonce] = time.Now().Add(2 * authWindow)
	return true
}

func (s *server) janitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			s.mu.Lock()
			for k, exp := range s.seen {
				if now.After(exp) {
					delete(s.seen, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *server) tunnel(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d := net.Dialer{Timeout: dialTimeout, KeepAlive: keepAlive}
	up, err := d.DialContext(r.Context(), "tcp", s.target)
	if err != nil {
		log.Printf("dial %s: %v", s.target, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")); err != nil {
		conn.Close()
		up.Close()
		return
	}
	log.Printf("tunnel %s <-> %s", conn.RemoteAddr(), s.target)
	pipe(&bufConn{Conn: conn, r: brw.Reader}, up)
}

// limitLn caps concurrent connections.
type limitLn struct {
	net.Listener
	sem chan struct{}
}

func (l *limitLn) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// ---------------------------------------------------------------- decoy website

const welcomeHTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

const notFoundHTML = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
`

func decoyHandler(site string) (http.Handler, error) {
	if site == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Server", "nginx")
			h.Set("Content-Type", "text/html")
			if r.URL.Path != "/" && r.URL.Path != "/index.html" {
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, notFoundHTML)
				return
			}
			io.WriteString(w, welcomeHTML)
		}), nil
	}
	u, err := url.Parse(site)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid decoy URL %q", site)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	orig := rp.Director
	rp.Director = func(r *http.Request) {
		orig(r)
		r.Host = u.Host
		r.Header["X-Forwarded-For"] = nil // do not reveal that we are proxying
		r.Header.Del("Cookie")
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center><hr><center>nginx</center></body></html>\n")
	}
	return rp, nil
}

// ================================================================ client

type dialer struct {
	remote string
	sni    string
	path   string
	psk    []byte
	cfg    *tls.Config
	frag   bool
}

func cmdClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:2222", "local address to accept plain TCP on")
	remote := fs.String("remote", "", "tunnel server host:port")
	sni := fs.String("sni", os.Getenv("TUNNEL_SNI"), "hostname sent as SNI / Host (default: host of -remote)")
	pskHex := fs.String("psk", os.Getenv("TUNNEL_PSK"), "pre-shared key, hex (or env TUNNEL_PSK)")
	path := fs.String("path", os.Getenv("TUNNEL_PATH"), "secret URL path (or env TUNNEL_PATH)")
	pinHex := fs.String("pin", os.Getenv("TUNNEL_PIN"), "server key pin, hex SHA-256 of SPKI (or env TUNNEL_PIN)")
	frag := fs.Bool("frag", true, "fragment the TLS ClientHello into small TCP segments")
	maxConns := fs.Int("max-conns", 1024, "max concurrent connections")
	fs.Parse(args)

	if *remote == "" {
		log.Fatal("-remote is required")
	}
	host, _, err := net.SplitHostPort(*remote)
	check(err)
	if *sni == "" {
		*sni = host
	}
	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) < 16 {
		log.Fatal("invalid or missing PSK")
	}
	pin, err := hex.DecodeString(*pinHex)
	if err != nil || len(pin) != sha256.Size {
		log.Fatal("invalid or missing server pin (64 hex chars)")
	}
	if !strings.HasPrefix(*path, "/") {
		log.Fatal("invalid or missing secret path")
	}

	d := &dialer{
		remote: *remote, sni: *sni, path: *path, psk: psk, frag: *frag,
		cfg: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: *sni,
			NextProtos: []string{"http/1.1"},
			// The certificate is self-signed and the SNI is a decoy, so normal
			// CA/hostname validation is replaced by strict public-key pinning below.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("server sent no certificate")
				}
				sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
				if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
					return errors.New("server key does not match the pin (wrong server or man-in-the-middle)")
				}
				return nil
			},
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	lc := net.ListenConfig{KeepAlive: keepAlive}
	ln, err := lc.Listen(ctx, "tcp", *listen)
	check(err)
	log.Printf("client on %s -> %s (sni=%s frag=%v)", *listen, *remote, *sni, *frag)

	serve(ctx, ln, *maxConns, func(c net.Conn) {
		defer c.Close()
		dctx, cancel := context.WithTimeout(ctx, 2*dialTimeout)
		rc, err := d.dial(dctx)
		cancel()
		if err != nil {
			log.Printf("dial %s: %v", d.remote, err)
			return
		}
		defer rc.Close()
		pipe(c, rc)
	})
}

func (d *dialer) dial(ctx context.Context) (net.Conn, error) {
	nd := net.Dialer{Timeout: dialTimeout, KeepAlive: keepAlive}
	raw, err := nd.DialContext(ctx, "tcp", d.remote)
	if err != nil {
		return nil, err
	}
	var base net.Conn = raw
	if d.frag {
		base = &fragConn{Conn: raw}
	}
	tc := tls.Client(base, d.cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	tc.SetDeadline(time.Now().Add(handshakeTimeout))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nCookie: sid=%s\r\n\r\n",
		d.path, d.sni, userAgent, makeCookie(d.psk, d.path))
	if _, err := tc.Write([]byte(req)); err != nil {
		tc.Close()
		return nil, err
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		tc.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		tc.Close()
		return nil, fmt.Errorf("server answered HTTP %d (wrong key/path, or clocks differ by more than 5 minutes)", resp.StatusCode)
	}
	tc.SetDeadline(time.Time{})
	return &bufConn{Conn: tc, r: br}, nil
}

// fragConn splits the FIRST write (the TLS ClientHello) into small TCP segments.
type fragConn struct {
	net.Conn
	done bool
}

func (c *fragConn) Write(p []byte) (int, error) {
	if c.done {
		return c.Conn.Write(p)
	}
	c.done = true
	total := 0
	for len(p) > 0 {
		n := 24 + mrand.Intn(80)
		if n > len(p) {
			n = len(p)
		}
		m, err := c.Conn.Write(p[:n])
		total += m
		if err != nil {
			return total, err
		}
		p = p[n:]
		if len(p) > 0 {
			time.Sleep(time.Duration(1+mrand.Intn(6)) * time.Millisecond)
		}
	}
	return total, nil
}

// ================================================================ shared

// bufConn lets us keep reading bytes that an HTTP reader already buffered.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func mac(psk, msg []byte, path string) []byte {
	h := hmac.New(sha256.New, psk)
	h.Write([]byte("tunnel-v2|"))
	h.Write([]byte(path))
	h.Write(msg)
	return h.Sum(nil)
}

func makeCookie(psk []byte, path string) string {
	b := make([]byte, 24)
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(b[8:]); err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(append(b, mac(psk, b, path)...))
}

func serve(ctx context.Context, ln net.Listener, max int, handle func(net.Conn)) {
	go func() { <-ctx.Done(); ln.Close() }()
	sem := make(chan struct{}, max)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				log.Println("shutting down")
				return
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Printf("connection limit reached, dropping %s", c.RemoteAddr())
			c.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			handle(c)
		}()
	}
}

// pipe copies both directions and propagates half-close.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil && strings.Contains(err.Error(), "remote error: tls") {
			log.Printf("peer rejected the connection: %v", err)
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// ================================================================ gen

func cmdGen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	sni := fs.String("sni", "www.microsoft.com", "hostname placed in the certificate")
	fs.Parse(args)
	check(os.MkdirAll(*out, 0o700))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	nb := time.Now().Add(-time.Duration(1+mrand.Intn(60)) * 24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: *sni},
		DNSNames:              []string{*sni},
		NotBefore:             nb,
		NotAfter:              nb.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	check(err)
	cert, err := x509.ParseCertificate(der)
	check(err)
	kder, err := x509.MarshalECPrivateKey(key)
	check(err)

	check(os.WriteFile(filepath.Join(*out, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	check(os.WriteFile(filepath.Join(*out, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600))

	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fmt.Printf("PSK=%s\nURLPATH=/%s\nPIN=%s\n", randHex(32), randHex(8), hex.EncodeToString(pin[:]))
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	check(err)
	return n
}
TUNNEL_GO_SOURCE_EOF
}

# ---------------------------------------------------------------- build
build_binary() {
  case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    armv7l)        ARCH=armv6l ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac

  mkdir -p "$TMP/src"
  emit_source > "$TMP/src/main.go"
  printf 'module tunnel\n\ngo 1.21\n' > "$TMP/src/go.mod"

  local want have
  want="$(sha256sum "$TMP/src/main.go" | cut -d' ' -f1)"
  have="$(cat "$SHARE/src.sha256" 2>/dev/null || true)"

  if [ -n "${PREBUILT:-}" ]; then   # binary built elsewhere (e.g. when Go cannot be downloaded here)
    [ -f "$PREBUILT" ] || die "PREBUILT file not found: $PREBUILT"
    install -m 0755 "$PREBUILT" "$BIN"
    mkdir -p "$SHARE"; printf '%s\n' "$want" > "$SHARE/src.sha256"
    ok "installed prebuilt binary to $BIN"
    return 0
  fi
  if [ -x "$BIN" ] && [ "$want" = "$have" ]; then
    ok "tunnel binary is up to date"
    return 0
  fi

  local GO="" minor
  if command -v go >/dev/null 2>&1; then
    minor="$(go env GOVERSION 2>/dev/null | sed -E 's/^go1\.([0-9]+).*/\1/')"
    if [[ "$minor" =~ ^[0-9]+$ ]] && [ "$minor" -ge 21 ]; then GO="$(command -v go)"; fi
  fi
  if [ -z "$GO" ]; then
    info "downloading Go ${GO_VERSION} (temporary, removed after build)"
    local tarball="go${GO_VERSION}.linux-${ARCH}.tar.gz" expected
    curl -fsSL "https://go.dev/dl/${tarball}" -o "$TMP/$tarball" \
      || die "cannot download Go from this server (blocked?). Build 'tunnel' on another machine (GOOS=linux GOARCH=$ARCH go build) , copy it here and run with PREBUILT=/path/to/tunnel"
    expected="$(curl -fsSL "https://dl.google.com/go/${tarball}.sha256" | tr -d '[:space:]')" || true
    [ -n "$expected" ] || die "could not fetch Go checksum (see PREBUILT option in the README)"
    echo "${expected}  $TMP/$tarball" | sha256sum -c - >/dev/null || die "Go checksum mismatch, aborting"
    tar -C "$TMP" -xzf "$TMP/$tarball"
    GO="$TMP/go/bin/go"
  fi

  info "building tunnel"
  ( cd "$TMP/src" && GOTOOLCHAIN=local CGO_ENABLED=0 GOCACHE="$TMP/cache" GOPATH="$TMP/gopath" \
      "$GO" build -trimpath -ldflags "-s -w" -o "$TMP/tunnel" . ) || die "build failed"
  install -m 0755 "$TMP/tunnel" "$BIN"
  mkdir -p "$SHARE"
  printf '%s\n' "$want" > "$SHARE/src.sha256"
  ok "installed $BIN"
}

# ---------------------------------------------------------------- system helpers
ensure_user() {
  if ! id tunnel >/dev/null 2>&1; then
    useradd -r -M -s "$(command -v nologin || echo /bin/false)" tunnel
  fi
  install -d -m 750 -o root -g tunnel "$CONF"
}

detect_ip() { curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true; }
port_busy() { [ -n "$(ss -ltnH "sport = :$1" 2>/dev/null || true)" ]; }

check_clock() {
  local s
  s="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
  if [ "$s" = "no" ]; then
    warn "system clock is not NTP-synchronized. The tunnel rejects clients whose clock differs by more than 5 minutes."
    warn "fix:  timedatectl set-ntp true"
  fi
}

open_port() { # port [source-ip]
  local port="$1" src="${2:-}" st
  st="$(ufw status 2>/dev/null || true)"
  if command -v ufw >/dev/null 2>&1 && [[ "$st" == *"Status: active"* ]]; then
    if [ -n "$src" ]; then ufw allow from "$src" to any port "$port" proto tcp >/dev/null
    else ufw allow "${port}/tcp" >/dev/null; fi
    printf 'ufw %s %s\n' "$port" "${src:--}" >> "$CONF/.fw"
    ok "ufw: opened ${port}/tcp${src:+ for $src}"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    if [ -n "$src" ]; then
      firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${src} port port=${port} protocol=tcp accept" >/dev/null
    else
      firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null
    fi
    firewall-cmd --reload >/dev/null
    printf 'firewalld %s %s\n' "$port" "${src:--}" >> "$CONF/.fw"
    ok "firewalld: opened ${port}/tcp${src:+ for $src}"
  else
    warn "no active ufw/firewalld found. If you use iptables, open TCP ${port} yourself."
  fi
  warn "if your hosting provider has a cloud firewall / security group, open TCP ${port} there too."
}

write_unit() { # name description execstart envfile
  cat > "/etc/systemd/system/$1.service" <<UNIT
[Unit]
Description=$2
After=network-online.target
Wants=network-online.target

[Service]
User=tunnel
Group=tunnel
EnvironmentFile=$4
ExecStart=$3
Restart=always
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddrFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "$1" >/dev/null 2>&1
  systemctl restart "$1"
  sleep 1
  systemctl is-active --quiet "$1" || { journalctl -u "$1" -n 15 --no-pager >&2 || true; die "service $1 failed to start"; }
  ok "service $1 is running (auto-starts on boot)"
}

# ---------------------------------------------------------------- token
make_token() { # sni remote psk path pin
  printf 'SNI=%s\nREMOTE=%s\nPSK=%s\nPATH=%s\nPIN=%s\n' "$1" "$2" "$3" "$4" "$5" | gzip -9n | base64 -w0
}

tok_get() { awk -F= -v k="$1" '$1==k{print substr($0,length(k)+2); exit}' "$2"; }

parse_token() { # token tmpdir  (sets T_SNI REMOTE T_PSK T_PATH T_PIN)
  local raw="${1//[[:space:]]/}" f="$2/token.txt" re64='^[0-9a-f]{64}$' rep='^/[0-9a-f]{16}$'
  raw="${raw#TUNNEL2.}"
  printf '%s' "$raw" | base64 -d 2>/dev/null | gunzip -c > "$f" 2>/dev/null || die "invalid token (could not decode)"
  T_SNI="$(tok_get SNI "$f")";   REMOTE="$(tok_get REMOTE "$f")"
  T_PSK="$(tok_get PSK "$f")";   T_PATH="$(tok_get PATH "$f")"; T_PIN="$(tok_get PIN "$f")"
  valid_host "$T_SNI"       || die "token: invalid SNI"
  valid_target "$REMOTE"    || die "token: invalid server address"
  [[ "$T_PSK" =~ $re64 ]]   || die "token: invalid key"
  [[ "$T_PATH" =~ $rep ]]   || die "token: invalid path"
  [[ "$T_PIN" =~ $re64 ]]   || die "token: invalid pin"
}

# ---------------------------------------------------------------- Server B
setup_server() {
  if [ -f "$CONF/server.crt" ] || [ -f "$CONF/cert.pem" ]; then
    warn "an existing setup was found. Continuing creates NEW keys; old tokens will stop working."
    confirm "Continue?" || die "aborted"
    systemctl stop tunnel-server >/dev/null 2>&1 || true
    close_ports
    rm -f "$CONF/.fw"
  fi

  ask LISTEN_PORT "Tunnel port (443 looks like a normal website)" 443 valid_port
  if port_busy "$LISTEN_PORT"; then
    die "port ${LISTEN_PORT} is already in use by another program (web server?). Re-run and choose another port, e.g. 8443 or 2053."
  fi
  ask TARGET "Forward decrypted traffic to (on this server)" 127.0.0.1:22 valid_target
  ask HOST "Public IP or domain of THIS server (what Server A connects to)" "$(detect_ip)" valid_host
  ask SNI "Website name to present (a big site that is NOT blocked in Iran)" www.microsoft.com valid_host
  ask DECOY "Mirror a real site for visitors? e.g. https://www.example.org (empty = built-in page)" "" valid_url
  ask ALLOW_IP "Only accept Server A's IP (recommended if A has a fixed IP; empty = anyone)" "" valid_allow

  ensure_user
  local d="$TMP/certs" out psk upath pin
  info "generating keys"
  out="$("$BIN" gen -out "$d" -sni "$SNI")" || die "key generation failed"
  psk="$(tok_get PSK <(printf '%s\n' "$out"))"
  upath="$(tok_get URLPATH <(printf '%s\n' "$out"))"
  pin="$(tok_get PIN <(printf '%s\n' "$out"))"
  [ -n "$psk" ] && [ -n "$upath" ] && [ -n "$pin" ] || die "unexpected output from key generation"

  rm -f "$CONF/ca.crt" "$CONF/server.crt" "$CONF/server.key"
  install -m 644 -o root -g tunnel "$d/cert.pem" "$CONF/cert.pem"
  install -m 640 -o root -g tunnel "$d/key.pem"  "$CONF/key.pem"
  (
    umask 077
    {
      printf 'TUNNEL_PSK=%s\nTUNNEL_PATH=%s\n' "$psk" "$upath"
      if [ -n "$DECOY" ]; then printf 'TUNNEL_DECOY=%s\n' "$DECOY"; fi
    } > "$CONF/server.env"
  )
  chown root:tunnel "$CONF/server.env"; chmod 640 "$CONF/server.env"

  local token
  token="TUNNEL2.$(make_token "$SNI" "${HOST}:${LISTEN_PORT}" "$psk" "$upath" "$pin")"
  ( umask 077; printf '%s\n' "$token" > "$CONF/token" )
  chown root:root "$CONF/token"; chmod 600 "$CONF/token"

  write_unit tunnel-server "Tunnel server (HTTPS camouflage)" \
    "$BIN server -listen :${LISTEN_PORT} -target ${TARGET} -cert $CONF/cert.pem -key $CONF/key.pem" "$CONF/server.env"
  open_port "$LISTEN_PORT" "$ALLOW_IP"
  check_clock
  show_token
}

show_token() {
  [ -f "$CONF/token" ] || die "no token found. Run option 1 on Server B first."
  echo
  echo "${B}Pairing token${N} (copy the WHOLE line). Treat it like a password: it contains the secret key."
  echo "--------------------------------------------------------------------------"
  cat "$CONF/token"
  echo "--------------------------------------------------------------------------"
  echo "Next: run this installer on Server A, choose option 2 and paste the token."
  echo "(Show it again anytime: option 4.)"
}

# ---------------------------------------------------------------- Server A
setup_client() {
  ask TOKEN "Paste the pairing token from Server B" "" valid_token
  ask LISTEN_ADDR "Local address to listen on (0.0.0.0 = all, 127.0.0.1 = this server only)" 0.0.0.0 valid_ipv4
  ask LISTEN_PORT "Local port to listen on" 2222 valid_port
  ask FRAG "Fragment the TLS handshake (helps against DPI; keep 'yes' unless it causes problems)" yes valid_yn

  ensure_user
  local d="$TMP/tok"; mkdir -p "$d"
  parse_token "$TOKEN" "$d"

  rm -f "$CONF/ca.crt" "$CONF/client.crt" "$CONF/client.key"
  (
    umask 077
    printf 'TUNNEL_PSK=%s\nTUNNEL_PATH=%s\nTUNNEL_PIN=%s\nTUNNEL_SNI=%s\n' "$T_PSK" "$T_PATH" "$T_PIN" "$T_SNI" > "$CONF/client.env"
  )
  chown root:tunnel "$CONF/client.env"; chmod 640 "$CONF/client.env"

  local fragflag=""
  case "$FRAG" in n|no) fragflag=" -frag=false" ;; esac
  write_unit tunnel-client "Tunnel client (HTTPS camouflage)" \
    "$BIN client -listen ${LISTEN_ADDR}:${LISTEN_PORT} -remote ${REMOTE}${fragflag}" "$CONF/client.env"
  if [ "$LISTEN_ADDR" != "127.0.0.1" ]; then open_port "$LISTEN_PORT" ""; fi
  check_clock
  test_client
  echo
  echo "Done. Connections to ${LISTEN_ADDR}:${LISTEN_PORT} on this server now travel to ${REMOTE%:*} disguised as HTTPS, and on to its target."
  echo "Example:  ssh -p ${LISTEN_PORT} user@THIS_SERVER_IP"
}

test_client() {
  local h="${REMOTE%:*}" p="${REMOTE##*:}" la="${LISTEN_ADDR/0.0.0.0/127.0.0.1}"
  if timeout 5 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then
    ok "Server B ($h:$p) is reachable"
  else
    warn "cannot reach $h:$p. Check the firewall on Server B / cloud security group / that Server B finished setup."
    return 0
  fi
  timeout 5 bash -c "exec 3<>/dev/tcp/$la/$LISTEN_PORT" 2>/dev/null || true
  sleep 3
  local bad
  bad="$(journalctl -u tunnel-client --since '-20s' -o cat --no-pager 2>/dev/null | grep -m1 -E 'dial |peer rejected' || true)"
  if [ -z "$bad" ]; then
    ok "authenticated handshake with Server B succeeded - tunnel is working"
  else
    err "tunnel test failed: $bad"
    warn "check:  journalctl -u tunnel-client -n 30   (and on Server B: journalctl -u tunnel-server -n 30)"
  fi
}

# ---------------------------------------------------------------- status / uninstall
close_ports() { # remove firewall rules that this script added
  [ -f "$CONF/.fw" ] || return 0
  local fw port src
  while read -r fw port src; do
    [ -n "$fw" ] || continue
    if [ "$src" = "-" ]; then src=""; fi
    case "$fw" in
      ufw)
        if [ -n "$src" ]; then ufw delete allow from "$src" to any port "$port" proto tcp >/dev/null 2>&1 || true
        else ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true; fi
        ok "ufw: removed rule for ${port}/tcp${src:+ ($src)}" ;;
      firewalld)
        if [ -n "$src" ]; then
          firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=${src} port port=${port} protocol=tcp accept" >/dev/null 2>&1 || true
        else
          firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
        fi
        firewall-cmd --reload >/dev/null 2>&1 || true
        ok "firewalld: removed rule for ${port}/tcp${src:+ ($src)}" ;;
    esac
  done < "$CONF/.fw"
}
show_status() {
  local u found=0
  for u in tunnel-server tunnel-client; do
    if [ -f "/etc/systemd/system/$u.service" ]; then
      found=1
      printf '%-16s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null || true)"
      journalctl -u "$u" -n 5 --no-pager -o cat 2>/dev/null | sed 's/^/    /' || true
    fi
  done
  if [ "$found" = 0 ]; then echo "tunnel is not configured on this server."; fi
}

uninstall_all() {
  echo "This will remove from this server:"
  echo "  - services tunnel-server / tunnel-client (stopped, disabled, unit files deleted)"
  echo "  - $BIN and the build marker in $SHARE"
  echo "  - $CONF (keys, certificates, pairing token, settings)"
  echo "  - the 'tunnel' system user"
  echo "  - firewall rules (ufw/firewalld) that this installer added"
  confirm "Remove everything?" || die "aborted"
  local u
  close_ports
  for u in tunnel-server tunnel-client; do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$u.service"
  done
  systemctl daemon-reload
  rm -rf "$CONF" "$SHARE" "$BIN"
  userdel tunnel >/dev/null 2>&1 || true
  ok "tunnel completely removed"
  warn "if you opened the port in a cloud firewall / security group or iptables yourself, remove that rule manually."
  echo "(Server A and B are independent: run the uninstall on the other server too.)"
}

# ---------------------------------------------------------------- main
main() {
  [ "$(uname -s)" = "Linux" ] || die "only Linux is supported"
  [ "$(id -u)" -eq 0 ] || die "please run as root (sudo -i, then run the command again)"
  command -v systemctl >/dev/null || die "systemd is required"
  command -v curl >/dev/null || die "curl is required"
  if (: </dev/tty) 2>/dev/null; then HAVE_TTY=1; fi

  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  local choice="${ROLE:-}"
  case "${choice,,}" in b|server) choice=1 ;; a|client) choice=2 ;; uninstall|remove) choice=5 ;; esac
  if [ -z "$choice" ]; then
    [ "$HAVE_TTY" = 1 ] || die "no terminal available. Set ROLE=A or ROLE=B, or download the script and run: sudo bash install.sh"
    echo
    echo "${B}  tunnel v2 - port-forward disguised as HTTPS${N}"
    echo "  (user -> [Server A] ==looks like normal HTTPS==> [Server B] -> target)"
    echo
    echo "   1) Server B  - destination, outside the filtered network (do this FIRST)"
    echo "   2) Server A  - entry point (runs the tunnel client)"
    echo "   3) Status"
    echo "   4) Show pairing token (on Server B)"
    echo "   5) Uninstall (remove everything)"
    echo "   0) Exit"
    echo
    read -r -p "Choose [1-5]: " choice </dev/tty || exit 1
  fi

  case "$choice" in
    1) build_binary; setup_server ;;
    2) build_binary; setup_client ;;
    3) show_status ;;
    4) show_token ;;
    5) uninstall_all ;;
    0) exit 0 ;;
    *) die "invalid choice" ;;
  esac
}

main "$@"
