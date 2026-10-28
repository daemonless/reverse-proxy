// reverse-proxy admin: renders the Caddy configuration from state, loads it
// over Caddy's admin socket and serves the UI and API on a unix socket that
// Caddy fronts on :8443.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/app"
	"github.com/daemonless/reverse-proxy/admin/internal/auth"
	"github.com/daemonless/reverse-proxy/admin/internal/ca"
	"github.com/daemonless/reverse-proxy/admin/internal/caddy"
	"github.com/daemonless/reverse-proxy/admin/internal/certs"
	"github.com/daemonless/reverse-proxy/admin/internal/dns"
	"github.com/daemonless/reverse-proxy/admin/internal/server"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

var version = "dev"

func main() {
	stateDir := flag.String("state", "/config", "state directory")
	caddySock := flag.String("caddy-socket", "/var/run/reverse-proxy/caddy.sock", "Caddy admin socket")
	listen := flag.String("listen", "/var/run/reverse-proxy/admin.sock", "unix socket to serve the UI and API on")
	probeSock := flag.String("probe-socket", "/var/run/reverse-proxy/tls.sock", "unix socket Caddy serves the hosts' certificates on")
	flag.Parse()

	log.SetFlags(0)
	switch flag.Arg(0) {
	case "reset-password":
		os.Exit(resetPassword(*listen))
	case "hosts":
		os.Exit(hostsCmd(*listen, flag.Args()[1:]))
	case "listen":
		os.Exit(listenCmd(*listen, flag.Args()[1:]))
	case "":
	default:
		fmt.Fprintf(os.Stderr, "reverse-proxy: unknown command %q\n\nCommands:\n  hosts           list, add, remove or restore hosts\n  listen          answer on every network, or on some\n  reset-password  forget the password and print a new setup link\n", flag.Arg(0))
		os.Exit(2)
	}
	log.Printf("[admin] reverse-proxy %s", version)
	// Typed in a shell while the container's admin runs: refuse here, before
	// the state file is rewritten (as root) and the socket unlinked from
	// under the running admin, which took the proxy down until a restart.
	if server.AdminAlive(*listen) {
		log.Fatalf("[admin] an admin is already running (it answers on %s). For the command line: reverse-proxy hosts, reverse-proxy reset-password", *listen)
	}

	secrets := filepath.Join(*stateDir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		log.Fatalf("[admin] %v", err)
	}
	certPath, keyPath, err := caddy.EnsureSetupCert(secrets)
	if err != nil {
		log.Fatalf("[admin] setup certificate: %v", err)
	}

	// Caddy (root) writes certificate events here for the admin to read.
	issuanceLog := filepath.Join(*stateDir, "logs", "issuance.log")
	if err := os.MkdirAll(filepath.Dir(issuanceLog), 0o755); err != nil {
		log.Fatalf("[admin] %v", err)
	}

	client := caddy.NewClient(*caddySock)
	refused := &dns.Refusal{}
	listenEnv := strings.TrimSpace(os.Getenv("RP_LISTEN"))
	answering := &answerOn{env: listenEnv}
	render := func(st *state.State) any {
		in := caddy.Input{
			AdminSocket: *caddySock,
			UISocket:    *listen,
			ProbeSocket: *probeSock,
			CertPath:    certPath,
			KeyPath:     keyPath,
			LogLevel:    "WARN",
			IssuanceLog: issuanceLog,
			State:       st,
		}
		in.Listen, in.Shut = answering.render(st.Settings.Listen)
		if os.Getenv("RP_DEBUG") != "" {
			in.LogLevel = "INFO"
		}
		if root, err := ca.Load(secrets); err == nil && root.Domain == st.Settings.Domain {
			in.RootCert, in.RootKey, in.RootID = root.CertPath, root.KeyPath, root.ID()
		}
		if c, err := dns.Load(secrets); err == nil && refused.Refused(c) == "" {
			in.DNS = c
		}
		return caddy.Render(in)
	}
	mgr, err := app.New(state.NewStore(filepath.Join(*stateDir, "state.json")), client, render)
	if err != nil {
		log.Fatalf("[admin] state: %v", err)
	}
	// The root CA exists from the moment a domain does, so every
	// certificate Caddy issues is under the restricted root.
	mgr.Prepare = func(st *state.State) error {
		if st.Settings.Domain == "" {
			return nil
		}
		root, err := ca.Ensure(secrets, st.Settings.Domain)
		if err != nil {
			return err
		}
		if root.Created {
			log.Printf("[admin] made the root certificate for %s; fingerprint %s", root.Domain, root.Fingerprint)
		}
		return nil
	}
	err = reloadWhenUp(mgr)
	// Credentials Caddy won't load must not keep the proxy down (and the
	// admin with it, where they would be fixed): without them it serves
	// names on its own certificates and says what to fix.
	var ce *app.CaddyError
	if c, lerr := dns.Load(secrets); errors.As(err, &ce) && lerr == nil {
		refused.Set(c, ce.Err)
		if err = reloadWhenUp(mgr); err == nil {
			log.Printf("[admin] Caddy refused the saved %s credentials (%v); using the proxy's own certificates until they are replaced", c.Provider, ce.Err)
		}
	}
	if err != nil {
		log.Fatalf("[admin] loading Caddy config: %v", err)
	}
	log.Printf("[admin] Caddy configuration loaded")

	// An app that installed the proxy (fjord) can pair with it up front:
	// it chose the key and passes it in, so nobody copies one across.
	if key := os.Getenv("RP_PAIRING_KEY"); key != "" {
		label := cmp.Or(os.Getenv("RP_PAIRING_NAME"), "Paired app")
		if added, err := server.RegisterPairingKey(mgr, key, label, os.Getenv("RP_PAIRING_URL"), os.Getenv("RP_PAIRING_ID")); err != nil {
			log.Printf("[admin] RP_PAIRING_KEY not used: %v", err)
		} else if added {
			log.Printf("[admin] connected %s (from RP_PAIRING_KEY)", label)
		}
	}

	setupToken := ""
	if mgr.State().Settings.AdminPasswordHash == "" {
		// RP_SETUP_TOKEN: the installing app made the token and opens the
		// setup with it. Only for first run; reset-password mints its own.
		setupToken = os.Getenv("RP_SETUP_TOKEN")
		if len(setupToken) < 16 {
			setupToken = auth.NewSetupToken()
		}
		printSetupBanner(setupToken, server.AdminURL(mgr.State()))
	}

	srv := server.New(version, client, mgr, setupToken, secrets)
	srv.CaddyVersion = caddyVersion()
	srv.ListenEnv = listenEnv
	srv.IssuanceLog = issuanceLog
	srv.Observe = func(ctx context.Context, name string) certs.Observation {
		return certs.Observe(ctx, "unix", *probeSock, name)
	}
	if v := os.Getenv("RP_TRUST_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			log.Fatalf("[admin] RP_TRUST_PORT=%q is not a port", v)
		}
		srv.TrustPort = p
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	srv.CheckProvider = server.CheckProvider
	srv.DNSRefused = func() string {
		c, err := dns.Load(secrets)
		if err != nil {
			return ""
		}
		return refused.Refused(c)
	}
	go certs.Watch(ctx, mgr, srv.Observe, client.Stop)
	go srv.WatchToken(ctx, 24*time.Hour)
	go keepLoaded(ctx, mgr, client)
	go answering.watch(ctx, mgr)
	if err := srv.ServeUnix(ctx, *listen); err != nil {
		log.Fatalf("[admin] %v", err)
	}
}

// reloadWhenUp waits for Caddy's socket, however long Caddy takes to start.
// A config Caddy rejects is a bug, not a timing issue, and fails at once.
func reloadWhenUp(m *app.Manager) error {
	for attempt := 1; ; attempt++ {
		err := m.Reload()
		if err == nil {
			return nil
		}
		var ce *app.CaddyError
		if errors.As(err, &ce) && !isDialError(ce.Err) {
			return err
		}
		// Caddy's socket appearing a moment later is normal and not
		// worth a line unless it drags on.
		if attempt == 5 || attempt%30 == 0 {
			log.Printf("[admin] still waiting for Caddy (%v)", err)
		}
		time.Sleep(time.Second)
	}
}

// keepLoaded puts the configuration back when Caddy restarted on its own
// and came up with only the bootstrap config.
func keepLoaded(ctx context.Context, m *app.Manager, c *caddy.Client) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if ok, err := c.Loaded(); err != nil || ok {
			continue
		}
		if err := m.Reload(); err != nil {
			log.Printf("[admin] Caddy restarted; loading the configuration failed: %v", err)
			continue
		}
		log.Printf("[admin] Caddy restarted; configuration loaded again")
	}
}

func isDialError(err error) bool {
	var se *os.SyscallError
	return errors.As(err, &se) || errors.Is(err, os.ErrNotExist)
}

// resetPassword is the `reverse-proxy reset-password` command: it asks the
// running admin, over its unix socket, to forget the password and print a
// new setup token.
func resetPassword(sock string) int {
	c := socketClient(sock)
	resp, err := c.Post("http://admin/internal/reset", "application/json", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach the admin at %s: %v\n", sock, err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		SetupToken string `json:"setupToken"`
		AdminURL   string `json:"adminUrl"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &out) != nil || out.SetupToken == "" {
		fmt.Fprintf(os.Stderr, "reset failed: %s %s\n", resp.Status, body)
		return 1
	}
	fmt.Print(setupText("Password cleared. Set up again", out.AdminURL, out.SetupToken))
	return 0
}

// adminPlace is where the admin's pages are when nothing better is known:
// the container cannot see which host port its 8443 is published on.
const adminPlace = "https://<this machine>:8443"

// setupText is the hand-off to the setup page, for the first-run banner and
// reset-password alike. The link carries the token in the fragment, which
// browsers never send to the server, so it cannot land in any log. adminURL
// is RP_ADMIN_URL or the address the account last used; "" when neither.
func setupText(lead, adminURL, token string) string {
	where := adminURL
	tail := ""
	if where == "" {
		where = adminPlace
		lead += " at port 8443 of this machine, over https"
		tail = "RP_ADMIN_URL in the compose makes this link exact.\n"
	} else {
		lead += " here"
	}
	return fmt.Sprintf("%s:\n\n    %s/#token=%s\n\nWithout the link, the page asks for the setup token: %s\n%s", lead, where, token, token, tail)
}

// printSetupBanner tells the person how to start.
func printSetupBanner(token, adminURL string) {
	log.Printf("[admin] ")
	for _, line := range strings.Split(strings.TrimRight(setupText("First run. Set up", adminURL, token), "\n"), "\n") {
		log.Printf("[admin] %s", line)
	}
	log.Printf("[admin] ")
}

// caddyVersion asks the Caddy binary once; it is shown on the About page.
func caddyVersion() string {
	out, err := exec.Command("/usr/local/bin/caddy", "version").Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
