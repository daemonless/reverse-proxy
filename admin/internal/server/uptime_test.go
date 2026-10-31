package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/uptime"
)

// The alert address is write-only: an ntfy topic is as good as a password.
func TestAlertsSettings(t *testing.T) {
	s, c, _ := setUp(t)
	if rr, out := c.do("PUT", "/api/v1/alerts", `{"kind":"ntfy","url":"https://ntfy.example"}`); rr.Code != 400 || out["field"] != "url" {
		t.Fatalf("ntfy without a topic: %d %v", rr.Code, out)
	}
	if rr, out := c.do("PUT", "/api/v1/alerts", `{"kind":"mail","url":"https://x.example/y"}`); rr.Code != 400 || out["field"] != "kind" {
		t.Fatalf("unknown kind: %d %v", rr.Code, out)
	}
	rr, out := c.do("PUT", "/api/v1/alerts", `{"kind":"ntfy","url":"https://ntfy.example/secret-topic"}`)
	if rr.Code != 200 || out["to"] != "ntfy.example" || strings.Contains(rr.Body.String(), "secret-topic") {
		t.Fatalf("saved: %d %s", rr.Code, rr.Body)
	}
	if a := s.mgr.State().Settings.Alerts; a == nil || a.URL != "https://ntfy.example/secret-topic" {
		t.Fatalf("stored: %+v", a)
	}
	if rr, _ := c.do("GET", "/api/v1/alerts", ""); strings.Contains(rr.Body.String(), "secret-topic") {
		t.Fatalf("the topic is shown: %s", rr.Body)
	}
	if rr, out := c.do("PUT", "/api/v1/alerts", `{"kind":"","url":""}`); rr.Code != 200 || out["kind"] != "" || s.mgr.State().Settings.Alerts != nil {
		t.Fatalf("off: %d %v", rr.Code, out)
	}
}

func TestAlertTest(t *testing.T) {
	_, c, _ := setUp(t)
	var title, body string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		title = r.Header.Get("Title")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	defer hook.Close()
	if rr, out := c.do("POST", "/api/v1/alerts/test", `{}`); rr.Code != 400 {
		t.Fatalf("nothing saved: %d %v", rr.Code, out)
	}
	// Before saving: the address being typed in.
	if rr, out := c.do("POST", "/api/v1/alerts/test", `{"kind":"ntfy","url":"`+hook.URL+`/topic"}`); rr.Code != 200 || title != "Test from the proxy" || !strings.HasPrefix(body, "Alerts work") {
		t.Fatalf("test: %d %v %q %q", rr.Code, out, title, body)
	}
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "forbidden topic", 403) }))
	defer refuse.Close()
	if rr, out := c.do("POST", "/api/v1/alerts/test", `{"kind":"ntfy","url":"`+refuse.URL+`/topic"}`); rr.Code != 502 || !strings.Contains(out["error"].(string), "forbidden topic") {
		t.Fatalf("refused: %d %v", rr.Code, out)
	}
}

// Without a monitor (tests, or before the first check) the answers are
// empty, not errors.
func TestUptimeEmpty(t *testing.T) {
	_, c, _ := setUp(t)
	if rr, out := c.do("GET", "/api/v1/hosts/uptime", ""); rr.Code != 200 || out["uptime"] == nil {
		t.Fatalf("list: %d %v", rr.Code, out)
	}
	_, h := c.do("POST", "/api/v1/hosts", `{"name":"web","target":{"address":"10.0.0.5","port":80}}`)
	id, _ := h["id"].(string)
	if rr, out := c.do("GET", "/api/v1/hosts/"+id+"/uptime", ""); rr.Code != 200 || out["state"] != "unknown" {
		t.Fatalf("one: %d %v", rr.Code, out)
	}
	if rr, _ := c.do("GET", "/api/v1/hosts/nope/uptime", ""); rr.Code != 404 {
		t.Fatalf("no such host: %d", rr.Code)
	}
}

// Alert is what the monitor calls: it posts to the saved place, and a
// refusal shows on Settings until the next one gets through.
func TestAlertFromMonitor(t *testing.T) {
	s, c, _ := setUp(t)
	refuse := false
	var got []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse {
			http.Error(w, "topic full", 429)
			return
		}
		got = append(got, r.Header.Get("Title"))
	}))
	defer hook.Close()
	s.Alert(uptime.Event{Name: "web.apps.test", Where: "10.0.0.5:80", Down: true}) // nothing saved: nothing sent
	c.do("PUT", "/api/v1/alerts", `{"kind":"ntfy","url":"`+hook.URL+`/topic"}`)
	s.Alert(uptime.Event{Name: "web.apps.test", Where: "10.0.0.5:80", Down: true})
	if len(got) != 1 || got[0] != "web.apps.test is down" {
		t.Fatalf("sent: %v", got)
	}
	refuse = true
	s.Alert(uptime.Event{Name: "web.apps.test", Lasted: time.Minute})
	if _, out := c.do("GET", "/api/v1/alerts", ""); !strings.Contains(fmt.Sprint(out["lastError"]), "topic full") {
		t.Fatalf("refusal not shown: %v", out)
	}
	refuse = false
	s.Alert(uptime.Event{Name: "web.apps.test", Lasted: time.Minute})
	if _, out := c.do("GET", "/api/v1/alerts", ""); out["lastError"] != nil || len(got) != 2 || got[1] != "web.apps.test is back" {
		t.Fatalf("after a delivery: %v %v", out, got)
	}
}

// Watching is kept when an update leaves it out: fjord re-sends the host
// whenever the app moves and must not switch the checks back on.
func TestWatchKeptWhenAbsent(t *testing.T) {
	s, c, _ := setUp(t)
	_, h := c.do("POST", "/api/v1/hosts", `{"name":"web","target":{"address":"10.0.0.5","port":80},"watch":false}`)
	id, _ := h["id"].(string)
	if h["unwatched"] != true {
		t.Fatalf("created unwatched: %v", h)
	}
	c.do("PUT", "/api/v1/hosts/"+id, `{"name":"web","target":{"address":"10.0.0.6","port":80}}`)
	if i := s.mgr.State().Find(id); !s.mgr.State().Hosts[i].Unwatched {
		t.Fatal("an update without watch turned the checks back on")
	}
	c.do("PUT", "/api/v1/hosts/"+id, `{"name":"web","target":{"address":"10.0.0.6","port":80},"watch":true}`)
	if i := s.mgr.State().Find(id); s.mgr.State().Hosts[i].Unwatched {
		t.Fatal("watch:true did not turn them on")
	}
}

func TestUptimeEnabled(t *testing.T) {
	s, c, _ := setUp(t)
	if rr, out := c.do("PUT", "/api/v1/uptime/enabled", `{"enabled":false}`); rr.Code != 200 || out["enabled"] != false || !s.mgr.State().Settings.UptimeOff {
		t.Fatalf("off: %d %v", rr.Code, out)
	}
	if _, out := c.do("GET", "/api/v1/hosts/uptime", ""); out["enabled"] != false {
		t.Fatalf("the list does not say it is off: %v", out)
	}
	if rr, out := c.do("PUT", "/api/v1/uptime/enabled", `{"enabled":true}`); rr.Code != 200 || out["enabled"] != true || s.mgr.State().Settings.UptimeOff {
		t.Fatalf("on: %d %v", rr.Code, out)
	}
}
