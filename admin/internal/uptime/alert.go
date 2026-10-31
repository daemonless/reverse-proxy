package uptime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Alert kinds: ntfy gets a title and text it shows as is; webhook gets JSON.
const (
	KindNtfy    = "ntfy"
	KindWebhook = "webhook"
)

// Text is the message for e, as a title and a line.
func (e Event) Text() (title, body string) {
	if e.Example {
		return "Test from the proxy", "Alerts work: you'll get a message like this when a name stops responding, and again when it's back."
	}
	if e.Down {
		return e.Name + " is down", fmt.Sprintf("%s is not responding at %s.", e.Name, e.Where)
	}
	return e.Name + " is back", fmt.Sprintf("%s is responding again, after %s.", e.Name, Duration(e.Lasted))
}

// Duration says d the way a person would: 40 s, 12 min, 3 h 5 min, 2 days.
func Duration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		h, m := int(d.Hours()), int(d.Minutes())%60
		if m == 0 {
			return fmt.Sprintf("%d h", h)
		}
		return fmt.Sprintf("%d h %d min", h, m)
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// Send delivers e to url as kind.
func Send(ctx context.Context, kind, url string, e Event) error {
	title, body := e.Text()
	var req *http.Request
	var err error
	switch kind {
	case KindNtfy:
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Title", title)
		switch {
		case e.Example:
			req.Header.Set("Tags", "bell")
		case e.Down:
			req.Header.Set("Tags", "rotating_light")
			req.Header.Set("Priority", "high")
		default:
			req.Header.Set("Tags", "white_check_mark")
		}
	case KindWebhook:
		state := "up"
		if e.Down {
			state = "down"
		}
		if e.Example {
			state = "test"
		}
		payload := map[string]any{"state": state, "title": title, "message": body}
		if e.Name != "" {
			payload["name"], payload["url"], payload["target"] = e.Name, "https://"+e.Name, e.Where
		}
		if !e.Since.IsZero() {
			payload["since"] = e.Since.UTC().Format(time.RFC3339)
		}
		if e.Lasted > 0 {
			payload["downSeconds"] = int(e.Lasted.Seconds())
		}
		data, _ := json.Marshal(payload)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
	default:
		return fmt.Errorf("unknown alert kind %q", kind)
	}
	req.Header.Set("User-Agent", "reverse-proxy")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("%s answered %s %s", req.URL.Host, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
