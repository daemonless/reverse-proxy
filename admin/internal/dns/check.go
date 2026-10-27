package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// cloudflareAPI is a variable so tests can point it at a fake.
var cloudflareAPI = "https://api.cloudflare.com/client/v4"

// Check asks the provider, before any certificate is tried, whether the
// credentials can reach zone's DNS. A wrong token then fails in a second
// with what to fix, not a minute later inside the trial. Providers without
// a check, and a provider that cannot be reached, return nil: the trial
// still tells.
func Check(ctx context.Context, c *Config, zone string) error {
	switch c.Provider {
	case "cloudflare":
		return checkCloudflare(ctx, c.Fields["api_token"], zone)
	}
	return nil
}

// Problem kinds: only the person can fix these.
const (
	KindRejected   = "rejected"   // the provider refuses the credentials
	KindZone       = "zone"       // they work, but not for this zone
	KindPermission = "permission" // the zone, but not its records
)

// Problem is a check's answer the person must act on. It unwraps to the
// form's field error, which setup shows under the token field.
type Problem struct {
	Kind string
	*state.FieldError
}

func (p *Problem) Unwrap() error { return p.FieldError }

func checkCloudflare(ctx context.Context, token, zone string) error {
	problem := func(kind, msg string) error {
		return &Problem{Kind: kind, FieldError: &state.FieldError{Field: "api_token", Msg: msg}}
	}
	get := func(path string, out any) (int, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareAPI+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}

	// Zones the token can see: any kind of token (profile or account) can
	// ask, unlike /user/tokens/verify.
	var zones struct {
		Result []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	code, err := get("/zones?name="+url.QueryEscape(zone), &zones)
	switch {
	case err != nil && code == 0:
		log.Printf("[admin] certificates: could not ask Cloudflare about the token (%v); the test certificate will tell", err)
		return nil
	case code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusBadRequest:
		return problem(KindRejected, "Cloudflare doesn't accept this token. Copy it again; Cloudflare shows it only once, so you may need to make a new one.")
	case code/100 != 2:
		log.Printf("[admin] certificates: Cloudflare answered %d about the token; the test certificate will tell", code)
		return nil
	case len(zones.Result) == 0:
		return problem(KindZone, fmt.Sprintf("The token works, but it can't see %s. In Cloudflare, edit the token and choose %s under Zone Resources.", zone, zone))
	}

	// The template's permission is DNS Edit, which includes reading.
	var recs struct{}
	code, err = get("/zones/"+url.PathEscape(zones.Result[0].ID)+"/dns_records?per_page=1", &recs)
	switch {
	case err != nil && code == 0:
		return nil
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return problem(KindPermission, fmt.Sprintf("The token can see %s but not its DNS records. Make it with the Edit zone DNS template.", zone))
	}
	return nil
}
