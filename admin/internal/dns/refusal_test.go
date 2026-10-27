package dns

import (
	"errors"
	"testing"
)

func TestRefusalUntilTheCredentialsChange(t *testing.T) {
	var r Refusal
	bad := &Config{Provider: "cloudflare", Fields: map[string]string{"api_token": "x"}}
	if r.Refused(bad) != "" {
		t.Fatal("nothing refused yet")
	}
	r.Set(bad, errors.New("API token 'x' appears invalid"))
	same := &Config{Provider: "cloudflare", Fields: map[string]string{"api_token": "x"}}
	if r.Refused(same) == "" {
		t.Fatal("the same credentials, loaded again, must stay refused")
	}
	if r.Refused(&Config{Provider: "cloudflare", Fields: map[string]string{"api_token": "y"}}) != "" {
		t.Fatal("a new token must be tried")
	}
	if r.Refused(nil) != "" {
		t.Fatal("no credentials, nothing refused")
	}
}
