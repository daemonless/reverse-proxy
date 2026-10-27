package main

import (
	"strings"
	"testing"
)

func TestSetupText(t *testing.T) {
	known := setupText("Password cleared. Set up again", "https://192.168.1.5:8444", "WXFV-FVUW-3JVG-FUE7")
	t.Logf("\n%s", known)
	if !strings.Contains(known, "    https://192.168.1.5:8444/#token=WXFV-FVUW-3JVG-FUE7\n") || strings.Contains(known, "RP_ADMIN_URL") || strings.Contains(known, "<") {
		t.Fatalf("known address:\n%s", known)
	}
	unknown := setupText("First run. Set up", "", "WXFV-FVUW-3JVG-FUE7")
	t.Logf("\n%s", unknown)
	if !strings.Contains(unknown, "port 8443 of this machine") || !strings.Contains(unknown, adminPlace+"/#token=") || !strings.Contains(unknown, "RP_ADMIN_URL") {
		t.Fatalf("unknown address:\n%s", unknown)
	}
}
