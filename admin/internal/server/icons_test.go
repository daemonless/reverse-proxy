package server

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const svgIcon = `<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><rect width="8" height="8"/></svg>`

// fjord sends the app's icon after it makes the name; the Names page shows it.
func TestHostIcon(t *testing.T) {
	s, c, key := setUp(t)
	api := &client{t: t, s: s, bearer: key}
	_, h := api.do("POST", "/api/v1/hosts", `{"name":"radarr","target":{"address":"192.168.1.20","port":7878},"ref":"fjord:x:radarr"}`)
	id := h["id"].(string)
	if h["icon"] != nil {
		t.Fatalf("a new host has an icon: %v", h)
	}
	if rr, _ := api.do("PUT", "/api/v1/hosts/"+id+"/icon", "#!/bin/sh\necho hi\n"); rr.Code != 415 {
		t.Fatalf("not an image: %d", rr.Code)
	}
	if rr, _ := api.do("PUT", "/api/v1/hosts/"+id+"/icon", "<svg"+strings.Repeat(" ", maxIcon)+"/>"); rr.Code != 413 {
		t.Fatalf("too big: %d", rr.Code)
	}
	rr, out := api.do("PUT", "/api/v1/hosts/"+id+"/icon", svgIcon)
	icon, _ := out["icon"].(string)
	if rr.Code != 200 || !strings.HasSuffix(icon, ".svg") {
		t.Fatalf("icon: %d %v", rr.Code, out)
	}
	// An edit of the host (fjord's rename sends the editable fields) keeps it.
	if _, out = api.do("PUT", "/api/v1/hosts/"+id, `{"name":"movies","target":{"address":"192.168.1.20","port":7878},"ref":"fjord:x:radarr"}`); out["icon"] != icon {
		t.Fatalf("after an edit: %v", out)
	}
	rr, _ = c.do("GET", "/api/v1/hosts/"+id+"/icon", "")
	if rr.Code != 200 || rr.Body.String() != svgIcon || rr.Header().Get("Content-Type") != "image/svg+xml" ||
		!strings.Contains(rr.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("served: %d %v", rr.Code, rr.Header())
	}
	if rr, _ := (&client{t: t, s: s}).do("GET", "/api/v1/hosts/"+id+"/icon", ""); rr.Code != 401 {
		t.Fatalf("signed out: %d", rr.Code)
	}

	// A PNG replaces it, and the SVG file goes.
	png := "\x89PNG\r\n\x1a\n" + strings.Repeat("\x00", 32)
	if _, out = api.do("PUT", "/api/v1/hosts/"+id+"/icon", png); !strings.HasSuffix(out["icon"].(string), ".png") {
		t.Fatalf("png: %v", out)
	}
	files, _ := os.ReadDir(s.iconDir())
	if len(files) != 1 || files[0].Name() != id+".png" {
		t.Fatalf("files: %v", files)
	}
	// A backup holds state.json, not the icons: restored without the file,
	// the host forgets it, so fjord sends it again.
	os.Remove(s.iconFile(s.mgr.State().Hosts[0]))
	st := s.mgr.State().Clone()
	if !s.fitIcons(st) || st.Hosts[0].Icon != "" {
		t.Fatalf("restored without the file: %v", st.Hosts[0])
	}
}

// fjord sends every app's icon at once when it starts: none may be lost.
func TestIconsSentAtOnce(t *testing.T) {
	s, _, key := setUp(t)
	api := &client{t: t, s: s, bearer: key}
	var ids []string
	for i := range 12 {
		_, h := api.do("POST", "/api/v1/hosts", `{"name":"app`+strconv.Itoa(i)+`","target":{"address":"192.168.1.20","port":80}}`)
		ids = append(ids, h["id"].(string))
	}
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			(&client{t: t, s: s, bearer: key}).do("PUT", "/api/v1/hosts/"+id+"/icon", strings.Replace(svgIcon, "8", strconv.Itoa(i+1), 1))
		}()
	}
	wg.Wait()
	for _, h := range s.mgr.State().Hosts {
		if _, err := os.Stat(s.iconFile(h)); h.Icon == "" || err != nil {
			t.Errorf("%s: icon %q, file %v", h.Name, h.Icon, err)
		}
	}
	// One lost anyway (an older build's race): forgotten at the next start,
	// so fjord sends it again.
	os.Remove(s.iconFile(s.mgr.State().Hosts[0]))
	again := New("test", upRunner{}, s.mgr, "", s.secrets)
	if h := again.mgr.State().Hosts[0]; h.Icon != "" {
		t.Fatalf("lost icon still named: %v", h.Icon)
	}
}
