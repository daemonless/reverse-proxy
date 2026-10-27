package server

import (
	_ "embed"
	"net/http"
)

// openAPISpec describes the v1 hosts API: what a connected app, a script
// or another manager may rely on. The UI's own calls are not in it.
//
//go:embed openapi.json
var openAPISpec []byte

func openAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(openAPISpec)
}
