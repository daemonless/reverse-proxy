// Package ui embeds the built Svelte app. `npm run build` in this directory
// fills dist/; the image build does the same in its node stage.
package ui

import "embed"

//go:embed all:dist
var Files embed.FS
