package handler

import (
	"net/http"
	"sync"

	"schautrack/internal/apierr"
	"schautrack/internal/openapi"
)

// The document is identical for every caller and costs a few hundred
// allocations to build, so it is built once and reused. sync.Once rather than
// package init so a build-version-dependent document is still possible.
var (
	specOnce  sync.Once
	specBytes []byte
	specErr   error
)

// OpenAPI handles GET /api/v1/openapi.json.
//
// Unauthenticated on purpose: a client must be able to read the contract before
// it holds a token, and the document describes only the API's shape, never any
// user's data.
func (h *V1Handler) OpenAPI(w http.ResponseWriter, r *http.Request) {
	specOnce.Do(func() {
		specBytes, specErr = openapi.Build(h.BuildVersion).JSON()
	})
	if specErr != nil {
		apierr.Write(w, r, dbFail("build openapi document", specErr))
		return
	}

	// application/openapi+json is the registered media type; the vnd suffix
	// tells tooling the version without having to parse the body.
	w.Header().Set("Content-Type", "application/openapi+json;version=3.1")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(specBytes)
}
