package handler

import (
	"net/http"
	"sync"

	"schautrack/internal/apierr"
	"schautrack/internal/openapi"
)

// specCache memoizes the built document. It is a field on V1Handler rather than
// a package-level var so the cached bytes belong to one handler — and therefore
// to one BaseURL. A process-wide cache would let the first handler to serve the
// spec fix the `servers` URL for every other handler in the process, which is
// exactly the host-leak this endpoint must not have.
//
// Must not be copied once used; V1Handler is always held by pointer, and
// `go vet`'s copylocks check enforces the rest.
type specCache struct {
	once  sync.Once
	bytes []byte
	err   error
}

// OpenAPI handles GET /api/v1/openapi.json.
//
// Unauthenticated on purpose: a client must be able to read the contract before
// it holds a token, and the document describes only the API's shape, never any
// user's data.
//
// The document is identical for every caller of this instance and costs a few
// hundred allocations to build, so it is built once and reused. It is keyed to
// nothing request-derived: the `servers` entry comes from h.BaseURL, fixed at
// startup, so no caller's Host header can influence what a later caller reads.
func (h *V1Handler) OpenAPI(w http.ResponseWriter, r *http.Request) {
	h.spec.once.Do(func() {
		h.spec.bytes, h.spec.err = openapi.Build(h.BuildVersion, h.BaseURL).JSON()
	})
	if h.spec.err != nil {
		apierr.Write(w, r, dbFail("build openapi document", h.spec.err))
		return
	}

	// application/openapi+json is the registered media type; the vnd suffix
	// tells tooling the version without having to parse the body.
	w.Header().Set("Content-Type", "application/openapi+json;version=3.1")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(h.spec.bytes)
}
