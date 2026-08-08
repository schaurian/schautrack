package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/apierr"
	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/sse"
)

// V1Handler serves the public, token-authenticated API at /api/v1.
type V1Handler struct {
	Pool   *pgxpool.Pool
	Broker *sse.Broker

	// BuildVersion is surfaced by GET /api/v1/me so a client can report which
	// server it is talking to.
	BuildVersion string

	// BaseURL is the public root this instance is reached at (config.BaseURL,
	// i.e. the BASE_URL environment variable). It becomes the sole `servers`
	// entry of GET /api/v1/openapi.json, so that a self-hosted instance's spec
	// points clients — including Swagger UI's "Try it out", which is where a
	// bearer token gets sent — at that instance and not at schautrack.com.
	// Empty means "not configured", which yields a relative server URL that
	// clients resolve against this instance anyway.
	BaseURL string

	// spec caches the built OpenAPI document for this handler. Per-handler, not
	// package-level, so one instance's BaseURL can never be served to another.
	spec specCache

	// Barcode and AIEstimate are the app's own handlers, injected rather than
	// reimplemented so the API and the UI cannot disagree about what a barcode
	// resolves to or how an estimate is billed. Nil when the feature is
	// disabled (ENABLE_BARCODE=false) or unconfigured (no AI provider), in
	// which case the route answers 404 rather than 500.
	Barcode    http.HandlerFunc
	AIEstimate http.HandlerFunc

	// TokenLimiter throttles per API token. It is applied inside the
	// authenticated group, since the token it buckets by does not exist until
	// RequireAPIToken has run. Nil disables it, which is what the route-parity
	// test relies on to build the tree without dependencies.
	TokenLimiter *middleware.RateLimiter

	// AILimiter and BarcodeLimiter are sized to the operation, not to the API.
	// TokenLimiter guards the surface as a whole (dozens of cheap reads a
	// minute); an AI estimate spends the operator's money on every call and a
	// barcode lookup hammers a third-party database, and both are reachable
	// through the app at far lower ceilings. Without these, a token was the
	// cheapest path to the most expensive operations the server can perform.
	//
	// They compose with TokenLimiter rather than replacing it, and bucket per
	// ACCOUNT (see middleware.NewUserRateLimiter) so that minting more tokens
	// does not multiply the budget. Nil disables, as above.
	AILimiter      *middleware.RateLimiter
	BarcodeLimiter *middleware.RateLimiter

	// Auth guards everything except GET /openapi.json. Nil means
	// middleware.RequireAPIToken(pool) — the production wiring — so forgetting
	// to set it cannot leave the surface unauthenticated.
	//
	// It exists as a field because the token lookup is the one dependency in
	// the chain that needs a database, and CI has none. A test that stubs it
	// drives the REAL route table, so what runs above each handler — scopes,
	// per-token and per-operation limiters, and their order — is asserted
	// against the thing production actually serves rather than a copy of it.
	Auth func(http.Handler) http.Handler
}

// optionalLimiter returns rl's middleware, or a pass-through when rl is nil, so
// the route table can name a limiter unconditionally and still be buildable
// from a zero-value V1Handler.
func optionalLimiter(rl *middleware.RateLimiter) func(http.Handler) http.Handler {
	if rl == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return rl.Middleware
}

// MountAPIV1 builds the /api/v1 sub-router.
//
// The whole v1 route table lives in this one function, on purpose: it is the
// single artifact the OpenAPI document is checked against. TestV1RoutesMatchSpec
// walks the router this returns and fails if it and the spec disagree in either
// direction, which is what stops the documentation from drifting the way the
// hand-written docs/api-internal.md did.
//
// It is constructible with a zero-value V1Handler so that test can build the
// route tree without a database.
func (h *V1Handler) MountAPIV1(pool *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()

	// Panics are an error path like any other, so they must answer in the v1
	// error format too. The globally-mounted middleware.Recovery writes the
	// legacy {"ok": false} envelope, which would break invariant #3 at exactly
	// the moment a client most needs a machine-readable error. Recovering here
	// — inside the mount, so this runs first and the global one never sees the
	// panic — keeps the decision in the route table rather than in a path
	// prefix check somewhere else. Same reasoning as the 404/405 overrides
	// below.
	r.Use(middleware.ProblemRecovery)

	// The spec is public: a client must be able to fetch it before it has a
	// token, and it contains no user data.
	r.Get("/openapi.json", h.OpenAPI)

	auth := h.Auth
	if auth == nil {
		auth = middleware.RequireAPIToken(pool)
	}

	r.Group(func(r chi.Router) {
		r.Use(auth)
		if h.TokenLimiter != nil {
			r.Use(h.TokenLimiter.Middleware)
		}

		// GET /me needs no scope beyond a valid token — it is how a client
		// discovers which scopes it actually holds. Writing settings is a
		// different matter and is scoped.
		r.Get("/me", h.Me)
		r.With(middleware.RequireScope(service.ScopeSettingsWrite)).Patch("/me", h.UpdateMeV1)

		r.With(middleware.RequireScope(service.ScopeLinksRead)).Get("/links", h.ListLinksV1)

		// Barcode lookup is food data, so it rides on foods:read rather than
		// getting a scope of its own.
		//
		// The scope check runs BEFORE the limiter on both of the routes below:
		// a 403 costs nothing to serve, and letting a wrongly-scoped token burn
		// the account's estimate budget would let it deny service to the
		// correctly-scoped token beside it.
		r.With(middleware.RequireScope(service.ScopeFoodsRead),
			optionalLimiter(h.BarcodeLimiter)).Get("/barcode/{code}", h.BarcodeV1)

		// Its own scope, implied by nothing: every call spends real money.
		// Not idempotent and not (yet) replayable, so it says so out loud
		// rather than accepting an Idempotency-Key it would ignore.
		r.With(middleware.RequireScope(service.ScopeAIEstimate),
			optionalLimiter(h.AILimiter)).Post("/ai/estimate", rejectIdempotencyKey(h.EstimateV1))

		r.Route("/entries", func(r chi.Router) {
			r.With(middleware.RequireScope(service.ScopeEntriesRead)).Get("/", h.ListEntries)
			r.With(middleware.RequireScope(service.ScopeEntriesWrite)).Post("/", h.withIdempotency(h.CreateEntryV1))
			r.With(middleware.RequireScope(service.ScopeEntriesRead)).Get("/{id}", h.GetEntryV1)
			r.With(middleware.RequireScope(service.ScopeEntriesWrite)).Patch("/{id}", h.UpdateEntryV1)
			r.With(middleware.RequireScope(service.ScopeEntriesWrite)).Delete("/{id}", h.DeleteEntryV1)
		})

		// Weight is keyed by date, not by surrogate id: there is exactly one
		// weight per user per day (enforced by a unique index), so the date IS
		// the natural key. That makes PUT genuinely idempotent — "my scale says
		// 82.4 today" is the same statement however many times it is sent.
		r.Route("/weight", func(r chi.Router) {
			r.With(middleware.RequireScope(service.ScopeWeightRead)).Get("/", h.ListWeight)
			r.With(middleware.RequireScope(service.ScopeWeightRead)).Get("/{date}", h.GetWeightV1)
			r.With(middleware.RequireScope(service.ScopeWeightWrite)).Put("/{date}", h.PutWeightV1)
			r.With(middleware.RequireScope(service.ScopeWeightWrite)).Delete("/{date}", h.DeleteWeightV1)
		})

		r.Route("/todos", func(r chi.Router) {
			r.With(middleware.RequireScope(service.ScopeTodosRead)).Get("/", h.ListTodosV1)
			r.With(middleware.RequireScope(service.ScopeTodosWrite)).Post("/", h.withIdempotency(h.CreateTodoV1))
			r.With(middleware.RequireScope(service.ScopeTodosRead)).Get("/day/{date}", h.TodosForDayV1)
			r.With(middleware.RequireScope(service.ScopeTodosWrite)).Patch("/{id}", h.UpdateTodoV1)
			r.With(middleware.RequireScope(service.ScopeTodosWrite)).Delete("/{id}", h.DeleteTodoV1)
			r.With(middleware.RequireScope(service.ScopeTodosWrite)).Put("/{id}/completions/{date}", h.SetTodoCompletionV1)
		})

		r.Route("/saved-foods", func(r chi.Router) {
			r.With(middleware.RequireScope(service.ScopeFoodsRead)).Get("/", h.ListSavedFoodsV1)
			r.With(middleware.RequireScope(service.ScopeFoodsWrite)).Post("/", h.withIdempotency(h.CreateSavedFoodV1))
			r.With(middleware.RequireScope(service.ScopeFoodsWrite)).Patch("/{id}", h.UpdateSavedFoodV1)
			r.With(middleware.RequireScope(service.ScopeFoodsWrite)).Delete("/{id}", h.DeleteSavedFoodV1)
			// Tracking a saved food CREATES a calorie entry, so it is gated on
			// entries:write, not foods:write. Scoping it by the resource in the
			// URL rather than by the resource it mutates would let a
			// foods-only token write entries.
			r.With(middleware.RequireScope(service.ScopeEntriesWrite)).Post("/{id}/track", h.withIdempotency(h.TrackSavedFoodV1))
		})

		r.Route("/notes", func(r chi.Router) {
			r.With(middleware.RequireScope(service.ScopeNotesRead)).Get("/{date}", h.GetNoteV1)
			r.With(middleware.RequireScope(service.ScopeNotesWrite)).Put("/{date}", h.PutNoteV1)
		})

		r.With(middleware.RequireScope(service.ScopePlanRead)).Get("/plan", h.GetPlanV1)
	})

	// chi's own 404/405 render text/plain; override them so that EVERY
	// response from /api/v1 — including the ones chi generates before any
	// handler runs — is problem+json. A client can then parse errors
	// unconditionally instead of sniffing the content type.
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		apierr.Write(w, r, apierr.NotFound("No such endpoint. See GET /api/v1/openapi.json."))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		apierr.Write(w, r, apierr.New(http.StatusMethodNotAllowed, "method-not-allowed",
			"Method not allowed", "That method is not supported on this endpoint."))
	})

	return r
}
