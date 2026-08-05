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
}

// MountAPIV1 builds the /api/v1 sub-router.
//
// The whole v1 route table lives in this one function, on purpose: it is the
// single artifact the OpenAPI document is checked against. TestV1RoutesMatchSpec
// walks the router this returns and fails if it and the spec disagree in either
// direction, which is what stops the documentation from drifting the way the
// hand-written docs/api.md did.
//
// It is constructible with a zero-value V1Handler so that test can build the
// route tree without a database.
func (h *V1Handler) MountAPIV1(pool *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()

	// The spec is public: a client must be able to fetch it before it has a
	// token, and it contains no user data.
	r.Get("/openapi.json", h.OpenAPI)

	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAPIToken(pool))

		// /me needs no scope beyond a valid token — it is how a client
		// discovers which scopes it actually holds.
		r.Get("/me", h.Me)

		r.Route("/entries", func(r chi.Router) {
			r.With(middleware.RequireScope(service.ScopeEntriesRead)).Get("/", h.ListEntries)
			r.With(middleware.RequireScope(service.ScopeEntriesWrite)).Post("/", h.CreateEntryV1)
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
			r.With(middleware.RequireScope(service.ScopeTodosWrite)).Post("/", h.CreateTodoV1)
			r.With(middleware.RequireScope(service.ScopeTodosRead)).Get("/day/{date}", h.TodosForDayV1)
			r.With(middleware.RequireScope(service.ScopeTodosWrite)).Patch("/{id}", h.UpdateTodoV1)
			r.With(middleware.RequireScope(service.ScopeTodosWrite)).Delete("/{id}", h.DeleteTodoV1)
			r.With(middleware.RequireScope(service.ScopeTodosWrite)).Put("/{id}/completions/{date}", h.SetTodoCompletionV1)
		})

		r.Route("/saved-foods", func(r chi.Router) {
			r.With(middleware.RequireScope(service.ScopeFoodsRead)).Get("/", h.ListSavedFoodsV1)
			r.With(middleware.RequireScope(service.ScopeFoodsWrite)).Post("/", h.CreateSavedFoodV1)
			r.With(middleware.RequireScope(service.ScopeFoodsWrite)).Patch("/{id}", h.UpdateSavedFoodV1)
			r.With(middleware.RequireScope(service.ScopeFoodsWrite)).Delete("/{id}", h.DeleteSavedFoodV1)
			// Tracking a saved food CREATES a calorie entry, so it is gated on
			// entries:write, not foods:write. Scoping it by the resource in the
			// URL rather than by the resource it mutates would let a
			// foods-only token write entries.
			r.With(middleware.RequireScope(service.ScopeEntriesWrite)).Post("/{id}/track", h.TrackSavedFoodV1)
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
