package main

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-webauthn/webauthn/webauthn"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/handler"
	"schautrack/internal/middleware"
	"schautrack/internal/release"
	"schautrack/internal/service"
	"schautrack/internal/session"
	"schautrack/internal/sse"
)

// Set via -ldflags at build time.
var version = "dev"

func main() {
	// Structured logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}
	cfg.BuildVersion = version

	// Graceful shutdown context via signal.NotifyContext
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Database
	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Migrations. A broken/partial schema makes every query 500 while
	// /api/health only pings the DB, so probes stay green and RollingUpdate
	// (maxUnavailable:0) would swap a healthy pod for a broken one. Fail fast so
	// the old healthy pod keeps serving.
	if err := database.InitSchemaWithRetry(ctx, pool, 10); err != nil {
		slog.Error("schema init failed after all retries; aborting startup", "error", err)
		os.Exit(1)
	}

	// Services
	settingsCache := database.NewSettingsCache(pool)
	sessionStore := session.NewStore(pool, cfg.SessionSecret)
	emailService := service.NewEmailService(cfg)
	authLimiter := middleware.NewRateLimiter(cfg.RateLimitAuth, 15*time.Minute, cfg.TrustProxy)
	strictLimiter := middleware.NewRateLimiter(cfg.RateLimitStrict, 5*time.Minute, cfg.TrustProxy)
	barcodeLimiter := middleware.NewRateLimiter(30, time.Minute, cfg.TrustProxy)

	// SSE broker. Events are fanned out through Postgres LISTEN/NOTIFY so they
	// reach subscribers held by *other* instances: with more than one replica
	// behind a load balancer, a user's stream and the write that should update
	// it routinely land on different pods.
	sseBroker := sse.NewBroker(pool)
	go sseBroker.Listen(ctx, cfg.DatabaseURL)

	// Auth handler
	authHandler := &handler.AuthHandler{
		Pool:         pool,
		SessionStore: sessionStore,
		Email:        emailService,
		Cfg:          cfg,
		Settings:     settingsCache,
	}

	// OIDC handler
	var oidcHandler *handler.OIDCHandler
	if cfg.OIDCEnabled() {
		var err error
		oidcHandler, err = handler.NewOIDCHandler(ctx, pool, cfg, settingsCache, sessionStore)
		if err != nil {
			slog.Warn("OIDC init failed", "error", err)
		}
	}

	// Passkey handler
	var passkeyHandler *handler.PasskeyHandler
	stepUpHandler := &handler.StepUpHandler{Pool: pool, SessionStore: sessionStore, TrustProxy: cfg.TrustProxy}
	if cfg.PasskeysEnabled() {
		origins := cfg.PasskeysRPOrigins
		if len(origins) == 0 {
			origins = []string{"https://" + cfg.PasskeysRPID}
		}
		wauthn, err := webauthn.New(&webauthn.Config{
			RPID:          cfg.PasskeysRPID,
			RPDisplayName: cfg.PasskeysRPName,
			RPOrigins:     origins,
		})
		if err != nil {
			slog.Error("WebAuthn init failed", "error", err)
		} else {
			passkeyHandler = &handler.PasskeyHandler{Pool: pool, WebAuthn: wauthn, SessionStore: sessionStore, TrustProxy: cfg.TrustProxy}
			stepUpHandler.WebAuthn = wauthn
		}
	}

	// Release source for the update check + "Report an Issue" links. A bad
	// UPDATE_PROVIDER/UPDATE_REPO must never break startup — fall back to the
	// public GitHub repo and log it.
	updateProvider, err := release.New(cfg.UpdateProvider, cfg.UpdateRepo, cfg.UpdateBaseURL)
	if err != nil {
		slog.Error("invalid release source config; falling back to github", "error", err)
		updateProvider, _ = release.New("github", "schaurian/schautrack", "")
	}

	// Router
	r := chi.NewRouter()
	// AccessLog is outermost so it observes the final committed status (including
	// Recovery's 500s) and emits one structured request log — the only source of
	// request rates, latencies and error counts this deployment has.
	r.Use(middleware.AccessLog(cfg.TrustProxy))
	r.Use(middleware.Recovery)
	r.Use(middleware.MaxBodySize(15 << 20)) // 15MB global limit
	r.Use(middleware.SecurityHeaders)
	// Static asset requests (Vite build output, favicons, logos, fonts) never
	// read the session or the current user, so skip the session load + full
	// 19-column users SELECT for them — a single page load fans out to ~a dozen
	// such requests. Authenticated /api/ and /events/ routes are never
	// classified static and keep the full session + user pipeline.
	r.Use(middleware.SkipStaticAssets(session.Middleware(sessionStore)))
	r.Use(middleware.SkipStaticAssets(middleware.AttachUser(pool)))
	r.Use(middleware.RememberClientTimezone)

	// SEO routes
	r.Get("/robots.txt", handler.RobotsTxt(cfg))
	r.Get("/sitemap.xml", handler.SitemapXml(cfg))

	// Android App Links (Digital Asset Links). 404s until a signing-cert
	// fingerprint is configured (ANDROID_CERT_FINGERPRINTS).
	r.Get("/.well-known/assetlinks.json", handler.AssetLinks(cfg))

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", handler.Health(pool, cfg.BuildVersion))
		r.Get("/latest-version", handler.LatestVersion(updateProvider, cfg.UpdateCheckEnabled))
		r.Get("/csrf", handler.CsrfToken)
		r.Get("/me", handler.Me(pool, cfg.AdminEmail, settingsCache, cfg))

		// Registration info (public)
		r.Get("/auth/registration-info", handler.RegistrationInfo(settingsCache, cfg))

		// Auth routes
		r.With(authLimiter.Middleware, session.CsrfProtection).Post("/auth/login", authHandler.Login)
		r.With(authLimiter.Middleware, session.CsrfProtection).Post("/auth/register", authHandler.Register)
		r.With(middleware.RequireLogin, session.CsrfProtection).Post("/auth/logout", authHandler.Logout)
		r.With(strictLimiter.Middleware, session.CsrfProtection).Post("/auth/forgot-password", authHandler.ForgotPassword)
		r.With(strictLimiter.Middleware, session.CsrfProtection).Post("/auth/reset-password", authHandler.ResetPassword)
		r.With(session.CsrfProtection).Post("/auth/verify-email", authHandler.VerifyEmail)
		r.With(session.CsrfProtection).Post("/auth/verify-email/resend", authHandler.VerifyEmailResend)
		r.Get("/auth/captcha", authHandler.Captcha)
		r.With(strictLimiter.Middleware, session.CsrfProtection).Post("/auth/reset-2fa", authHandler.Reset2FA)
		r.Get("/auth/info", handler.AuthInfo(cfg))

		// Step-up (sudo mode) — elevates the session for sensitive auth-method
		// changes. Rate-limited to slow brute-forcing the password+TOTP path.
		r.With(authLimiter.Middleware, middleware.RequireLogin, session.CsrfProtection).Post("/auth/step-up", stepUpHandler.PasswordTOTP)
		if passkeyHandler != nil {
			// Rate-limited for symmetry with the password path. Brute-forcing a
			// passkey assertion is cryptographically infeasible, but the limiter
			// also protects against burst /begin spam that would churn server-side
			// challenges.
			r.With(authLimiter.Middleware, middleware.RequireLogin, session.CsrfProtection).Post("/auth/step-up/passkey/begin", stepUpHandler.PasskeyBegin)
			r.With(authLimiter.Middleware, middleware.RequireLogin, session.CsrfProtection).Post("/auth/step-up/passkey/finish", stepUpHandler.PasskeyFinish)
		}

		// Settings (requires login)
		r.With(middleware.RequireLogin).Get("/settings", handler.Settings(pool, cfg.AdminEmail, settingsCache, cfg))

		// Admin (requires admin)
		r.With(middleware.RequireLogin, middleware.RequireAdmin(cfg.AdminEmail)).Get("/admin", handler.AdminData(pool, settingsCache, cfg.AdminEmail))
	})

	// stepUp gates routes that change auth methods. The middleware short-circuits
	// with 403 + a structured body when the session lacks fresh primary auth;
	// the client renders a step-up modal and retries on success.
	stepUp := middleware.RequireStepUp(pool)

	// OIDC routes
	if oidcHandler != nil {
		r.Get("/auth/oidc/login", oidcHandler.Login)
		r.Get("/auth/oidc/callback", oidcHandler.Callback)
		// Step-up via OIDC re-auth — only path that doesn't need RequireLocalAuth
		// because it's literally for users whose only auth method is OIDC.
		r.With(middleware.RequireLogin).Get("/auth/oidc/step-up", oidcHandler.StepUpInit)
		r.With(middleware.RequireLogin, middleware.RequireLocalAuth, stepUp, session.CsrfProtection).Post("/settings/oidc/unlink", oidcHandler.Unlink)
	}

	// Passkey routes
	if passkeyHandler != nil {
		r.Post("/passkeys/login/begin", passkeyHandler.LoginBegin)
		r.Post("/passkeys/login/finish", passkeyHandler.LoginFinish)
		// Only /begin needs step-up. /finish is authenticated by the signed
		// WebAuthn challenge issued from the session in /begin — no additional
		// re-prompt required, and skipping it avoids a second modal when the
		// user takes longer than the grace window to complete the platform's
		// passkey ceremony.
		r.With(middleware.RequireLogin, middleware.RequireLocalAuth, stepUp, session.CsrfProtection).Post("/passkeys/register/begin", passkeyHandler.RegisterBegin)
		r.With(middleware.RequireLogin, middleware.RequireLocalAuth, session.CsrfProtection).Post("/passkeys/register/finish", passkeyHandler.RegisterFinish)
		r.With(middleware.RequireLogin, middleware.RequireLocalAuth, stepUp, session.CsrfProtection).Post("/passkeys/delete", passkeyHandler.Delete)
		r.With(middleware.RequireLogin, middleware.RequireLocalAuth, session.CsrfProtection).Post("/passkeys/rename", passkeyHandler.Rename)
		r.With(middleware.RequireLogin).Get("/passkeys/list", passkeyHandler.List)
	}

	// Non-API authenticated routes
	r.With(middleware.RequireLogin, stepUp, session.CsrfProtection).Post("/delete", authHandler.DeleteAccount)

	// Email change routes
	r.With(strictLimiter.Middleware, middleware.RequireLogin, middleware.RequireLocalAuth, stepUp, session.CsrfProtection).Post("/settings/email/request", authHandler.EmailChangeRequest)
	r.With(middleware.RequireLogin, middleware.RequireLocalAuth, session.CsrfProtection).Post("/settings/email/verify", authHandler.EmailChangeVerify)
	r.With(middleware.RequireLogin, middleware.RequireLocalAuth, session.CsrfProtection).Post("/settings/email/cancel", authHandler.EmailChangeCancel)

	// Entry routes
	entriesHandler := &handler.EntriesHandler{Pool: pool, Broker: sseBroker, Cfg: cfg, Settings: settingsCache}
	r.With(middleware.RequireLogin).Get("/api/dashboard", entriesHandler.Dashboard)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareNutrition)).Get("/overview", entriesHandler.Overview)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareNutrition)).Get("/entries/day", entriesHandler.DayEntries)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/entries", entriesHandler.CreateEntry)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/entries/{id}/update", entriesHandler.UpdateEntry)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/entries/{id}/delete", entriesHandler.DeleteEntry)
	// Export and import both move whole-account data — gate them with step-up.
	r.With(middleware.RequireLogin, stepUp, session.CsrfProtection).Post("/settings/export", entriesHandler.Export)
	r.With(middleware.RequireLogin, stepUp, session.CsrfProtection).Post("/settings/import", entriesHandler.Import)

	// Weight routes
	weightHandler := &handler.WeightHandler{Pool: pool, Broker: sseBroker}
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareWeight)).Get("/weight/day", weightHandler.WeightDay)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/weight/upsert", weightHandler.WeightUpsert)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/weight/{id}/delete", weightHandler.WeightDelete)

	// Plan routes (weight-loss planner)
	planHandler := &handler.PlanHandler{Pool: pool, Broker: sseBroker}
	r.With(middleware.RequireLogin).Get("/api/plan", planHandler.Get)
	r.With(middleware.RequireLogin, session.CsrfProtection).Put("/api/plan/metrics", planHandler.UpdateMetrics)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/plan/metrics/clear", planHandler.ClearMetrics)
	r.With(middleware.RequireLogin, session.CsrfProtection).Put("/api/plan/goal", planHandler.UpsertGoal)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/plan/goal/apply-budget", planHandler.ApplyBudget)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/plan/goal/abandon", planHandler.AbandonGoal)

	// Settings routes
	settingsHandler := &handler.SettingsHandler{Pool: pool, Broker: sseBroker, AIKeyEncryptSecret: cfg.AIKeyEncryptSecret, TrustProxy: cfg.TrustProxy}
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/preferences", settingsHandler.Preferences)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/macros", settingsHandler.Macros)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/ai", settingsHandler.AISettings)
	r.With(middleware.RequireLogin, middleware.RequireLocalAuth, stepUp, session.CsrfProtection).Post("/settings/password", settingsHandler.Password)
	r.With(middleware.RequireLogin, middleware.RequireLocalAuth, session.CsrfProtection).Post("/2fa/setup", settingsHandler.TwoFactorSetup)
	r.With(middleware.RequireLogin, middleware.RequireLocalAuth, session.CsrfProtection).Post("/2fa/cancel", settingsHandler.TwoFactorCancel)
	r.With(middleware.RequireLogin, middleware.RequireLocalAuth, stepUp, session.CsrfProtection).Post("/2fa/enable", settingsHandler.TwoFactorEnable)
	r.With(middleware.RequireLogin, middleware.RequireLocalAuth, stepUp, session.CsrfProtection).Post("/2fa/disable", settingsHandler.TwoFactorDisable)
	r.With(middleware.RequireLogin, middleware.RequireLocalAuth, stepUp, session.CsrfProtection).Post("/2fa/backup-codes", settingsHandler.RegenerateBackupCodes)

	// Link routes
	linksHandler := &handler.LinksHandler{Pool: pool, Broker: sseBroker}
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/link/request", linksHandler.LinkRequest)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/link/respond", linksHandler.LinkRespond)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/link/remove", linksHandler.LinkRemove)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/links/{id}/label", linksHandler.LinkLabel)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/links/{id}/shares", linksHandler.SetShares)

	// SSE endpoint
	r.With(middleware.RequireLogin).Get("/events/entries", func(w http.ResponseWriter, r *http.Request) {
		user := middleware.GetCurrentUser(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "sseUserID", user.ID)
		sseBroker.ServeHTTP(w, r.WithContext(ctx))
	})

	// Todo routes
	todosHandler := &handler.TodosHandler{Pool: pool, Broker: sseBroker}
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/todos/toggle-enabled", todosHandler.ToggleEnabled)
	r.With(middleware.RequireLogin).Get("/api/todos", todosHandler.List)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/todos", todosHandler.Create)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/todos/{id}/update", todosHandler.Update)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/todos/{id}/delete", todosHandler.Delete)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareTodos)).Get("/api/todos/day", todosHandler.DayTodos)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/todos/{id}/toggle", todosHandler.Toggle)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/todos/reorder", todosHandler.Reorder)

	// Saved foods routes
	savedFoodsHandler := &handler.SavedFoodsHandler{Pool: pool, Broker: sseBroker}
	r.With(middleware.RequireLogin).Get("/api/saved-foods", savedFoodsHandler.List)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/saved-foods", savedFoodsHandler.Create)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/saved-foods/{id}/update", savedFoodsHandler.Update)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/saved-foods/{id}/delete", savedFoodsHandler.Delete)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/saved-foods/{id}/track", savedFoodsHandler.Track)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/entries/{id}/save-as-food", savedFoodsHandler.SaveFromEntry)

	// Notes routes
	notesHandler := &handler.NotesHandler{Pool: pool, Broker: sseBroker}
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/notes/toggle-enabled", notesHandler.ToggleEnabled)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareNotes)).Get("/api/notes/day", notesHandler.Get)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/notes", notesHandler.Save)

	// Welcome tour
	onboardingHandler := &handler.OnboardingHandler{Pool: pool}
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/onboarding/complete", onboardingHandler.Complete)

	// AI estimation
	aiHandler := &handler.AIHandler{Pool: pool, Cfg: cfg, Settings: settingsCache}
	r.With(strictLimiter.Middleware, middleware.RequireLogin).Post("/api/ai/estimate", aiHandler.Estimate)

	// Personal access token management. Session-authenticated, NOT part of
	// /api/v1: a token must never be able to mint another token, or one leaked
	// read-only token could be escalated into a permanent full-scope one.
	// Minting is step-up gated like every other credential change; revoking
	// deliberately is not, so the kill switch is always one click away.
	apiTokensHandler := &handler.APITokensHandler{Pool: pool, TrustProxy: cfg.TrustProxy}
	r.With(middleware.RequireLogin).Get("/api/tokens", apiTokensHandler.List)
	r.With(middleware.RequireLogin, stepUp, session.CsrfProtection).Post("/api/tokens", apiTokensHandler.Create)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/tokens/{id}/delete", apiTokensHandler.Revoke)

	// Public API v1 — bearer-token authenticated, RFC 9457 errors, described by
	// GET /api/v1/openapi.json. Mounted as a self-contained sub-router so the
	// whole surface has exactly one definition (see handler.MountAPIV1), which
	// is what the route-parity test checks the OpenAPI document against.
	//
	// apiV1Limiter is per-IP and separate from the auth limiters: API clients
	// make far more requests than a login form, but still need a ceiling.
	// Two limiters, deliberately. The per-IP one is the outer guard: it is the
	// only thing that can throttle an unauthenticated flood, since there is no
	// token to bucket by until the request has been authenticated. The
	// per-token one sits inside the sub-router, below RequireAPIToken, and is
	// the limit that actually matters for a legitimate client — everyone behind
	// one CGNAT would otherwise share a single bucket.
	// The barcode and AI handlers are the app's own, injected rather than
	// reimplemented: one lookup path, one billing path, no chance of the API
	// and the UI disagreeing. Left nil when the feature is off, which makes the
	// v1 route answer 404 instead of 500.
	var v1Barcode http.HandlerFunc
	if cfg.EnableBarcode {
		v1Barcode = handler.Barcode(cfg)
	}
	v1Handler := &handler.V1Handler{
		Pool:         pool,
		Broker:       sseBroker,
		BuildVersion: cfg.BuildVersion,
		Barcode:      v1Barcode,
		AIEstimate:   aiHandler.Estimate,
		TokenLimiter: middleware.NewTokenRateLimiter(cfg.RateLimitAPIToken, time.Minute, cfg.TrustProxy),
	}
	apiV1IPLimiter := middleware.NewProblemRateLimiter(cfg.RateLimitAPI, time.Minute, cfg.TrustProxy)
	r.With(apiV1IPLimiter.Middleware).Mount("/api/v1", v1Handler.MountAPIV1(pool))

	// Barcode
	if cfg.EnableBarcode {
		r.With(middleware.RequireLogin, barcodeLimiter.Middleware).Get("/api/barcode/{code}", handler.Barcode(cfg))
	}

	// Admin routes
	adminHandler := &handler.AdminHandler{Pool: pool, Settings: settingsCache, Cfg: cfg, Email: emailService}
	r.With(middleware.RequireLogin, middleware.RequireAdmin(cfg.AdminEmail), session.CsrfProtection).Post("/admin/settings", adminHandler.UpdateSettings)
	r.With(middleware.RequireLogin, middleware.RequireAdmin(cfg.AdminEmail), session.CsrfProtection).Post("/admin/users/{id}/delete", adminHandler.DeleteUser)
	r.With(middleware.RequireLogin, middleware.RequireAdmin(cfg.AdminEmail), session.CsrfProtection).Post("/admin/invites", adminHandler.CreateInvite)
	r.With(middleware.RequireLogin, middleware.RequireAdmin(cfg.AdminEmail)).Get("/admin/invites", adminHandler.ListInvites)
	r.With(middleware.RequireLogin, middleware.RequireAdmin(cfg.AdminEmail), session.CsrfProtection).Post("/admin/invites/{id}/delete", adminHandler.DeleteInvite)

	// Legal imprint SVGs
	r.Get("/imprint/address.svg", handler.ImprintAddressSVG(settingsCache))
	r.Get("/imprint/email.svg", handler.ImprintEmailSVG(settingsCache))

	// Periodic cleanup
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				handler.CleanExpiredTokens(pool)
				handler.CleanExpiredIdempotencyKeys(pool)
			}
		}
	}()

	// SPA fallback — serve React client and public assets (must be last)
	clientDist := "client/dist"
	if info, err := os.Stat(clientDist); err == nil && info.IsDir() {
		spaHandler := spaFallback(clientDist, "public")
		// gzip/deflate the static bundle: the main JS chunk ships ~192 KB
		// instead of ~667 KB. Scoped to the file server only — chi's Compress
		// picks encodings off Accept-Encoding and gates on the response
		// Content-Type. Called with no explicit type list so it uses chi's
		// defaults, which cover text/html, text/css, text/javascript (Go's mime
		// type for .js), application/json and image/svg+xml. It never wraps the
		// streaming SSE handler, which is registered as its own /events/ route.
		r.Handle("/*", chimw.Compress(5)(spaHandler))
	}

	// Start server with BaseContext for clean shutdown propagation
	srv := &http.Server{
		Addr:        ":" + cfg.Port,
		Handler:     r,
		ReadTimeout: 15 * time.Second,
		// Absolute per-response write deadline for slow-loris protection. The
		// SSE handler clears this deadline for its own connection (via
		// http.ResponseController) so long-lived streams are not force-closed.
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	go func() {
		slog.Info("server started", "port", cfg.Port, "version", cfg.BuildVersion)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	stop()
	slog.Info("shutting down gracefully")
	handler.MarkShuttingDown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}

	pool.Close()
	slog.Info("shutdown complete")
}

// spaFallback serves static files from the client dist directory and public directory,
// falling back to index.html for SPA routing.
func spaFallback(clientDir, publicDir string) http.Handler {
	clientFS := os.DirFS(clientDir)
	clientFileServer := http.FileServer(http.FS(clientFS))

	var publicFS fs.FS
	if info, err := os.Stat(publicDir); err == nil && info.IsDir() {
		publicFS = os.DirFS(publicDir)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/events/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		// Check public/ directory first (logos, favicons)
		if publicFS != nil {
			if _, err := fs.Stat(publicFS, path); err == nil {
				w.Header().Set("Cache-Control", "public, max-age=604800")
				http.ServeFile(w, r, filepath.Join(publicDir, path))
				return
			}
		}

		// Check client/dist/ (built React assets)
		if _, err := fs.Stat(clientFS, path); err == nil {
			if strings.HasPrefix(path, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
			} else if path == "index.html" {
				w.Header().Set("Cache-Control", "no-cache")
			}
			clientFileServer.ServeHTTP(w, r)
			return
		}

		// A build asset that isn't here is gone, not a client route. Falling back
		// to index.html would answer a dynamic import with HTML and a 200, which
		// the browser reports as "Failed to fetch dynamically imported module" —
		// the real cause (a tab holding an index.html from a previous deploy that
		// references a since-replaced chunk) stays invisible. 404 says so plainly
		// and lets the client recover.
		if strings.HasPrefix(path, "assets/") {
			http.NotFound(w, r)
			return
		}

		// SPA fallback: serve index.html (must revalidate so clients pick up new asset hashes after deploys)
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, filepath.Join(clientDir, "index.html"))
	})
}
