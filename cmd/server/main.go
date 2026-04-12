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

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/handler"
	"schautrack/internal/middleware"
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

	// Migrations
	if err := database.InitSchemaWithRetry(ctx, pool, 10); err != nil {
		slog.Warn("schema init returned error", "error", err)
	}

	// Services
	settingsCache := database.NewSettingsCache(pool)
	sessionStore := session.NewStore(pool, cfg.SessionSecret)
	emailService := service.NewEmailService(cfg)
	authLimiter := middleware.NewRateLimiter(cfg.RateLimitAuth, 15*time.Minute, cfg.TrustProxy)
	strictLimiter := middleware.NewRateLimiter(5, 5*time.Minute, cfg.TrustProxy)
	barcodeLimiter := middleware.NewRateLimiter(30, time.Minute, cfg.TrustProxy)

	// SSE broker
	sseBroker := sse.NewBroker(pool)

	// Auth handler
	authHandler := &handler.AuthHandler{
		Pool:         pool,
		SessionStore: sessionStore,
		Email:        emailService,
		Cfg:          cfg,
		Settings:     settingsCache,
	}

	// Router
	r := chi.NewRouter()
	r.Use(middleware.Recovery)
	r.Use(middleware.MaxBodySize(15 << 20)) // 15MB global limit
	r.Use(middleware.SecurityHeaders)
	r.Use(session.Middleware(sessionStore))
	r.Use(middleware.AttachUser(pool))
	r.Use(middleware.RememberClientTimezone)

	// SEO routes
	r.Get("/robots.txt", handler.RobotsTxt(cfg))
	r.Get("/sitemap.xml", handler.SitemapXml(cfg))

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", handler.Health(pool, cfg.BuildVersion))
		r.Get("/csrf", handler.CsrfToken)
		r.Get("/me", handler.Me(cfg.AdminEmail, settingsCache, cfg))

		// Registration info (public)
		r.Get("/auth/registration-info", handler.RegistrationInfo(settingsCache, cfg))

		// Auth routes
		r.With(authLimiter.Middleware, session.CsrfProtection).Post("/auth/login", authHandler.Login)
		r.With(authLimiter.Middleware, session.CsrfProtection).Post("/auth/register", authHandler.Register)
		r.With(middleware.RequireLogin, session.CsrfProtection).Post("/auth/logout", authHandler.Logout)
		r.With(strictLimiter.Middleware, session.CsrfProtection).Post("/auth/forgot-password", authHandler.ForgotPassword)
		r.With(session.CsrfProtection).Post("/auth/reset-password", authHandler.ResetPassword)
		r.With(session.CsrfProtection).Post("/auth/verify-email", authHandler.VerifyEmail)
		r.With(session.CsrfProtection).Post("/auth/verify-email/resend", authHandler.VerifyEmailResend)
		r.Get("/auth/captcha", authHandler.Captcha)
		r.With(strictLimiter.Middleware, session.CsrfProtection).Post("/auth/reset-2fa", authHandler.Reset2FA)

		// Settings (requires login)
		r.With(middleware.RequireLogin).Get("/settings", handler.Settings(pool, cfg.AdminEmail, settingsCache, cfg))

		// Admin (requires admin)
		r.With(middleware.RequireLogin, middleware.RequireAdmin(cfg.AdminEmail)).Get("/admin", handler.AdminData(pool, settingsCache, cfg.AdminEmail))
	})

	// Non-API authenticated routes
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/delete", authHandler.DeleteAccount)

	// Email change routes
	r.With(strictLimiter.Middleware, middleware.RequireLogin, session.CsrfProtection).Post("/settings/email/request", authHandler.EmailChangeRequest)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/email/verify", authHandler.EmailChangeVerify)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/email/cancel", authHandler.EmailChangeCancel)

	// Entry routes
	entriesHandler := &handler.EntriesHandler{Pool: pool, Broker: sseBroker, Cfg: cfg, Settings: settingsCache}
	r.With(middleware.RequireLogin).Get("/api/dashboard", entriesHandler.Dashboard)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool)).Get("/overview", entriesHandler.Overview)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool)).Get("/entries/day", entriesHandler.DayEntries)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/entries", entriesHandler.CreateEntry)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/entries/{id}/update", entriesHandler.UpdateEntry)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/entries/{id}/delete", entriesHandler.DeleteEntry)
	r.With(middleware.RequireLogin).Get("/settings/export", entriesHandler.Export)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/import", entriesHandler.Import)

	// Weight routes
	weightHandler := &handler.WeightHandler{Pool: pool, Broker: sseBroker}
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool)).Get("/weight/day", weightHandler.WeightDay)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/weight/upsert", weightHandler.WeightUpsert)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/weight/{id}/delete", weightHandler.WeightDelete)

	// Settings routes
	settingsHandler := &handler.SettingsHandler{Pool: pool, Broker: sseBroker, AIKeyEncryptSecret: cfg.AIKeyEncryptSecret}
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/preferences", settingsHandler.Preferences)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/macros", settingsHandler.Macros)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/ai", settingsHandler.AISettings)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/password", settingsHandler.Password)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/2fa/setup", settingsHandler.TwoFactorSetup)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/2fa/cancel", settingsHandler.TwoFactorCancel)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/2fa/enable", settingsHandler.TwoFactorEnable)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/2fa/disable", settingsHandler.TwoFactorDisable)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/2fa/backup-codes", settingsHandler.RegenerateBackupCodes)

	// Link routes
	linksHandler := &handler.LinksHandler{Pool: pool, Broker: sseBroker}
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/link/request", linksHandler.LinkRequest)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/link/respond", linksHandler.LinkRespond)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/settings/link/remove", linksHandler.LinkRemove)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/links/{id}/label", linksHandler.LinkLabel)

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
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool)).Get("/api/todos/day", todosHandler.DayTodos)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/todos/{id}/toggle", todosHandler.Toggle)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/todos/reorder", todosHandler.Reorder)

	// Notes routes
	notesHandler := &handler.NotesHandler{Pool: pool, Broker: sseBroker}
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/notes/toggle-enabled", notesHandler.ToggleEnabled)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool)).Get("/api/notes/day", notesHandler.Get)
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/api/notes", notesHandler.Save)

	// AI estimation
	aiHandler := &handler.AIHandler{Pool: pool, Cfg: cfg, Settings: settingsCache}
	r.With(strictLimiter.Middleware, middleware.RequireLogin).Post("/api/ai/estimate", aiHandler.Estimate)

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
			}
		}
	}()

	// SPA fallback — serve React client and public assets (must be last)
	clientDist := "client/dist"
	if info, err := os.Stat(clientDist); err == nil && info.IsDir() {
		spaHandler := spaFallback(clientDist, "public")
		r.Handle("/*", spaHandler)
	}

	// Start server with BaseContext for clean shutdown propagation
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second, // Long for SSE
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

		// SPA fallback: serve index.html (must revalidate so clients pick up new asset hashes after deploys)
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, filepath.Join(clientDir, "index.html"))
	})
}

