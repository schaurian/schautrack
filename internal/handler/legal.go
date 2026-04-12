package handler

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"strings"

	"schautrack/internal/config"
	"schautrack/internal/database"
)

func RobotsTxt(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if cfg.RobotsIndex {
			host := r.Host
			protocol := "https"
			if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
				protocol = "http"
			}
			if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
				protocol = fwd
			}
			fmt.Fprintf(w, `User-agent: *
Allow: /
Disallow: /dashboard
Disallow: /settings
Disallow: /admin
Disallow: /api/

Sitemap: %s://%s/sitemap.xml
`, protocol, host)
		} else {
			fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
		}
	}
}

func SitemapXml(cfg *config.Config) http.HandlerFunc {
	type page struct {
		Loc        string
		Priority   string
		Changefreq string
	}
	pages := []page{
		{"/", "1.0", "weekly"},
		{"/login", "0.8", "monthly"},
		{"/register", "0.8", "monthly"},
		{"/privacy", "0.5", "yearly"},
		{"/terms", "0.5", "yearly"},
		{"/imprint", "0.3", "yearly"},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		baseURL := cfg.BaseURL
		if baseURL == "" {
			protocol := "https"
			if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
				protocol = fwd
			}
			baseURL = protocol + "://" + r.Host
		}

		var sb strings.Builder
		sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
		sb.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
		for _, p := range pages {
			fmt.Fprintf(&sb, "  <url>\n    <loc>%s%s</loc>\n    <changefreq>%s</changefreq>\n    <priority>%s</priority>\n  </url>\n",
				baseURL, p.Loc, p.Changefreq, p.Priority)
		}
		sb.WriteString("</urlset>")

		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(sb.String()))
	}
}

// ImprintAddressSVG handles GET /imprint/address.svg
func ImprintAddressSVG(settings *database.SettingsCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableLegal := settings.GetEffectiveSetting(r.Context(), "enable_legal", os.Getenv("ENABLE_LEGAL"))
		address := settings.GetEffectiveSetting(r.Context(), "imprint_address", os.Getenv("IMPRINT_ADDRESS"))
		if enableLegal.Value == nil || *enableLegal.Value != "true" || address.Value == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(textToSvg(*address.Value)))
	}
}

// ImprintEmailSVG handles GET /imprint/email.svg
func ImprintEmailSVG(settings *database.SettingsCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableLegal := settings.GetEffectiveSetting(r.Context(), "enable_legal", os.Getenv("ENABLE_LEGAL"))
		email := settings.GetEffectiveSetting(r.Context(), "imprint_email", os.Getenv("IMPRINT_EMAIL"))
		if enableLegal.Value == nil || *enableLegal.Value != "true" || email.Value == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(textToSvg(*email.Value)))
	}
}

func textToSvg(text string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(text, "\\n", "\n"), "\n")
	fontSize := 16
	lineHeight := 24
	height := len(lines) * lineHeight
	maxLen := 0
	for _, l := range lines {
		if len(l) > maxLen {
			maxLen = len(l)
		}
	}
	width := int(math.Max(float64(maxLen*10), 100))

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`, width, height, width, height)
	sb.WriteString(`<style>text { font-family: "Space Grotesk", sans-serif; }</style>`)
	for i, line := range lines {
		fmt.Fprintf(&sb, `<text x="0" y="%d" fill="#e5e7eb" font-family="sans-serif" font-weight="500" font-size="%d">%s</text>`,
			(i+1)*lineHeight-6, fontSize, escapeXml(line))
	}
	sb.WriteString(`</svg>`)
	return sb.String()
}

func escapeXml(s string) string {
	r := strings.NewReplacer("<", "&lt;", ">", "&gt;", "&", "&amp;", "'", "&apos;", `"`, "&quot;")
	return r.Replace(s)
}
