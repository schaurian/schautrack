package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	latestVersionURL    = "https://api.github.com/repos/schaurian/schautrack/releases/latest"
	latestVersionTTL    = time.Hour
	latestVersionErrTTL = 5 * time.Minute
	latestVersionUA     = "schautrack-server"
)

type latestVersionCache struct {
	mu        sync.Mutex
	tag       string
	fetchedAt time.Time
	err       bool
}

var latestVersion latestVersionCache

func LatestVersion() http.HandlerFunc {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=600")

		tag := latestVersion.lookup(r.Context(), client)
		var payload any
		if tag != "" {
			payload = tag
		}
		json.NewEncoder(w).Encode(map[string]any{"latest": payload})
	}
}

func (c *latestVersionCache) lookup(ctx context.Context, client *http.Client) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	ttl := latestVersionTTL
	if c.err {
		ttl = latestVersionErrTTL
	}
	if !c.fetchedAt.IsZero() && time.Since(c.fetchedAt) < ttl {
		return c.tag
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestVersionURL, nil)
	if err != nil {
		c.fetchedAt = time.Now()
		c.err = true
		return c.tag
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", latestVersionUA)

	resp, err := client.Do(req)
	if err != nil {
		c.fetchedAt = time.Now()
		c.err = true
		return c.tag
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.fetchedAt = time.Now()
		c.err = true
		return c.tag
	}

	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		c.fetchedAt = time.Now()
		c.err = true
		return c.tag
	}

	c.tag = strings.TrimPrefix(strings.TrimSpace(body.TagName), "v")
	c.fetchedAt = time.Now()
	c.err = false
	return c.tag
}
