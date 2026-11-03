package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var anyRoute = regexp.MustCompile(`\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`)

// TestAdminRoutesRequireAdmin fails when an admin route registered in main.go
// is not behind middleware.RequireLogin + middleware.RequireAdmin.
//
// The handler-level tests wrap AdminData in RequireAdmin themselves, so they
// cannot notice main.go mounting it without the guard — and GET /api/admin
// serves every user's email and last login. Like the CSRF guard next door, it
// reads the source because the router is assembled inside main(). A route is
// "admin" by its path (/admin…) or by its handler (AdminData, adminHandler.*),
// so moving one to another path does not slip it past the check.
func TestAdminRoutesRequireAdmin(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for i, line := range strings.Split(string(src), "\n") {
		m := anyRoute.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		isAdmin := strings.HasPrefix(m[2], "/admin") ||
			strings.Contains(line, "handler.AdminData(") ||
			strings.Contains(line, "adminHandler.")
		if !isAdmin {
			continue
		}
		checked++
		if !strings.Contains(line, "middleware.RequireLogin") || !strings.Contains(line, "middleware.RequireAdmin(cfg.AdminEmail)") {
			t.Errorf("main.go:%d: %s %s is registered without middleware.RequireLogin + middleware.RequireAdmin(cfg.AdminEmail)",
				i+1, strings.ToUpper(m[1]), m[2])
		}
	}
	// GET /admin (AdminData) plus the five adminHandler routes. Fewer means
	// the scan stopped matching how routes are registered.
	if checked < 6 {
		t.Fatalf("only %d admin routes found in main.go; the scan no longer matches how routes are registered", checked)
	}
}
