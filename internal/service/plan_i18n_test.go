package service

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// The plan page renders its disclaimer and warnings from the client catalog so
// they follow the UI language; the API still carries the English text. These
// pin the two together: a reworded server string, or a new warning code the
// catalog does not name, fails here instead of silently drifting in the UI.

type planCatalog struct {
	Plan struct {
		Disclaimer string            `json:"disclaimer"`
		Warnings   map[string]string `json:"warnings"`
	} `json:"plan"`
}

func loadEnDashboardCatalog(t *testing.T) planCatalog {
	t.Helper()
	raw, err := os.ReadFile("../../client/src/i18n/locales/en/dashboard.json")
	if err != nil {
		t.Fatalf("read en catalog: %v", err)
	}
	var c planCatalog
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse en catalog: %v", err)
	}
	return c
}

func TestPlanDisclaimerMatchesClientCatalog(t *testing.T) {
	c := loadEnDashboardCatalog(t)
	if c.Plan.Disclaimer != PlanDisclaimer {
		t.Fatalf("client plan.disclaimer differs from PlanDisclaimer:\n client: %q\n server: %q", c.Plan.Disclaimer, PlanDisclaimer)
	}
}

func TestPlanWarningCodesMatchClientCatalog(t *testing.T) {
	c := loadEnDashboardCatalog(t)
	src, err := os.ReadFile("plan_assemble.go")
	if err != nil {
		t.Fatalf("read plan_assemble.go: %v", err)
	}
	re := regexp.MustCompile(`Code:\s+"([a-z_]+)",\s+Message:\s+"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("found no PlanWarning literals; the pattern no longer matches plan_assemble.go")
	}
	for _, m := range matches {
		code, msg := m[1], m[2]
		got, ok := c.Plan.Warnings[code]
		if !ok {
			t.Errorf("warning code %q has no client translation key plan.warnings.%s", code, code)
			continue
		}
		if got != msg {
			t.Errorf("plan.warnings.%s = %q, server message = %q", code, got, msg)
		}
	}
}
