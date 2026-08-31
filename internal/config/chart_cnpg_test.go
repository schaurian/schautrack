package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// chartTemplates is the rendered-template source these assertions read.
var chartTemplates = filepath.Join("..", "..", "helm", "schautrack", "templates")

func readChartTemplates(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(chartTemplates)
	if err != nil {
		t.Fatalf("read chart templates: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(chartTemplates, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(b)
	}
	if len(out) == 0 {
		t.Fatal("no chart templates found")
	}
	return out
}

// TestChartNeverPointsAtAReadOnlyService is the build-time half of the invariant
// docs/cloudnativepg.md states in prose: everything that talks to the database
// uses the CloudNativePG -rw Service.
//
// This is worth a test rather than a comment because the failure is invisible.
// A DSN on -ro or -r reads fine and passes /api/health, so nothing looks wrong —
// but NOTIFY does not replicate, so the LISTEN in internal/sse attaches to a
// standby and waits on a channel that never fires. Cross-instance SSE goes dead
// with no error in any log, and the symptom users report is "linked accounts
// stopped updating", days later.
//
// The match has to survive templating, which is where the first version of
// this test was useless: it looked for a literal "postgresql-ro" and happily
// passed on `{{ include "schautrack.postgresql.fullname" . }}-ro`, the only
// spelling anyone would actually write. So the suffix is matched wherever it
// lands — after a template action, after a printf verb, or in a literal name —
// and `-rw` is the sole accepted form.
func TestChartNeverPointsAtAReadOnlyService(t *testing.T) {
	// A service-suffix `-ro`/`-r` not followed by the `w` that would make it -rw.
	readService := regexp.MustCompile(`-r(o\b|\b)`)
	for name, body := range readChartTemplates(t) {
		for i, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue // prose about -ro is how the invariant gets explained
			}
			if m := readService.FindString(line); m != "" {
				t.Errorf("%s:%d references a CloudNativePG read Service (%q):\n  %s\n"+
					"NOTIFY does not replicate: a LISTEN on a standby never fires and "+
					"cross-instance SSE dies silently. Use the -rw Service.",
					name, i+1, m, strings.TrimSpace(line))
			}
		}
	}
}

// TestChartUsesTheReadWriteServiceHelper pins the indirection itself. Someone
// hardcoding "-rw" in one template and not another is how the two drift, and
// the drift only shows up after a failover moves the primary.
func TestChartUsesTheReadWriteServiceHelper(t *testing.T) {
	helpers, err := os.ReadFile(filepath.Join(chartTemplates, "_helpers.tpl"))
	if err != nil {
		t.Fatalf("read _helpers.tpl: %v", err)
	}
	if !strings.Contains(string(helpers), `define "schautrack.postgresql.rwService"`) {
		t.Fatal("the schautrack.postgresql.rwService helper is gone; every database " +
			"reference must resolve through it so they cannot drift apart")
	}

	for name, body := range readChartTemplates(t) {
		if name == "cnpg-cluster.yaml" {
			continue // declares the Cluster; the Services are derived from it
		}
		for _, line := range strings.Split(body, "\n") {
			if !strings.Contains(line, "-rw") {
				continue
			}
			if strings.Contains(line, "rwService") || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			t.Errorf("%s hardcodes a -rw reference:\n  %s\nUse the "+
				"schautrack.postgresql.rwService helper instead.", name, strings.TrimSpace(line))
		}
	}
}

// TestChartRejectsRemovedPostgresValues guards the upgrade trap. Chart 3.0.0
// dropped the keys that configured the bundled Deployment, and
// postgresql.persistence.existingClaim is the dangerous one: it reads as "keep
// my data", so a chart that accepted and ignored it would provision an empty
// volume and look like it had eaten the database. The render must fail loudly,
// and the message must send the reader somewhere useful.
func TestChartRejectsRemovedPostgresValues(t *testing.T) {
	helpers, err := os.ReadFile(filepath.Join(chartTemplates, "_helpers.tpl"))
	if err != nil {
		t.Fatalf("read _helpers.tpl: %v", err)
	}
	body := string(helpers)

	if !strings.Contains(body, `define "schautrack.postgresql.validate"`) {
		t.Fatal("the postgresql.validate helper is gone; removed pre-3.0 keys would " +
			"be silently ignored instead of failing the render")
	}
	for _, key := range []string{"persistence", "image", "livenessProbe", "readinessProbe"} {
		if !strings.Contains(body, `"`+key+`"`) {
			t.Errorf("postgresql.validate does not reject the removed key %q", key)
		}
	}
	if !strings.Contains(body, "docs/cloudnativepg.md") {
		t.Error("the upgrade failure message must point at docs/cloudnativepg.md; " +
			"a bare 'unsupported key' tells someone what broke but not what to do")
	}

	// The cluster template has to actually call it, or the guard never runs.
	cluster, err := os.ReadFile(filepath.Join(chartTemplates, "cnpg-cluster.yaml"))
	if err != nil {
		t.Fatalf("read cnpg-cluster.yaml: %v", err)
	}
	if !strings.Contains(string(cluster), `include "schautrack.postgresql.validate"`) {
		t.Error("cnpg-cluster.yaml does not include the validate helper, so the " +
			"removed-key guard never executes")
	}
}

// TestBundledPostgresTemplatesAreGone stops the old single-Pod Deployment from
// being reintroduced alongside the Cluster. Two things claiming the same
// database name and PVC is a data-loss shape, not a merge conflict.
func TestBundledPostgresTemplatesAreGone(t *testing.T) {
	for _, name := range []string{
		"postgresql-deployment.yaml",
		"postgresql-pvc.yaml",
		"postgresql-service.yaml",
	} {
		if _, err := os.Stat(filepath.Join(chartTemplates, name)); err == nil {
			t.Errorf("%s is back. Chart 3.0.0 replaced the bundled PostgreSQL "+
				"Deployment with a CloudNativePG Cluster; running both would have "+
				"two servers contending for one database.", name)
		}
	}
}
