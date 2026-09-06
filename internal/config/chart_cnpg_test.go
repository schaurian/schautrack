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
		// .tpl too, not just .yaml. The first version of this helper read only
		// .yaml, so _helpers.tpl — the one file that actually spells the Service
		// suffix — was never scanned, and a rwService helper returning "-ro"
		// passed every test below.
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".tpl")) {
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
// templateComment strips {{/* ... */}} blocks. Prose about -ro is how this
// invariant gets explained, so the explanation must not trip the check.
var templateComment = regexp.MustCompile(`(?s)\{\{-?\s*/\*.*?\*/\s*-?\}\}`)

func TestChartNeverPointsAtAReadOnlyService(t *testing.T) {
	// A service-suffix `-ro`/`-r`, not the `-r` of a command-line flag: the
	// suffix is always welded to a name, so require a preceding word character,
	// `}` (end of a template action) or `%s` (a printf verb). Without that,
	// prose like "migrate.sh -n %s -r %s" reads as a read Service.
	readService := regexp.MustCompile(`[\w}]-r(o\b|\b)`)
	for name, body := range readChartTemplates(t) {
		for i, line := range strings.Split(templateComment.ReplaceAllString(body, ""), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue // YAML comments explain it too
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

	// A positive assertion, not just "the define exists": the helper has to
	// actually emit -rw. Asserting its presence is what let a "-ro" body slip
	// through unnoticed.
	if !regexp.MustCompile(`define "schautrack\.postgresql\.rwService"[\s\S]{0,200}?printf "%s-rw"`).MatchString(string(helpers)) {
		t.Error("schautrack.postgresql.rwService must render a -rw suffix; " +
			"NOTIFY does not replicate, so any other Service silently kills cross-instance SSE")
	}

	for name, body := range readChartTemplates(t) {
		// _helpers.tpl is where rwService is legitimately defined, and
		// cnpg-cluster.yaml declares the Cluster the Services derive from.
		if name == "cnpg-cluster.yaml" || name == "_helpers.tpl" {
			continue
		}
		for _, line := range strings.Split(templateComment.ReplaceAllString(body, ""), "\n") {
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

// TestChartKeepsBothDatabaseEngines pins the promise that the chart offers two
// databases, not one with a legacy path. Both are supported: bundled for
// installs that want no operator, CloudNativePG for installs that want backups
// and failover.
//
// It is a test rather than a convention because deleting the bundled templates
// is a tidy-looking change with an untidy consequence: an existing release keeps
// its data in a PVC only those templates manage, so a chart that stopped
// rendering them would leave the volume mounted by nothing and the database
// would look erased.
func TestChartKeepsBothDatabaseEngines(t *testing.T) {
	for _, name := range []string{
		"postgresql-deployment.yaml",
		"postgresql-pvc.yaml",
		"postgresql-service.yaml",
		"cnpg-cluster.yaml",
	} {
		if _, err := os.Stat(filepath.Join(chartTemplates, name)); err != nil {
			t.Errorf("%s is missing. Both engines must render: CloudNativePG for new "+
				"installs, the bundled Deployment so existing releases are undisturbed.", name)
		}
	}
}

// TestDatabaseEnginesAreMutuallyExclusive guards the shape that would be worst
// to get wrong: two servers, one database name, one release. Every engine
// template must gate on the resolved mode helpers rather than on
// postgresql.enabled, which is true for both.
func TestDatabaseEnginesAreMutuallyExclusive(t *testing.T) {
	want := map[string]string{
		"postgresql-deployment.yaml": "schautrack.postgresql.isBundled",
		"postgresql-pvc.yaml":        "schautrack.postgresql.isBundled",
		"postgresql-service.yaml":    "schautrack.postgresql.isBundled",
		"cnpg-cluster.yaml":          "schautrack.postgresql.isCNPG",
	}
	for name, guard := range want {
		b, err := os.ReadFile(filepath.Join(chartTemplates, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		head := strings.SplitN(string(b), "\n", 2)[0]
		if !strings.Contains(head, guard) {
			t.Errorf("%s does not gate on %s; its first line is:\n  %s\n"+
				"Gating on postgresql.enabled alone would render both engines at once.",
				name, guard, head)
		}
	}
}

// TestBundledModeIsTheDefault is the whole compatibility argument in one
// assertion. Helm cannot distinguish a fresh install from an upgrade, so a
// default of "cnpg" would move every existing release off the Deployment it is
// running and strand its PVC. Choosing CloudNativePG is therefore explicit, and
// changing this default is a major-version decision rather than a tweak.
func TestBundledModeIsTheDefault(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(chartTemplates, "..", "values.yaml"))
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	if !regexp.MustCompile(`(?m)^  mode: bundled\s*$`).Match(b) {
		t.Error("postgresql.mode must default to \"bundled\" in values.yaml. " +
			"Defaulting to cnpg silently migrates every existing release away from " +
			"its data. Flipping this is a major-version decision.")
	}
}
