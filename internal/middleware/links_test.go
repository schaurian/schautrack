package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/database"
	"schautrack/internal/model"
	"schautrack/internal/service"
)

// RequireLinkAuth is the only place in the application where one account may
// read another's data, so it is the only place a bug becomes a cross-account
// data leak. These tests need a real database: the entire decision is a single
// SQL statement over account_links, and a fake would only assert that the
// statement we wrote is the statement we wrote.
//
// Skipped unless TEST_DATABASE_URL is set, matching the other integration tests
// in this repo (CI has no database; e2e covers the full stack). Run locally
// with, e.g.:
//
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/middleware/ -run TestRequireLinkAuth -v

// linkTestDB opens a pool and applies the schema, or skips.
func linkTestDB(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.InitSchemaWithRetry(ctx, pool, 3); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return ctx, pool
}

// mkUser inserts a user and returns it as the middleware would load it.
func mkUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string) *model.User {
	t.Helper()
	email := fmt.Sprintf("linkauth-%s-%d@middleware.test", label, time.Now().UnixNano())
	var id int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', true) RETURNING id`,
		email).Scan(&id); err != nil {
		t.Fatalf("seeding user %s failed: %v", label, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	})

	u, err := GetUserByID(ctx, pool, id)
	if err != nil {
		t.Fatalf("loading seeded user %s failed: %v", label, err)
	}
	return u
}

// setLink replaces whatever link exists between the two accounts.
// requesterShares is what the requester exposes to the target, and vice versa.
func setLink(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	requesterID, targetID int, status string, requesterShares, targetShares map[string]bool) {
	t.Helper()
	clearLink(t, ctx, pool, requesterID, targetID)

	enc := func(m map[string]bool) string {
		if m == nil {
			m = map[string]bool{}
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("encoding share map: %v", err)
		}
		return string(b)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
		VALUES ($1, $2, $3, $4::jsonb, $5::jsonb)`,
		requesterID, targetID, status, enc(requesterShares), enc(targetShares)); err != nil {
		t.Fatalf("seeding %s link %d→%d failed: %v", status, requesterID, targetID, err)
	}
}

func clearLink(t *testing.T, ctx context.Context, pool *pgxpool.Pool, a, b int) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`DELETE FROM account_links WHERE (requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1)`,
		a, b); err != nil {
		t.Fatalf("clearing link %d↔%d failed: %v", a, b, err)
	}
}

// linkResult is what a run of the middleware produced.
type linkResult struct {
	status       int
	contentType  string
	body         string
	reached      bool
	targetUserID int
	targetUser   *model.User
}

// runLinkAuth drives RequireLinkAuth for one viewer, category and ?user= value.
// A nil viewer models an unauthenticated request.
func runLinkAuth(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	category string, viewer *model.User, rawQuery string) linkResult {
	t.Helper()

	res := linkResult{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res.reached = true
		res.targetUserID = GetTargetUserID(r)
		res.targetUser = GetTargetUser(r)
		w.WriteHeader(http.StatusOK)
	})

	url := "/entries/day?date=2026-08-08"
	if rawQuery != "" {
		url += "&" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, url, nil).WithContext(ctx)
	if viewer != nil {
		req = req.WithContext(WithTestUser(req.Context(), viewer))
	}

	rec := httptest.NewRecorder()
	RequireLinkAuth(pool, category)(next).ServeHTTP(rec, req)

	res.status = rec.Code
	res.contentType = rec.Header().Get("Content-Type")
	res.body = strings.TrimSpace(rec.Body.String())
	return res
}

func (r linkResult) assertDenied(t *testing.T, why string) {
	t.Helper()
	if r.reached {
		t.Fatalf("%s: the handler ran — another account's data would have been served", why)
	}
	if r.status != http.StatusForbidden {
		t.Errorf("%s: status = %d, want 403", why, r.status)
	}
	if r.contentType != "application/json" {
		t.Errorf("%s: Content-Type = %q, want application/json", why, r.contentType)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(r.body), &body); err != nil {
		t.Fatalf("%s: 403 body is not JSON (%q): %v", why, r.body, err)
	}
	if body["ok"] != false || body["error"] != "Not authorized" {
		t.Errorf("%s: body = %v, want {ok:false, error:\"Not authorized\"}", why, body)
	}
}

func (r linkResult) assertAllowed(t *testing.T, wantTargetID int, why string) {
	t.Helper()
	if !r.reached {
		t.Fatalf("%s: denied with %d (%s), want the handler to run", why, r.status, r.body)
	}
	if r.targetUserID != wantTargetID {
		t.Errorf("%s: target user id in context = %d, want %d", why, r.targetUserID, wantTargetID)
	}
	if r.targetUser == nil {
		t.Fatalf("%s: no target user in context; handlers fall back to the viewer and would read the wrong rows", why)
	}
	if r.targetUser.ID != wantTargetID {
		t.Errorf("%s: target user in context is %d, want %d", why, r.targetUser.ID, wantTargetID)
	}
}

func TestRequireLinkAuth(t *testing.T) {
	ctx, pool := linkTestDB(t)

	alice := mkUser(t, ctx, pool, "alice")
	bob := mkUser(t, ctx, pool, "bob")
	carol := mkUser(t, ctx, pool, "carol")

	all := map[string]bool{
		service.ShareNutrition: true,
		service.ShareWeight:    true,
		service.ShareTodos:     true,
		service.ShareNotes:     true,
	}

	t.Run("unauthenticated request is 401, not 403", func(t *testing.T) {
		res := runLinkAuth(t, ctx, pool, service.ShareNutrition, nil, "")
		if res.reached {
			t.Fatal("the handler ran without a logged-in user")
		}
		if res.status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", res.status)
		}
	})

	t.Run("no ?user= reads your own data", func(t *testing.T) {
		res := runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, "")
		res.assertAllowed(t, alice.ID, "own data with no ?user=")
	})

	t.Run("?user= pointing at yourself needs no link", func(t *testing.T) {
		clearLink(t, ctx, pool, alice.ID, bob.ID)
		res := runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, fmt.Sprintf("user=%d", alice.ID))
		res.assertAllowed(t, alice.ID, "self-reference")
	})

	t.Run("no link at all is denied", func(t *testing.T) {
		clearLink(t, ctx, pool, alice.ID, bob.ID)
		res := runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, fmt.Sprintf("user=%d", bob.ID))
		res.assertDenied(t, "unlinked account")
	})

	// A pending request is an invitation, not consent. Reading on the strength
	// of one would mean sending a link request were enough to see someone's
	// data before they ever answered.
	t.Run("pending link is denied even with every share flag on", func(t *testing.T) {
		setLink(t, ctx, pool, alice.ID, bob.ID, "pending", all, all)
		res := runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, fmt.Sprintf("user=%d", bob.ID))
		res.assertDenied(t, "pending link")

		res = runLinkAuth(t, ctx, pool, service.ShareNutrition, bob, fmt.Sprintf("user=%d", alice.ID))
		res.assertDenied(t, "pending link, other direction")
	})

	t.Run("accepted link grants only the categories it names", func(t *testing.T) {
		// Bob (the target) shares nutrition and weight with Alice. Todos and
		// notes stay private; "notes" is absent from the JSON entirely, which
		// must read as false rather than as NULL/true.
		setLink(t, ctx, pool, alice.ID, bob.ID, "accepted",
			map[string]bool{},
			map[string]bool{service.ShareNutrition: true, service.ShareWeight: true, service.ShareTodos: false})

		for _, category := range []string{service.ShareNutrition, service.ShareWeight} {
			res := runLinkAuth(t, ctx, pool, category, alice, fmt.Sprintf("user=%d", bob.ID))
			res.assertAllowed(t, bob.ID, "granted category "+category)
		}
		for _, category := range []string{service.ShareTodos, service.ShareNotes} {
			res := runLinkAuth(t, ctx, pool, category, alice, fmt.Sprintf("user=%d", bob.ID))
			res.assertDenied(t, "ungranted category "+category)
		}
	})

	// The share flags are per direction. Bob letting Alice see his nutrition
	// must not let Bob see Alice's — this is the row of the table that would
	// turn "I shared with you" into "we shared with each other".
	t.Run("sharing is directional", func(t *testing.T) {
		setLink(t, ctx, pool, alice.ID, bob.ID, "accepted",
			map[string]bool{}, // Alice → Bob: nothing
			map[string]bool{service.ShareNutrition: true}) // Bob → Alice: nutrition

		runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, fmt.Sprintf("user=%d", bob.ID)).
			assertAllowed(t, bob.ID, "Alice reading Bob, who shares with her")
		runLinkAuth(t, ctx, pool, service.ShareNutrition, bob, fmt.Sprintf("user=%d", alice.ID)).
			assertDenied(t, "Bob reading Alice, who shares nothing")

		// Now Alice opts in too; the reverse direction opens and nothing else does.
		setLink(t, ctx, pool, alice.ID, bob.ID, "accepted",
			map[string]bool{service.ShareNutrition: true},
			map[string]bool{service.ShareNutrition: true})
		runLinkAuth(t, ctx, pool, service.ShareNutrition, bob, fmt.Sprintf("user=%d", alice.ID)).
			assertAllowed(t, alice.ID, "Bob reading Alice after she opted in")
		runLinkAuth(t, ctx, pool, service.ShareWeight, bob, fmt.Sprintf("user=%d", alice.ID)).
			assertDenied(t, "weight was never shared")
	})

	// Declining a request and removing a link both DELETE the row (there is no
	// 'declined' status — the CHECK constraint permits only pending/accepted),
	// so revocation has to take effect on the very next request.
	t.Run("deleting the link revokes access immediately", func(t *testing.T) {
		setLink(t, ctx, pool, alice.ID, bob.ID, "accepted", map[string]bool{}, all)
		runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, fmt.Sprintf("user=%d", bob.ID)).
			assertAllowed(t, bob.ID, "before revocation")

		clearLink(t, ctx, pool, alice.ID, bob.ID)
		runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, fmt.Sprintf("user=%d", bob.ID)).
			assertDenied(t, "after the link was removed")
	})

	t.Run("a third party's link grants nothing", func(t *testing.T) {
		// Bob and Carol share everything with each other. Alice is linked to
		// neither and must not ride along.
		setLink(t, ctx, pool, bob.ID, carol.ID, "accepted", all, all)
		clearLink(t, ctx, pool, alice.ID, bob.ID)
		clearLink(t, ctx, pool, alice.ID, carol.ID)

		runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, fmt.Sprintf("user=%d", bob.ID)).
			assertDenied(t, "Alice reading Bob via Bob↔Carol")
		runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, fmt.Sprintf("user=%d", carol.ID)).
			assertDenied(t, "Alice reading Carol via Bob↔Carol")

		clearLink(t, ctx, pool, bob.ID, carol.ID)
	})

	t.Run("malformed and hostile ?user= values", func(t *testing.T) {
		clearLink(t, ctx, pool, alice.ID, bob.ID)

		// Values that do not parse as an integer fall back to the caller's own
		// id. That is fail-closed — you see your own data, never someone
		// else's — and is pinned here so the fallback cannot quietly become
		// "ignore the check". (/api/v1 answers 400 for the same input; the two
		// surfaces differ on purpose, the legacy one predates the problem+json
		// contract.)
		for _, raw := range []string{"abc", "1.5", "", "%20", "null", "1;2", "1+OR+1=1"} {
			res := runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, "user="+raw)
			res.assertAllowed(t, alice.ID, fmt.Sprintf("unparseable ?user=%q falls back to self", raw))
		}

		// Values that DO parse but name no reachable account are denied, and
		// denied identically — a different status or body would let a caller
		// enumerate which user ids exist.
		for _, raw := range []string{"0", "-1", "2147483647", "99999999999999999"} {
			res := runLinkAuth(t, ctx, pool, service.ShareNutrition, alice, "user="+raw)
			res.assertDenied(t, fmt.Sprintf("?user=%s", raw))
		}
	})

	t.Run("denial is indistinguishable across causes", func(t *testing.T) {
		// no link / accepted-but-not-shared / nonexistent user must produce
		// byte-identical responses.
		clearLink(t, ctx, pool, alice.ID, bob.ID)
		noLink := runLinkAuth(t, ctx, pool, service.ShareNotes, alice, fmt.Sprintf("user=%d", bob.ID))

		setLink(t, ctx, pool, alice.ID, bob.ID, "accepted", map[string]bool{}, map[string]bool{service.ShareNotes: false})
		notShared := runLinkAuth(t, ctx, pool, service.ShareNotes, alice, fmt.Sprintf("user=%d", bob.ID))

		noSuchUser := runLinkAuth(t, ctx, pool, service.ShareNotes, alice, "user=2147483646")

		for _, r := range []linkResult{noLink, notShared, noSuchUser} {
			r.assertDenied(t, "enumeration probe")
		}
		if noLink.status != notShared.status || noLink.body != notShared.body {
			t.Errorf("an unlinked account and a non-sharing one are distinguishable:\n%d %q\n%d %q",
				noLink.status, noLink.body, notShared.status, notShared.body)
		}
		if noLink.status != noSuchUser.status || noLink.body != noSuchUser.body {
			t.Errorf("a nonexistent user id is distinguishable from an unshared one:\n%d %q\n%d %q",
				noLink.status, noLink.body, noSuchUser.status, noSuchUser.body)
		}
	})

	t.Run("context carries the target so handlers read the right rows", func(t *testing.T) {
		setLink(t, ctx, pool, alice.ID, bob.ID, "accepted", map[string]bool{}, all)
		res := runLinkAuth(t, ctx, pool, service.ShareWeight, alice, fmt.Sprintf("user=%d", bob.ID))
		res.assertAllowed(t, bob.ID, "linked read")
		if res.targetUser.Email != bob.Email {
			t.Errorf("target user email = %q, want %q — the wrong account was loaded", res.targetUser.Email, bob.Email)
		}
	})
}

// TestGetTargetUserWithoutMiddleware pins the fallback every handler relies on:
// a route that does NOT mount RequireLinkAuth leaves no target in the context,
// so GetTargetUser returns nil and the handlers fall back to the current user.
// That is exactly what makes ?user= inert on a mutating route.
func TestGetTargetUserWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/entries?user=999", nil).
		WithContext(WithTestUser(t.Context(), &model.User{ID: 1, Email: "a@example.com"}))

	if u := GetTargetUser(req); u != nil {
		t.Errorf("GetTargetUser = %v, want nil when RequireLinkAuth is not mounted", u)
	}
	if id := GetTargetUserID(req); id != 0 {
		t.Errorf("GetTargetUserID = %d, want 0 when RequireLinkAuth is not mounted", id)
	}
}

// --- The read-only invariant, as a table over the router -------------------
//
// CLAUDE.md: "Shared data is read-only (no editing other users' entries)."
//
// Nothing in the type system enforces that. It holds only because every route
// that honours ?user= is a GET, and every handler that reads the target user is
// mounted behind RequireLinkAuth. Both halves are one-line edits away from
// being false, so both are asserted here directly against the route table in
// cmd/server/main.go and the handler sources.

var routeRe = regexp.MustCompile(
	`\.(Get|Post|Put|Patch|Delete|Head|Options)\(\s*"([^"]*)"\s*,\s*([A-Za-z_][A-Za-z0-9_.]*)\)`)

type route struct {
	line    int
	method  string
	path    string
	handler string // e.g. "entriesHandler.Overview"
	chain   string // the text before the registration: the .With(...) middleware list
}

// parseRoutes extracts the route table from a Go source file. Registrations
// whose handler is a call expression or a func literal are skipped; only the
// `var.Method` form is of interest here.
func parseRoutes(t *testing.T, path string) []route {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var out []route
	for i, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "r.") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		loc := routeRe.FindStringSubmatchIndex(trimmed)
		if loc == nil {
			continue
		}
		m := routeRe.FindStringSubmatch(trimmed)
		out = append(out, route{
			line:    i + 1,
			method:  m[1],
			path:    m[2],
			handler: m[3],
			chain:   trimmed[:loc[0]],
		})
	}
	return out
}

type methodKey struct{ recv, name string }

func (k methodKey) String() string { return k.recv + "." + k.name }

// methodsCalling returns the methods in a package directory whose bodies
// mention any of the given selectors ("middleware.GetTargetUser", or a bare
// "resolveTarget" for calls on the receiver).
func methodsCalling(t *testing.T, dir string, wanted map[string]bool) map[methodKey]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}

	found := map[methodKey]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 || fn.Body == nil {
					continue
				}
				recv := ""
				switch rt := fn.Recv.List[0].Type.(type) {
				case *ast.StarExpr:
					if id, ok := rt.X.(*ast.Ident); ok {
						recv = id.Name
					}
				case *ast.Ident:
					recv = rt.Name
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if wanted[sel.Sel.Name] {
						found[methodKey{recv, fn.Name.Name}] = true
						return true
					}
					if x, ok := sel.X.(*ast.Ident); ok && wanted[x.Name+"."+sel.Sel.Name] {
						found[methodKey{recv, fn.Name.Name}] = true
					}
					return true
				})
			}
		}
	}
	return found
}

// handlerVarTypes maps the local variables in main.go to their handler types,
// so `notesHandler.Get` can be resolved to `NotesHandler.Get` (there is more
// than one handler with a method called Get).
func handlerVarTypes(t *testing.T, path string) map[string]string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	re := regexp.MustCompile(`(\w+)\s*:?=\s*&handler\.(\w+)\{`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out[m[1]] = m[2]
	}
	return out
}

func TestSharedDataIsReadOnlyAcrossTheRouter(t *testing.T) {
	const mainGo = "../../cmd/server/main.go"

	routes := parseRoutes(t, mainGo)
	if len(routes) < 40 {
		t.Fatalf("only %d routes parsed out of %s; the route-table guard is not actually looking at "+
			"anything. Fix parseRoutes before trusting this test.", len(routes), mainGo)
	}

	varTypes := handlerVarTypes(t, mainGo)
	targetReaders := methodsCalling(t, "../handler", map[string]bool{
		"middleware.GetTargetUser":   true,
		"middleware.GetTargetUserID": true,
	})
	if len(targetReaders) == 0 {
		t.Fatal("no handler methods were found reading the target user; the AST scan is broken")
	}

	linkAuthed := map[methodKey]bool{}
	for _, rt := range routes {
		hasLinkAuth := strings.Contains(rt.chain, "RequireLinkAuth")

		// 1. ?user= may only be honoured on a read.
		if hasLinkAuth && rt.method != "Get" {
			t.Errorf("%s:%d — %s %s mounts RequireLinkAuth on a mutating method. "+
				"Shared data is read-only; a linked account must never be able to write.",
				mainGo, rt.line, rt.method, rt.path)
		}

		key, known := resolveHandler(rt.handler, varTypes)
		if !known {
			continue
		}
		if hasLinkAuth {
			linkAuthed[key] = true
		}

		// 2. A handler that reads the target user must be gated by the
		//    middleware that validates it — otherwise ?user= would be honoured
		//    with no authorization check at all.
		if targetReaders[key] {
			if !hasLinkAuth {
				t.Errorf("%s:%d — %s %s serves %s, which reads middleware.GetTargetUser, but the route "+
					"does not mount RequireLinkAuth. ?user= would be honoured unchecked.",
					mainGo, rt.line, rt.method, rt.path, key)
			}
			if rt.method != "Get" {
				t.Errorf("%s:%d — %s %s serves %s, which reads the target user, on a mutating method.",
					mainGo, rt.line, rt.method, rt.path, key)
			}
		}
	}

	// 3. The two sets must match exactly: no handler reads a target it was not
	//    given, and no route validates a target nobody uses.
	if got, want := keys(linkAuthed), keys(targetReaders); !equalStrings(got, want) {
		t.Errorf("the set of RequireLinkAuth-gated handlers and the set of handlers reading the target "+
			"user disagree.\n  gated by RequireLinkAuth: %v\n  reading the target user:  %v", got, want)
	}
	if len(linkAuthed) < 4 {
		t.Errorf("only %d link-authorized routes found; expected the nutrition, weight, todos and notes "+
			"read routes at minimum", len(linkAuthed))
	}
}

// TestV1SharedDataIsReadOnly is the same invariant on the public API. There,
// ?user= is resolved by V1Handler.resolveTarget rather than by middleware, and
// its doc comment claims "no write endpoint calls this". This asserts it.
func TestV1SharedDataIsReadOnly(t *testing.T) {
	const v1Router = "../handler/v1_router.go"

	routes := parseRoutes(t, v1Router)
	if len(routes) < 15 {
		t.Fatalf("only %d routes parsed out of %s; the guard is not looking at the real route table",
			len(routes), v1Router)
	}

	resolvers := methodsCalling(t, "../handler", map[string]bool{"resolveTarget": true})
	// resolveTarget itself is in the set; drop it, it is the definition.
	delete(resolvers, methodKey{"V1Handler", "resolveTarget"})
	if len(resolvers) == 0 {
		t.Fatal("no v1 handlers were found calling resolveTarget; the AST scan is broken")
	}

	mounted := map[methodKey]bool{}
	for _, rt := range routes {
		name := rt.handler
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:]
		}
		key := methodKey{"V1Handler", name}
		if !resolvers[key] {
			continue
		}
		mounted[key] = true
		if rt.method != "Get" {
			t.Errorf("%s:%d — %s %s serves %s, which honours ?user=, on a mutating method. "+
				"A token would be able to write to a linked account.", v1Router, rt.line, rt.method, rt.path, key)
		}
	}
	if len(mounted) != len(resolvers) {
		t.Errorf("handlers calling resolveTarget that no parsed route mounts: gated %v, callers %v",
			keys(mounted), keys(resolvers))
	}
}

// resolveHandler turns a route's handler expression into a Type.Method key.
func resolveHandler(expr string, varTypes map[string]string) (methodKey, bool) {
	i := strings.LastIndex(expr, ".")
	if i < 0 {
		return methodKey{}, false
	}
	recvVar, method := expr[:i], expr[i+1:]
	typ, ok := varTypes[recvVar]
	if !ok {
		return methodKey{}, false
	}
	return methodKey{typ, method}, true
}

func keys(m map[methodKey]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k.String())
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
