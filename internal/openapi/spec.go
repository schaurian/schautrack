package openapi

import (
	"fmt"
	"sort"
	"strings"

	"schautrack/internal/service"
)

// APIVersion is the version of the /api/v1 contract itself, independent of the
// application build. It changes when the contract changes, not when the server
// is redeployed — so a client can pin against it meaningfully.
const APIVersion = "1.0.0"

// Endpoint is one (method, path) pair with the scope that guards it.
type Endpoint struct {
	Method string
	Path   string
	Scope  string // "" means: any valid token, no scope required
}

// Operations returns every operation in the document, sorted. This is the
// canonical list the route-parity test compares against the live chi router.
func (d *Document) Operations() []Endpoint {
	var out []Endpoint
	for path, item := range d.Paths {
		for method, op := range item.Operations() {
			out = append(out, Endpoint{Method: method, Path: path, Scope: op.Scope})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// scopeList renders the grantable scopes as a Markdown table for the API
// description, generated from service.ScopeDescriptions so the spec cannot
// list a scope the server does not honour.
func scopeList() string {
	s := "\n\n| Scope | Grants |\n| --- | --- |\n"
	for _, d := range service.ScopeDescriptions {
		s += fmt.Sprintf("| `%s` | %s |\n", d.Scope, d.Description)
	}
	return s
}

const apiDescription = `The Schautrack public API.

## Authentication

Every endpoint except ` + "`/openapi.json`" + ` requires a **personal access token**,
sent as a bearer token:

` + "```" + `
Authorization: Bearer stk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
` + "```" + `

Create one under **Settings → API tokens**. The token is shown once and cannot be
retrieved again. Tokens can be scoped and given an expiry, and can be revoked at
any time.

Session cookies are **not** accepted here. Because the API never treats a cookie
as authentication, no cross-site request can carry credentials to it — which is
why there is no CSRF token to manage.

## Scopes

A token carries an explicit set of scopes. A ` + "`:write`" + ` scope implies the
matching ` + "`:read`" + `, so ` + "`entries:write`" + ` alone is enough to both read and
write entries.

Calling an endpoint without its scope returns ` + "`403`" + ` with a
` + "`required_scope`" + ` field naming what is missing.

## Errors

Errors are [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem details,
served as ` + "`application/problem+json`" + `:

` + "```json" + `
{
  "type": "https://schautrack.com/problems/validation-failed",
  "title": "Validation failed",
  "status": 422,
  "detail": "One or more macro values are out of range.",
  "instance": "/api/v1/entries",
  "invalid_params": [{ "name": "protein_g", "reason": "must be between 0 and 999" }]
}
` + "```" + `

Branch on ` + "`type`" + `, not on ` + "`detail`" + `: the type URI is stable, the prose is not.

The ` + "`type`" + ` URIs are **stable identifiers, not endpoints**. Every instance,
self-hosted ones included, emits the same ` + "`https://schautrack.com/problems/…`" + `
URIs on purpose, so a client can recognise a problem type without knowing which
host produced it. Do not dereference them, and do not expect a self-hosted
instance to rewrite them to its own domain. This document's ` + "`servers`" + ` URL,
by contrast, *is* an endpoint, and always names the instance that served it.

## Dates and time zones

Dates are ` + "`YYYY-MM-DD`" + ` in the **account's** time zone. Omitting a date means
"today" for that account, not for the machine making the request. Timestamps are
RFC 3339 UTC; each entry also carries ` + "`local_time`" + ` rendered in the account's
zone.

## Pagination

` + "`GET /entries`" + ` and ` + "`GET /weight`" + ` are paginated by keyset. Pass the
` + "`next_cursor`" + ` from a response back as ` + "`cursor`" + ` to fetch the next
page; stop when ` + "`has_more`" + ` is false. Cursors are opaque — do not
construct them.

## Retrying safely

Every ` + "`PUT`" + ` here is idempotent by construction: the URL names the resource
and the body states the desired state, so repeating one changes nothing.

` + "`POST`" + ` is different. If a request to create an entry times out, you cannot
know whether it landed. Send an ` + "`Idempotency-Key`" + ` header — any string you
generate once per logical operation and reuse when retrying:

` + "```" + `
Idempotency-Key: 5f8c1e2a-meal-breakfast-2026-08-05
` + "```" + `

The first request executes and its response is stored. Any retry with the same
key replays that response, with ` + "`Idempotency-Replayed: true`" + `, instead of
logging the meal twice. Reusing a key with a *different* body returns ` + "`409`" + `
rather than silently discarding the new request. Keys are remembered for 24
hours. A request that fails releases its key, so the retry is a fresh attempt
rather than a replay of the error.

Every endpoint that creates something accepts the header: ` + "`POST /entries`" + `,
` + "`POST /todos`" + `, ` + "`POST /saved-foods`" + `, and
` + "`POST /saved-foods/{id}/track`" + `. The operation parameter lists say which,
and they are not advisory — the one ` + "`POST`" + ` that does not honour the header
(` + "`POST /ai/estimate`" + `) rejects it with ` + "`400`" + ` instead of ignoring it.
An accepted request is therefore always a request whose retry semantics are
what you asked for.

## Rate limits

Three limits apply: one per IP address, one per token, and — on the two
endpoints that cost real resources — one per account. ` + "`POST /ai/estimate`" + `
and ` + "`GET /barcode/{code}`" + ` reach a paid provider and a third-party food
database respectively, so they are capped at the same rate the app's own UI
gets rather than at the API-wide ceiling; a token is not a cheaper route to
them than a browser.

Exceeding any of the three returns ` + "`429`" + ` with a ` + "`Retry-After`" + `
header giving the number of seconds until the window reopens. Honour it rather
than retrying blindly.`

// CanonicalBaseURL is the URL of the Schautrack-hosted instance. It is the base
// cmd/apidocs bakes into the committed api/openapi.json and docs/api-v1.md, so
// those two artifacts describe one fixed, reviewable host instead of whatever
// machine happened to run the generator. A running server never uses it: it
// serves its own BASE_URL — see Build.
const CanonicalBaseURL = "https://schautrack.com"

// servers returns the single `servers` entry for the instance serving this
// document.
//
// There is exactly one entry, and it is this instance. A hardcoded list naming
// schautrack.com used to ship to every deployment, which meant a self-hoster's
// spec pointed clients — Swagger UI's "Try it out" above all, which sends the
// caller's `stk_…` bearer token to servers[0] — at a host they do not control.
// A long-lived token leaked that way is a durable exposure, so the server URL
// has to follow the instance.
func servers(baseURL string) []Server {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		// No BASE_URL configured. A relative server URL is resolved by the
		// client against the URL the document itself was fetched from (OpenAPI
		// 3.1 §4.8.5), which keeps an unconfigured instance pointing at itself.
		// Deriving an absolute URL from the request's Host header instead would
		// put an attacker-supplied value into the published contract, so the
		// relative form is both simpler and safer.
		return []Server{{URL: "/api/v1", Description: serverDescription}}
	}
	return []Server{{URL: base + "/api/v1", Description: serverDescription}}
}

const serverDescription = "This instance. Every deployment serves its own URL here, so tools that read this document — Swagger UI's \"Try it out\" included — send credentials only to the host the document came from."

// Build assembles the OpenAPI document.
//
// version is the running build version, surfaced so a reader can tell which
// deployment served the spec. baseURL is the public root this instance is
// reached at (config.BaseURL / the BASE_URL environment variable); it becomes
// the sole `servers` entry as <baseURL>/api/v1. An empty baseURL yields the
// relative "/api/v1", which every client resolves against this instance.
func Build(version, baseURL string) *Document {
	d := &Document{
		OpenAPI: "3.1.0",
		Info: Info{
			Title:       "Schautrack API",
			Version:     APIVersion,
			Summary:     "Read and write your Schautrack calorie, weight, todo, and food data.",
			Description: apiDescription + scopeList(),
			License:     &License{Name: "AGPL-3.0-or-later", Identifier: "AGPL-3.0-or-later"},
			Contact:     &Contact{Name: "Schautrack", URL: "https://schautrack.com"},
		},
		Servers: servers(baseURL),
		Tags: []Tag{
			{Name: "Account", Description: "Who the token belongs to and what it may do."},
			{Name: "Entries", Description: "Calorie entries and their macros."},
			{Name: "Weight", Description: "Daily weight readings."},
			{Name: "Todos", Description: "Recurring todos and their completions."},
			{Name: "Saved foods", Description: "Reusable quick-add foods."},
			{Name: "Notes", Description: "One free-text note per day."},
			{Name: "Plan", Description: "The weight-loss plan and its projections."},
			{Name: "Links", Description: "Accounts that share data with you."},
			{Name: "AI", Description: "Nutrition estimation from photos."},
			{Name: "Meta", Description: "The API's own description."},
		},
		Components: Components{
			Schemas:         schemas(),
			SecuritySchemes: securitySchemes(),
			Responses:       sharedResponses(),
		},
		// Applied to every operation unless overridden; /openapi.json opts out
		// with an explicit empty requirement.
		Security: []SecurityRequirement{{"bearerAuth": {}}},
	}
	d.Paths = paths()
	d.Info.Version = APIVersion
	if version != "" {
		d.Info.Description += "\n\n---\n\nServed by build `" + version + "`."
	}
	return d
}

func securitySchemes() map[string]*SecurityScheme {
	return map[string]*SecurityScheme{
		"bearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "stk_<43 base64url characters>",
			Description: "A personal access token from Settings → API tokens. " +
				"Send it as `Authorization: Bearer stk_…`.",
		},
	}
}

func sharedResponses() map[string]*Response {
	r := func(desc string) *Response {
		return &Response{Description: desc, Content: problemBody()}
	}
	return map[string]*Response{
		"Unauthorized":      r("No token, or the token is unknown, revoked, or expired."),
		"InsufficientScope": r("The token is valid but lacks the scope this endpoint requires. The `required_scope` field names it."),
		"NotFound":          r("No such resource, or it belongs to another account."),
		"BadRequest":        r("The request is malformed — unparseable JSON, an unknown field, or a bad query parameter."),
		"Unprocessable":     r("The request is well-formed but its values are rejected. `invalid_params` lists the offending fields."),
		"Conflict":          r("The request collides with existing state — a duplicate name, a limit already reached, or a feature not enabled."),
		"RateLimited": {
			Description: "Too many requests. The `Retry-After` header gives the number of seconds until the window reopens.",
			Content:     problemBody(),
			Headers: map[string]Header{
				"Retry-After": {Description: "Seconds to wait before retrying.", Schema: integer("")},
			},
		},
		"ServerError": r("An unexpected server-side failure."),
	}
}

// linkedUserParam lets a read endpoint return a linked account's data.
var linkedUserParam = Parameter{
	Name: "user", In: "query",
	Description: "Read a linked account's data instead of your own. Pass the `user_id` from " +
		"`GET /links`. Requires the `links:read` scope AND that the account shares this " +
		"category with you; otherwise 403. Shared data is read-only — no write endpoint accepts this.",
	Schema: integer(""),
}

// idempotencyParam documents the opt-in retry-safety header. It belongs on
// every endpoint that creates something; the endpoints that do not honour it
// reject it with 400 rather than ignoring it, so this list is not advisory.
var idempotencyParam = Parameter{
	Name: "Idempotency-Key", In: "header",
	Description: "Optional. A key you generate once per logical operation and reuse when retrying. " +
		"The first request executes and its response is stored; a retry with the same key replays " +
		"that response instead of creating a second record, and carries `Idempotency-Replayed: true`. " +
		"Reusing a key for a different request body is rejected with 409. Keys are remembered for 24 hours.",
	Schema: str(""),
}

func schemas() map[string]*Schema {
	macros := object("Macronutrients in grams. `null` means the macro was not recorded, which is distinct from a recorded zero.",
		map[string]*Schema{
			"protein_g": nullInt("Protein, grams."),
			"carbs_g":   nullInt("Carbohydrates, grams."),
			"fat_g":     nullInt("Fat, grams."),
			"fiber_g":   nullInt("Fibre, grams."),
			"sugar_g":   nullInt("Sugar, grams."),
		}, "protein_g", "carbs_g", "fat_g", "fiber_g", "sugar_g")

	macroInputProps := func() map[string]*Schema {
		return map[string]*Schema{
			"protein_g": withRange(nullInt("Protein, grams."), 0, 999),
			"carbs_g":   withRange(nullInt("Carbohydrates, grams."), 0, 999),
			"fat_g":     withRange(nullInt("Fat, grams."), 0, 999),
			"fiber_g":   withRange(nullInt("Fibre, grams."), 0, 999),
			"sugar_g":   withRange(nullInt("Sugar, grams."), 0, 999),
		}
	}

	entryProps := map[string]*Schema{
		"id":         integer("Server-assigned identifier."),
		"date":       dateStr("The day this entry belongs to, in the account's time zone."),
		"calories":   integer("Energy in kilocalories. May be negative to record a correction."),
		"name":       nullStr("What was eaten. Up to 120 bytes."),
		"macros":     ref("Macros"),
		"created_at": dateTime("When the entry was recorded (UTC)."),
		"local_time": str("`created_at` rendered as HH:MM in the account's time zone."),
	}

	entryInput := object("A new calorie entry. Supply `calories`, at least one macro, or both.",
		mergeProps(map[string]*Schema{
			"date":     dateStr("Defaults to today in the account's time zone."),
			"calories": withRange(integer("Energy in kilocalories."), -9999, 9999),
			"name":     str("What was eaten."),
		}, macroInputProps()))

	entryPatch := object("Fields to change. Omit a field to leave it alone; send `null` to clear a macro or the name.",
		mergeProps(map[string]*Schema{
			"date":     dateStr("Move the entry to another day."),
			"calories": withRange(integer("Energy in kilocalories. Rejected while the account computes calories from macros."), -9999, 9999),
			"name":     nullStr("What was eaten. `null` clears it."),
		}, macroInputProps()))

	savedFoodProps := map[string]*Schema{
		"id":           integer("Server-assigned identifier."),
		"name":         str("Food name. Unique per account, case-insensitively."),
		"emoji":        nullStr("Optional emoji shown next to the name."),
		"calories":     nullInt("Energy per unit, kilocalories."),
		"macros":       ref("Macros"),
		"use_count":    integer("How many units have been tracked from this food."),
		"last_used_at": nullable(dateTime("When it was last tracked.")),
		"created_at":   dateTime("When it was created (UTC)."),
		"updated_at":   dateTime("When it was last changed (UTC)."),
	}

	// The plan's ten schemas are built separately — inline they would bury
	// everything else in this function.
	return mergeProps(map[string]*Schema{
		"Macros": macros,

		"Entry": object("A calorie entry.", entryProps,
			"id", "date", "calories", "name", "macros", "created_at", "local_time"),
		"EntryInput": entryInput,
		"EntryPatch": entryPatch,
		"EntryList": object("A page of entries.", map[string]*Schema{
			"data":        array(ref("Entry"), "The entries, newest first."),
			"has_more":    boolean("Whether another page exists."),
			"next_cursor": nullStr("Pass back as `cursor` to fetch the next page. Opaque — do not parse."),
		}, "data"),

		"Weight": object("A weight reading. One per account per day.", map[string]*Schema{
			"date":       dateStr("The day this reading belongs to."),
			"weight":     number("The reading, in `unit`."),
			"body_fat":   nullable(number("Body fat as a percentage, or `null` when the day carries no measurement.")),
			"unit":       {Type: "string", Enum: []any{"kg", "lb"}, Description: "The account's weight unit. Readings are stored as entered and never converted."},
			"created_at": dateTime("When first recorded (UTC)."),
			"updated_at": dateTime("When last changed (UTC)."),
		}, "date", "weight", "body_fat", "unit", "created_at", "updated_at"),
		"WeightInput": object("A weight reading.", map[string]*Schema{
			"weight": withRange(number("The reading, in the account's unit."), 0.01, 1500),
			"body_fat": nullable(withRange(number(
				"Body fat as a percentage, rounded to one decimal. **Omit** to leave any stored "+
					"reading for that day untouched — which is what makes a weight-only scale "+
					"integration safe to retry. Send `null` to clear it. Writing a value switches "+
					"the account's body-fat field on if it was off, so the reading is visible in "+
					"the app; clearing never switches it back off."),
				0.1, service.MaxBodyFatPct)),
		}, "weight"),
		"WeightList": object("A page of weight readings, newest first.", map[string]*Schema{
			"data":        array(ref("Weight"), "The readings."),
			"has_more":    boolean("Whether another page exists."),
			"next_cursor": nullStr("Pass back as `cursor` to fetch the next page. Opaque — do not parse."),
		}, "data"),

		"Todo": object("A recurring todo.", map[string]*Schema{
			"id":          integer("Server-assigned identifier."),
			"name":        str("What to do."),
			"schedule":    ref("Schedule"),
			"time_of_day": nullStr("Optional HH:MM the todo is due at."),
			"sort_order":  integer("Display order."),
			"created_at":  dateTime("When it was created (UTC)."),
		}, "id", "name", "schedule", "time_of_day", "sort_order", "created_at"),
		"Schedule": object("When a todo recurs.", map[string]*Schema{
			"type": {Type: "string", Enum: []any{"daily", "weekly"}, Description: "`daily` every day; `weekly` on the listed days."},
			"days": array(withRange(integer("Day of week, 0 = Sunday."), 0, 6), "Required when `type` is `weekly`."),
		}, "type"),
		"TodoInput": object("A new todo.", map[string]*Schema{
			"name":        str("What to do. Up to 100 bytes."),
			"schedule":    ref("Schedule"),
			"time_of_day": nullStr("Optional HH:MM."),
		}, "name", "schedule"),
		"TodoPatch": object("Fields to change.", map[string]*Schema{
			"name":        str("What to do."),
			"schedule":    ref("Schedule"),
			"time_of_day": nullStr("`null` clears the time."),
		}),
		"TodoList": object("Todo definitions.", map[string]*Schema{
			"data": array(ref("Todo"), "The todos, in display order."),
		}, "data"),
		"TodoDay": object("A todo as it applies to one date.", map[string]*Schema{
			"id":           integer("The todo's identifier."),
			"name":         str("What to do."),
			"time_of_day":  nullStr("HH:MM it is due at, if set."),
			"completed":    boolean("Whether it is done on this date."),
			"streak":       integer("Consecutive scheduled days completed, ending on this date."),
			"missed_since": nullStr("The first scheduled day missed, if the streak is broken."),
		}, "id", "name", "time_of_day", "completed", "streak", "missed_since"),
		"TodoDayList": object("Todos scheduled for a date.", map[string]*Schema{
			"data": array(ref("TodoDay"), "Timed todos first, in time order, then untimed."),
		}, "data"),
		"CompletionInput": object("The desired completion state.", map[string]*Schema{
			"completed": boolean("`true` marks it done on this date, `false` clears it."),
		}, "completed"),
		"Completion": object("A todo's completion state on a date.", map[string]*Schema{
			"todo_id":   integer("The todo."),
			"date":      dateStr("The date."),
			"completed": boolean("The resulting state."),
		}, "todo_id", "date", "completed"),

		"SavedFood": object("A reusable quick-add food.", savedFoodProps,
			"id", "name", "emoji", "calories", "macros", "use_count", "last_used_at", "created_at", "updated_at"),
		"SavedFoodInput": object("A new saved food.",
			mergeProps(map[string]*Schema{
				"name":     str("Food name, up to 80 bytes. Must be unique for the account."),
				"emoji":    str("Optional emoji, up to 16 bytes."),
				"calories": withRange(integer("Energy per unit, kilocalories."), -9999, 9999),
			}, macroInputProps()), "name"),
		"SavedFoodPatch": object("Fields to change. `null` clears a nullable field.",
			mergeProps(map[string]*Schema{
				"name":     str("Food name."),
				"emoji":    nullStr("`null` clears the emoji."),
				"calories": withRange(nullInt("Energy per unit."), -9999, 9999),
			}, macroInputProps())),
		"SavedFoodList": object("Saved foods, most-used first. Never partial.", map[string]*Schema{
			"data": array(ref("SavedFood"), "Every saved food on the account."),
		}, "data"),
		"TrackInput": object("How to log this food.", map[string]*Schema{
			"date":     dateStr("Defaults to today in the account's time zone."),
			"quantity": withRange(integer("How many units to log."), 1, 99),
		}),

		"Note": object("One day's free-text note.", map[string]*Schema{
			"date":       dateStr("The day."),
			"content":    str("The note. Empty when no note is set."),
			"updated_at": nullable(dateTime("When it was last written (UTC). `null` when there is no note.")),
		}, "date", "content", "updated_at"),
		"NoteInput": object("The note's full content. Writing an empty string deletes it.", map[string]*Schema{
			"content": {Type: "string", Description: "Up to 10000 characters.", MaxLength: intp(10000)},
		}, "content"),

		"Me": object("The authenticated account, the token, and the account's enabled features.", map[string]*Schema{
			"user": object("The account this token belongs to.", map[string]*Schema{
				"id":          integer("Account identifier."),
				"email":       str("Account email."),
				"timezone":    str("IANA time zone. Determines what `today` and every bare date mean."),
				"weight_unit": {Type: "string", Enum: []any{"kg", "lb"}, Description: "The unit weight readings are stored in."},
				"daily_goal":  nullInt("Daily calorie goal, if set."),
				"language":    nullStr("UI language, if set."),
			}, "id", "email", "timezone", "weight_unit", "daily_goal", "language"),
			"token": object("The token that authenticated this request.", map[string]*Schema{
				"id":         integer("Token identifier."),
				"name":       str("The label given when it was created."),
				"prefix":     str("The token's non-secret prefix."),
				"scopes":     array(str("A granted scope."), "Everything this token may do."),
				"expires_at": nullable(dateTime("When it stops working. `null` means never.")),
			}, "id", "name", "prefix", "scopes", "expires_at"),
			"server": object("The server answering.", map[string]*Schema{
				"version": str("The running build version."),
				"today":   dateStr("Today's date in the account's time zone."),
			}, "version", "today"),
			"features": object(
				"Per-account opt-ins that change how the rest of the API behaves. "+
					"Read-only: they are switched in the app's settings, not through this API. "+
					"Every field is always present.",
				map[string]*Schema{
					"body_fat": boolean("Body-fat readings are enabled. When `false` a stored " +
						"reading is not shown in the app."),
					"todos": boolean("Todos are enabled in the app. The todo endpoints work either " +
						"way, but a todo created while this is `false` is invisible to the user."),
					"notes": boolean("Daily notes are enabled. When `false`, `GET` and `PUT " +
						"/notes/{date}` answer `409`."),
					"macros": boolean("At least one macro (protein, carbs, fat, fiber, sugar) is " +
						"enabled for this account, so macro values are shown in the app."),
					"auto_calc_calories": boolean("Calories are computed from macros. When `true`, " +
						"`POST /entries` derives `calories` from the macros it was given rather than " +
						"trusting the value sent, and `PATCH /entries/{id}` rejects `calories` with a `422`."),
				}, "body_fat", "todos", "notes", "macros", "auto_calc_calories"),
		}, "user", "token", "server", "features"),

		"Link": object("A linked account, from your point of view.", map[string]*Schema{
			"user_id": integer("Pass this as the `user` query parameter on a read endpoint."),
			"email":   str("The linked account's email."),
			"label":   nullStr("The name you gave this link, if any."),
			"shares_with_me": object("What this account shares WITH you — the only categories `?user=` will serve.", map[string]*Schema{
				"nutrition": boolean("Calorie entries and macros."),
				"weight":    boolean("Weight readings."),
				"todos":     boolean("Todos and completions."),
				"notes":     boolean("Daily notes."),
			}, "nutrition", "weight", "todos", "notes"),
			"shares_to_them": object("What you share back with them.", map[string]*Schema{
				"nutrition": boolean("Calorie entries and macros."),
				"weight":    boolean("Weight readings."),
				"todos":     boolean("Todos and completions."),
				"notes":     boolean("Daily notes."),
			}, "nutrition", "weight", "todos", "notes"),
			"timezone": str("Their IANA time zone. Their timestamps are rendered in it, not yours."),
		}, "user_id", "email", "label", "shares_with_me", "shares_to_them", "timezone"),
		"LinkList": object("Accounts linked to yours.", map[string]*Schema{
			"data": array(ref("Link"), "The linked accounts."),
		}, "data"),

		"SettingsPatch": object("Account settings to change. Omit a field to leave it alone.", map[string]*Schema{
			"daily_goal":  withRange(nullInt("Daily calorie goal. `null` clears it."), 1, 9999),
			"timezone":    str("IANA time zone name, e.g. `Europe/Berlin`. Decides what every bare date means."),
			"weight_unit": {Type: "string", Enum: []any{"kg", "lb"}, Description: "Display unit. Changing it does NOT convert stored readings — they are kept as entered."},
			"language":    nullStr("UI language: one of en, de, es, fr, it, nl, pl, pt. `null` restores automatic."),
		}),

		"EstimateInput": object("A food photo to estimate.", map[string]*Schema{
			"image":   str("The photo as a `data:image/...;base64,...` URI. Maximum 10 MB."),
			"context": str("Optional hint, e.g. \"a large bowl\"."),
		}, "image"),
		"Estimate": {
			Type:                 "object",
			Description:          "The model's nutrition estimate. Shape follows the app's AI response.",
			AdditionalProperties: true,
		},
		"BarcodeProduct": {
			Type:                 "object",
			Description:          "The product as resolved from OpenFoodFacts, or a not-found result.",
			AdditionalProperties: true,
		},

		"Problem": object("An RFC 9457 problem details object.", map[string]*Schema{
			"type":     str("Stable URI identifying the problem type. Branch on this."),
			"title":    str("Short, human-readable summary of the problem type."),
			"status":   integer("The HTTP status code."),
			"detail":   str("Human-readable explanation specific to this occurrence."),
			"instance": str("The request path that produced it."),
			"invalid_params": array(object("A rejected field.", map[string]*Schema{
				"name":   str("The field's name."),
				"reason": str("Why it was rejected."),
			}, "name", "reason"), "Present on validation failures."),
			"required_scope": str("Present on 403s: the scope the token is missing."),
		}, "type", "title", "status"),
	}, planSchemas())
}

// planSchemas describes GET /plan: one component per Go type behind
// service.PlanResponse.
//
// Named components rather than one free-form blob, which is what this was until
// it turned out that "additionalProperties: true" also means "Document.Validate
// checks nothing". /plan carries the largest payload in the API and the one that
// changes most often, and it had silently gained three undocumented fields.
// Writing the shape down is what puts it under the same drift check as every
// other response (internal/handler.TestPlanMatchesSchema); the docs and the
// generated clients getting real types instead of Record<string, unknown> are
// the bonus.
//
// Sub-objects are separate components rather than inline ones so the reference
// page renders a field table for each — an inline object renders as the word
// "object" and nothing else.
//
// Weight-valued fields are in the account's unit throughout, including the four
// whose names say Kg (minKg, maxKg, rateKgPerWeek, slopeKgPerWeek):
// service.ConvertPlanResponseToDisplayUnit converts them like every other
// weight. The names are historical and misleading — schaurian/schautrack#361.
func planSchemas() map[string]*Schema {
	const inUnit = " In the account's weight unit."

	return map[string]*Schema{
		"Plan": object("The weight-loss plan: body metrics, active goal, computed budget, "+
			"projected curve, and trend analysis. Every field is always present; those that depend "+
			"on data the account has not supplied are `null`. Weight-valued fields are in the "+
			"account's unit.",
			map[string]*Schema{
				"metrics":       describedRef("PlanMetrics", "The body metrics the plan is computed from."),
				"currentWeight": nullable(number("The most recent weight reading. `null` when none is logged." + inUnit)),
				"bmi":           nullable(number("Body mass index. `null` without both a height and a weight.")),
				"bmiCategory":   nullEnumStr("The band `bmi` falls in: `underweight`, `normal`, `overweight` or `obese`.", "underweight", "normal", "overweight", "obese"),
				"composition":   nullableRef("BodyComposition", "Derived from the most recent body-fat reading. `null` when none was recorded."),
				"healthyRange":  nullableRef("HealthyRange", "The healthy weight range for the account's height. `null` without a height and a weight."),
				"goal":          nullableRef("WeightGoal", "The active weight goal. `null` when none is set."),
				"computed":      nullableRef("PlanComputed", "The budget and projection. `null` unless the body metrics are complete AND an active goal has a usable pace."),
				"trend":         nullableRef("PlanTrend", "Observed progress. `null` when no goal is set; present but flagged `insufficient_data` when there are too few readings."),
				"currentCalorieGoal": nullInt("The account's daily calorie target as it stands now, which need not equal " +
					"`computed.budgetKcal` — the recommendation is only applied when the user accepts it."),
				"series":     array(ref("SeriesPoint"), "Logged weight readings from the last 180 days, oldest first."),
				"warnings":   array(ref("PlanWarning"), "Safety notes about this plan. Empty when there is nothing to flag."),
				"disclaimer": str("Fixed text to show alongside the numbers. The plan is an estimate, not medical advice."),
			},
			"metrics", "currentWeight", "bmi", "bmiCategory", "composition", "healthyRange", "goal",
			"computed", "trend", "currentCalorieGoal", "series", "warnings", "disclaimer"),

		"PlanMetrics": object("The body metrics the plan is computed from. Each is `null` until the account supplies it; they are set in the app, not over this API.",
			map[string]*Schema{
				"heightCm":      nullable(number("Height in centimetres. Never converted — this is not a weight.")),
				"birthYear":     nullInt("Year of birth; age is derived from it."),
				"sex":           nullEnumStr("`male`, `female` or `other`. Used by the Mifflin–St Jeor formula and the calorie floor.", "male", "female", "other"),
				"activityLevel": nullEnumStr("`sedentary`, `light`, `moderate`, `active` or `very_active`. Decides the multiplier applied to BMR to reach TDEE.", "sedentary", "light", "moderate", "active", "very_active"),
				"complete":      boolean("Whether all four are set. `computed` stays `null` while this is `false`."),
			}, "heightCm", "birthYear", "sex", "activityLevel", "complete"),

		"BodyComposition": object("Body composition derived from the most recent body-fat reading. That reading can be "+
			"older than the current weight — body composition is measured less often — so `date` says when it was taken.",
			map[string]*Schema{
				"date":       dateStr("The day the body-fat reading was recorded."),
				"bodyFatPct": number("Body fat as a percentage of total mass. A percentage, so never unit-converted."),
				"leanMass":   number("Fat-free mass at that reading." + inUnit),
				"fatMass":    number("Fat mass at that reading." + inUnit),
				"category":   nullEnumStr("The band `bodyFatPct` falls in for this sex: `essential`, `athletic`, `fitness`, `average` or `obese`. `null` when the sex is unknown — the bands genuinely differ by sex, so no label is given rather than a wrong one.", "essential", "athletic", "fitness", "average", "obese"),
			}, "date", "bodyFatPct", "leanMass", "fatMass", "category"),

		"HealthyRange": object("The weight range corresponding to a BMI of 18.5 to 24.9 at the account's height.",
			map[string]*Schema{
				"minKg": number("Lower bound." + inUnit + " Not necessarily kg, despite the name."),
				"maxKg": number("Upper bound." + inUnit + " Not necessarily kg, despite the name."),
			}, "minKg", "maxKg"),

		"WeightGoal": object("The active weight goal, echoed in the account's unit. Read-only here: setting a goal has "+
			"real health implications, so it stays in the app where the numbers can be explained.",
			map[string]*Schema{
				"id":               integer("Goal identifier."),
				"user_id":          integer("The account that owns it."),
				"start_weight":     number("Weight when the goal was set." + inUnit),
				"start_date":       dateStr("The day the goal was set."),
				"target_weight":    number("The target." + inUnit),
				"pace_mode":        enumStr("`rate` sets a weekly pace directly; `date` derives one from `target_date`.", "rate", "date"),
				"rate_kg_per_week": number("The requested pace per week. Present when `pace_mode` is `rate`." + inUnit + " Not necessarily kg, despite the name."),
				"target_date":      dateStr("The requested finish date. Present when `pace_mode` is `date`."),
				"activity_level":   enumStr("The activity level recorded with the goal: `sedentary`, `light`, `moderate`, `active` or `very_active`.", "sedentary", "light", "moderate", "active", "very_active"),
				"status":           enumStr("`active`, `achieved` or `abandoned` — always `active` here, since this endpoint only returns the active goal.", "active", "achieved", "abandoned"),
				"achieved_at":      dateTime("When the goal was met (UTC). Absent while it is active."),
				"created_at":       dateTime("When the goal was created (UTC)."),
				"updated_at":       dateTime("When it was last changed (UTC)."),
			}, "id", "user_id", "start_weight", "start_date", "target_weight", "pace_mode", "status", "created_at", "updated_at"),

		"PlanComputed": object("The energy budget and the projection it produces.",
			map[string]*Schema{
				"bmr":           number("Basal metabolic rate, kcal/day, per `bmrFormula`."),
				"tdee":          number("Total daily energy expenditure: BMR times the activity factor, kcal/day."),
				"budgetKcal":    integer("The recommended daily intake, kcal."),
				"budgetClamped": boolean("Whether the budget was raised to the safe floor for this sex. The matching `budget_clamped` warning is also emitted."),
				"rateKgPerWeek": number("The goal's pace per week." + inUnit + " Not necessarily kg, despite the name."),
				"etaWeeks":      number("Weeks to the target at that pace."),
				"etaDate":       nullable(dateStr("The date `etaWeeks` lands on. `null` when the ETA is not a finite number.")),
				"planCurve": array(ref("CurvePoint"), "Projected weight week by week. It decelerates: BMR is recomputed at each "+
					"simulated weight, so the deficit shrinks as the weight does. Stops at the target, at a plateau, or after 160 weeks."),
				"bmrFormula": enumStr("Which estimator produced `bmr`: `katch_mcardle` when a body-fat reading was available (it works off lean mass, the more accurate basis), `mifflin_st_jeor` otherwise.",
					"mifflin_st_jeor", "katch_mcardle"),
			}, "bmr", "tdee", "budgetKcal", "budgetClamped", "rateKgPerWeek", "etaWeeks", "etaDate", "planCurve", "bmrFormula"),

		"CurvePoint": object("One week of the projected curve.", map[string]*Schema{
			"week":   integer("Weeks from now. Week 0 is the starting weight."),
			"weight": number("Projected weight that week." + inUnit),
		}, "week", "weight"),

		"PlanTrend": object("Observed progress: a least-squares fit over the readings from the last 30 days. "+
			"Independent of the body metrics, so it works even when `computed` is `null`.",
			map[string]*Schema{
				"slopeKgPerWeek": number("Fitted change per week, negative when losing." + inUnit + " Not necessarily kg, despite the name."),
				"hasData":        boolean("Whether there were enough readings — two, at least a week apart — to fit a line."),
				"projectedWeeks": number("Weeks to the target at the observed rate. `-1` when it cannot be projected."),
				"projectedDate":  nullable(dateStr("The date `projectedWeeks` lands on. `null` when it cannot be projected.")),
				"status": enumStr("Progress against the plan's pace: `ahead` from 110%, `on_track` from 85%, `behind` below that. "+
					"`stalled` when the fitted change is under 0.05 per week, `wrong_direction` when it moves away from the target, "+
					"`insufficient_data` when `hasData` is false.",
					"insufficient_data", "stalled", "wrong_direction", "behind", "on_track", "ahead"),
			}, "slopeKgPerWeek", "hasData", "projectedWeeks", "projectedDate", "status"),

		"SeriesPoint": object("One logged weight reading, as charted.", map[string]*Schema{
			"date":    dateStr("The day of the reading."),
			"weight":  number("The reading." + inUnit),
			"bodyFat": number("Body fat percentage recorded with it. Absent when the scale reported weight only."),
		}, "date", "weight"),

		"PlanWarning": object("A safety note about the plan. Branch on `code`; `message` is English prose that can change.",
			map[string]*Schema{
				"code": enumStr("What is being flagged: `budget_clamped` (the budget was raised to the safe floor), "+
					"`aggressive_rate` (the pace exceeds 1% of body weight per week), `target_underweight` or `target_obese` "+
					"(the target weight falls in that BMI band).",
					"budget_clamped", "aggressive_rate", "target_underweight", "target_obese"),
				"message": str("Human-readable explanation, in English."),
			}, "code", "message"),
	}
}

// mergeProps combines maps of named schemas — properties, or the components
// map itself. Later maps win on key collision.
func mergeProps(maps ...map[string]*Schema) map[string]*Schema {
	out := map[string]*Schema{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func intp(n int) *int { return &n }

// respRef points at a shared response in components.
func respRef(name string) *Response {
	// OpenAPI allows $ref for responses, but modelling that would mean a
	// Response union type used in exactly one place. Copying the shared
	// definition keeps the struct simple and the output self-contained, which
	// matters more for a document people read than DRY does.
	return sharedResponses()[name]
}

// errs builds the error responses an operation can return, always including
// the ones every authenticated endpoint shares.
func errs(extra map[string]*Response) map[string]*Response {
	out := map[string]*Response{
		"401": respRef("Unauthorized"),
		"403": respRef("InsufficientScope"),
		"429": respRef("RateLimited"),
		"500": respRef("ServerError"),
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// ok200 is a plain successful JSON response.
func ok200(desc string, s *Schema) *Response {
	return &Response{Description: desc, Content: jsonBody(s)}
}

// created201 is a creation response with a Location header.
func created201(desc string, s *Schema, location string) *Response {
	return &Response{
		Description: desc,
		Content:     jsonBody(s),
		Headers: map[string]Header{
			"Location": {Description: location, Schema: str("")},
		},
	}
}

var noContent204 = &Response{Description: "Deleted. No body."}

func paths() map[string]*PathItem {
	dateParam := Parameter{
		Name: "date", In: "path", Required: true,
		Description: "A calendar date in the account's time zone.",
		Schema:      dateStr(""),
	}
	idParam := Parameter{
		Name: "id", In: "path", Required: true,
		Description: "The resource's identifier.",
		Schema:      integer(""),
	}
	limitParam := Parameter{
		Name: "limit", In: "query",
		Description: "Maximum results to return. Values above 200 are clamped to 200.",
		Schema:      withRange(&Schema{Type: "integer", Default: 50}, 1, 200),
	}

	return map[string]*PathItem{
		"/openapi.json": {Get: &Operation{
			OperationID: "getOpenAPI",
			Summary:     "This document",
			Description: "Returns this OpenAPI description. The only endpoint that needs no token.",
			Tags:        []string{"Meta"},
			Security:    []SecurityRequirement{{}},
			Responses: map[string]*Response{
				"200": ok200("The OpenAPI 3.1 document.", &Schema{Type: "object", AdditionalProperties: true}),
			},
		}},

		"/me": {
			Get: &Operation{
				OperationID: "getMe",
				Summary:     "The authenticated account and token",
				Description: "Requires a valid token but no particular scope — this is how a client discovers " +
					"which scopes it holds and, via `features`, which optional features the account has on.",
				Tags:      []string{"Account"},
				Responses: merge(map[string]*Response{"200": ok200("The account, the token, the server, and the account's enabled features.", ref("Me"))}, errs(nil)),
			},
			Patch: &Operation{
				OperationID: "updateMe",
				Summary:     "Change account settings",
				Description: "Only settings that affect how the rest of the API behaves are writable. " +
					"Authentication settings (password, 2FA, passkeys, email) are deliberately NOT — those are " +
					"step-up gated in the app, and step-up is meaningless for a bearer token, so allowing them " +
					"would turn one leaked token into account takeover.",
				Tags:        []string{"Account"},
				Scope:       service.ScopeSettingsWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeSettingsWrite}}},
				RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("SettingsPatch"))},
				Responses: merge(map[string]*Response{
					"200": ok200("The updated account.", ref("Me")),
					"400": respRef("BadRequest"), "422": respRef("Unprocessable"),
				}, errs(nil)),
			},
		},

		"/entries": {
			Get: &Operation{
				OperationID: "listEntries",
				Summary:     "List calorie entries",
				Description: "Newest first. Filter by a single `date`, or by a `from`/`to` range — not both. Paginated by keyset.",
				Tags:        []string{"Entries"},
				Scope:       service.ScopeEntriesRead,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeEntriesRead}}},
				Parameters: []Parameter{
					{Name: "date", In: "query", Description: "Return entries for this single day.", Schema: dateStr("")},
					{Name: "from", In: "query", Description: "Start of an inclusive date range.", Schema: dateStr("")},
					{Name: "to", In: "query", Description: "End of an inclusive date range.", Schema: dateStr("")},
					limitParam,
					{Name: "cursor", In: "query", Description: "The `next_cursor` from a previous response.", Schema: str("")},
					linkedUserParam,
				},
				Responses: merge(map[string]*Response{
					"200": ok200("A page of entries.", ref("EntryList")),
					"400": respRef("BadRequest"),
					"422": respRef("Unprocessable"),
				}, errs(nil)),
			},
			Post: &Operation{
				OperationID: "createEntry",
				Summary:     "Create a calorie entry",
				Description: "Needs `calories`, at least one macro, or both. When the account computes calories from macros, a supplied `calories` is replaced by the computed value.",
				Tags:        []string{"Entries"},
				Scope:       service.ScopeEntriesWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeEntriesWrite}}},
				Parameters:  []Parameter{idempotencyParam},
				RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("EntryInput"))},
				Responses: merge(map[string]*Response{
					"201": created201("The created entry.", ref("Entry"), "URL of the created entry."),
					"400": respRef("BadRequest"),
					"409": respRef("Conflict"),
					"422": respRef("Unprocessable"),
				}, errs(nil)),
			},
		},
		"/entries/{id}": {
			Get: &Operation{
				OperationID: "getEntry", Summary: "Fetch one calorie entry",
				Tags: []string{"Entries"}, Scope: service.ScopeEntriesRead,
				Security:   []SecurityRequirement{{"bearerAuth": {service.ScopeEntriesRead}}},
				Parameters: []Parameter{idParam},
				Responses: merge(map[string]*Response{
					"200": ok200("The entry.", ref("Entry")),
					"400": respRef("BadRequest"), "404": respRef("NotFound"),
				}, errs(nil)),
			},
			Patch: &Operation{
				OperationID: "updateEntry", Summary: "Change a calorie entry",
				Description: "Only the fields present in the body are changed. Send `null` to clear the name or a macro.",
				Tags:        []string{"Entries"}, Scope: service.ScopeEntriesWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeEntriesWrite}}},
				Parameters:  []Parameter{idParam},
				RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("EntryPatch"))},
				Responses: merge(map[string]*Response{
					"200": ok200("The updated entry.", ref("Entry")),
					"400": respRef("BadRequest"), "404": respRef("NotFound"),
					"422": respRef("Unprocessable"),
				}, errs(nil)),
			},
			Delete: &Operation{
				OperationID: "deleteEntry", Summary: "Delete a calorie entry",
				Tags: []string{"Entries"}, Scope: service.ScopeEntriesWrite,
				Security:   []SecurityRequirement{{"bearerAuth": {service.ScopeEntriesWrite}}},
				Parameters: []Parameter{idParam},
				Responses: merge(map[string]*Response{
					"204": noContent204, "400": respRef("BadRequest"), "404": respRef("NotFound"),
				}, errs(nil)),
			},
		},

		"/weight": {Get: &Operation{
			OperationID: "listWeight", Summary: "List weight readings",
			Description: "Newest first, optionally bounded by `from`/`to`.",
			Tags:        []string{"Weight"}, Scope: service.ScopeWeightRead,
			Security: []SecurityRequirement{{"bearerAuth": {service.ScopeWeightRead}}},
			Parameters: []Parameter{
				{Name: "from", In: "query", Description: "Start of an inclusive date range.", Schema: dateStr("")},
				{Name: "to", In: "query", Description: "End of an inclusive date range.", Schema: dateStr("")},
				limitParam,
				{Name: "cursor", In: "query", Description: "The `next_cursor` from a previous response.", Schema: str("")},
				linkedUserParam,
			},
			Responses: merge(map[string]*Response{
				"200": ok200("The readings.", ref("WeightList")),
				"400": respRef("BadRequest"), "422": respRef("Unprocessable"),
			}, errs(nil)),
		}},
		"/weight/{date}": {
			Get: &Operation{
				OperationID: "getWeight", Summary: "Fetch one day's weight",
				Tags: []string{"Weight"}, Scope: service.ScopeWeightRead,
				Security:   []SecurityRequirement{{"bearerAuth": {service.ScopeWeightRead}}},
				Parameters: []Parameter{dateParam},
				Responses: merge(map[string]*Response{
					"200": ok200("The reading.", ref("Weight")),
					"400": respRef("BadRequest"), "404": respRef("NotFound"),
				}, errs(nil)),
			},
			Put: &Operation{
				OperationID: "putWeight", Summary: "Record a day's weight",
				Description: "Idempotent: repeating the same request is harmless, which makes it safe for a scale integration to retry. Returns 201 the first time a date is written and 200 thereafter. " +
					"`body_fat` is three-state: omit it and any stored reading for that day is left alone, send `null` to clear it, send a number to record it.",
				Tags:        []string{"Weight"}, Scope: service.ScopeWeightWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeWeightWrite}}},
				Parameters:  []Parameter{dateParam},
				RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("WeightInput"))},
				Responses: merge(map[string]*Response{
					"200": ok200("The reading was replaced.", ref("Weight")),
					"201": created201("The reading was created.", ref("Weight"), "URL of the reading."),
					"400": respRef("BadRequest"), "422": respRef("Unprocessable"),
				}, errs(nil)),
			},
			Delete: &Operation{
				OperationID: "deleteWeight", Summary: "Delete a day's weight",
				Tags: []string{"Weight"}, Scope: service.ScopeWeightWrite,
				Security:   []SecurityRequirement{{"bearerAuth": {service.ScopeWeightWrite}}},
				Parameters: []Parameter{dateParam},
				Responses: merge(map[string]*Response{
					"204": noContent204, "400": respRef("BadRequest"), "404": respRef("NotFound"),
				}, errs(nil)),
			},
		},

		"/todos": {
			Get: &Operation{
				OperationID: "listTodos", Summary: "List todo definitions",
				Description: "The recurring todos themselves. For what is due on a given day, use `/todos/day/{date}`.",
				Tags:        []string{"Todos"}, Scope: service.ScopeTodosRead,
				Security:  []SecurityRequirement{{"bearerAuth": {service.ScopeTodosRead}}},
				Responses: merge(map[string]*Response{"200": ok200("The todos.", ref("TodoList"))}, errs(nil)),
			},
			Post: &Operation{
				OperationID: "createTodo", Summary: "Create a todo",
				Tags: []string{"Todos"}, Scope: service.ScopeTodosWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeTodosWrite}}},
				Parameters:  []Parameter{idempotencyParam},
				RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("TodoInput"))},
				Responses: merge(map[string]*Response{
					"201": created201("The created todo.", ref("Todo"), "URL of the created todo."),
					"400": respRef("BadRequest"), "409": respRef("Conflict"),
					"422": respRef("Unprocessable"),
				}, errs(nil)),
			},
		},
		"/todos/day/{date}": {Get: &Operation{
			OperationID: "listTodosForDay", Summary: "Todos due on a date",
			Description: "The todos actually scheduled for that date, with completion, streak, and missed-since. Timed todos come first in time order.",
			Tags:        []string{"Todos"}, Scope: service.ScopeTodosRead,
			Security:   []SecurityRequirement{{"bearerAuth": {service.ScopeTodosRead}}},
			Parameters: []Parameter{dateParam, linkedUserParam},
			Responses: merge(map[string]*Response{
				"200": ok200("The todos due that day.", ref("TodoDayList")),
				"400": respRef("BadRequest"),
			}, errs(nil)),
		}},
		"/todos/{id}": {
			Patch: &Operation{
				OperationID: "updateTodo", Summary: "Change a todo",
				Tags: []string{"Todos"}, Scope: service.ScopeTodosWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeTodosWrite}}},
				Parameters:  []Parameter{idParam},
				RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("TodoPatch"))},
				Responses: merge(map[string]*Response{
					"200": ok200("The updated todo.", ref("Todo")),
					"400": respRef("BadRequest"), "404": respRef("NotFound"),
					"422": respRef("Unprocessable"),
				}, errs(nil)),
			},
			Delete: &Operation{
				OperationID: "deleteTodo", Summary: "Delete a todo",
				Description: "The todo is archived rather than erased, so its completion history and streaks survive. It disappears from every read endpoint either way.",
				Tags:        []string{"Todos"}, Scope: service.ScopeTodosWrite,
				Security:   []SecurityRequirement{{"bearerAuth": {service.ScopeTodosWrite}}},
				Parameters: []Parameter{idParam},
				Responses: merge(map[string]*Response{
					"204": noContent204, "400": respRef("BadRequest"), "404": respRef("NotFound"),
				}, errs(nil)),
			},
		},
		"/todos/{id}/completions/{date}": {Put: &Operation{
			OperationID: "setTodoCompletion", Summary: "Mark a todo done or not done",
			Description: "States the desired result rather than toggling, so a retried request cannot silently undo itself.",
			Tags:        []string{"Todos"}, Scope: service.ScopeTodosWrite,
			Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeTodosWrite}}},
			Parameters:  []Parameter{idParam, dateParam},
			RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("CompletionInput"))},
			Responses: merge(map[string]*Response{
				"200": ok200("The resulting completion state.", ref("Completion")),
				"400": respRef("BadRequest"), "404": respRef("NotFound"),
			}, errs(nil)),
		}},

		"/saved-foods": {
			Get: &Operation{
				OperationID: "listSavedFoods", Summary: "List saved foods",
				Description: "Most-used first, then most-recently-used, then newest first. " +
					"Not paginated: an account holds at most 200 saved foods, so this always " +
					"returns the complete set.",
				Tags: []string{"Saved foods"}, Scope: service.ScopeFoodsRead,
				Security: []SecurityRequirement{{"bearerAuth": {service.ScopeFoodsRead}}},
				// No 400: the operation takes no input to reject, matching the
				// other parameterless collections (listTodos, listLinks).
				Responses: merge(map[string]*Response{
					"200": ok200("The saved foods.", ref("SavedFoodList")),
				}, errs(nil)),
			},
			Post: &Operation{
				OperationID: "createSavedFood", Summary: "Create a saved food",
				Tags: []string{"Saved foods"}, Scope: service.ScopeFoodsWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeFoodsWrite}}},
				Parameters:  []Parameter{idempotencyParam},
				RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("SavedFoodInput"))},
				Responses: merge(map[string]*Response{
					"201": created201("The created food.", ref("SavedFood"), "URL of the created food."),
					"400": respRef("BadRequest"), "409": respRef("Conflict"),
					"422": respRef("Unprocessable"),
				}, errs(nil)),
			},
		},
		"/saved-foods/{id}": {
			Patch: &Operation{
				OperationID: "updateSavedFood", Summary: "Change a saved food",
				Tags: []string{"Saved foods"}, Scope: service.ScopeFoodsWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeFoodsWrite}}},
				Parameters:  []Parameter{idParam},
				RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("SavedFoodPatch"))},
				Responses: merge(map[string]*Response{
					"200": ok200("The updated food.", ref("SavedFood")),
					"400": respRef("BadRequest"), "404": respRef("NotFound"),
					"409": respRef("Conflict"), "422": respRef("Unprocessable"),
				}, errs(nil)),
			},
			Delete: &Operation{
				OperationID: "deleteSavedFood", Summary: "Delete a saved food",
				Tags: []string{"Saved foods"}, Scope: service.ScopeFoodsWrite,
				Security:   []SecurityRequirement{{"bearerAuth": {service.ScopeFoodsWrite}}},
				Parameters: []Parameter{idParam},
				Responses: merge(map[string]*Response{
					"204": noContent204, "400": respRef("BadRequest"), "404": respRef("NotFound"),
				}, errs(nil)),
			},
		},
		"/saved-foods/{id}/track": {Post: &Operation{
			OperationID: "trackSavedFood", Summary: "Log a saved food as an entry",
			Description: "Creates a calorie entry from the saved food and returns it. Requires `entries:write`, not `foods:write` — it writes an entry.",
			Tags:        []string{"Saved foods"}, Scope: service.ScopeEntriesWrite,
			Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeEntriesWrite}}},
			Parameters:  []Parameter{idParam, idempotencyParam},
			RequestBody: &RequestBody{Content: jsonBody(ref("TrackInput"))},
			Responses: merge(map[string]*Response{
				"201": created201("The created entry.", ref("Entry"), "URL of the created entry."),
				"400": respRef("BadRequest"), "404": respRef("NotFound"),
				"409": respRef("Conflict"), "422": respRef("Unprocessable"),
			}, errs(nil)),
		}},

		"/notes/{date}": {
			Get: &Operation{
				OperationID: "getNote", Summary: "Fetch a day's note",
				Description: "A day with no note returns 200 with empty content, not 404.",
				Tags:        []string{"Notes"}, Scope: service.ScopeNotesRead,
				Security:   []SecurityRequirement{{"bearerAuth": {service.ScopeNotesRead}}},
				Parameters: []Parameter{dateParam, linkedUserParam},
				Responses: merge(map[string]*Response{
					"200": ok200("The note.", ref("Note")),
					"400": respRef("BadRequest"), "409": respRef("Conflict"),
				}, errs(nil)),
			},
			Put: &Operation{
				OperationID: "putNote", Summary: "Write a day's note",
				Description: "Replaces the whole note. Writing an empty string deletes it. Returns 409 when daily notes are not enabled for the account.",
				Tags:        []string{"Notes"}, Scope: service.ScopeNotesWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeNotesWrite}}},
				Parameters:  []Parameter{dateParam},
				RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("NoteInput"))},
				Responses: merge(map[string]*Response{
					"200": ok200("The stored note.", ref("Note")),
					"400": respRef("BadRequest"), "409": respRef("Conflict"),
					"422": respRef("Unprocessable"),
				}, errs(nil)),
			},
		},

		"/links": {Get: &Operation{
			OperationID: "listLinks", Summary: "List linked accounts",
			Description: "The accounts linked to yours, what each shares with you, and what you share back. " +
				"Use `user_id` as the `user` parameter on a read endpoint.",
			Tags: []string{"Links"}, Scope: service.ScopeLinksRead,
			Security:  []SecurityRequirement{{"bearerAuth": {service.ScopeLinksRead}}},
			Responses: merge(map[string]*Response{"200": ok200("The linked accounts.", ref("LinkList"))}, errs(nil)),
		}},

		"/barcode/{code}": {Get: &Operation{
			OperationID: "lookupBarcode", Summary: "Look up a product by barcode",
			Description: "Resolves an EAN-8, UPC-A, or EAN-13 barcode via OpenFoodFacts. " +
				"Rate limited per account at the same rate as the app's own scanner, since it " +
				"queries the same third-party database. " +
				"Returns 404 when barcode lookup is disabled on the server.",
			Tags: []string{"Saved foods"}, Scope: service.ScopeFoodsRead,
			Security: []SecurityRequirement{{"bearerAuth": {service.ScopeFoodsRead}}},
			Parameters: []Parameter{{
				Name: "code", In: "path", Required: true,
				Description: "An 8-13 digit barcode. The GS1 check digit is verified.",
				Schema:      str(""),
			}},
			Responses: merge(map[string]*Response{
				"200": ok200("The product.", ref("BarcodeProduct")),
				"400": respRef("BadRequest"),
				"404": respRef("NotFound"),
				"422": respRef("Unprocessable"),
				"504": {Description: "The food database did not answer in time.", Content: problemBody()},
			}, errs(nil)),
		}},

		"/ai/estimate": {Post: &Operation{
			OperationID: "estimateFromPhoto", Summary: "Estimate nutrition from a food photo",
			Description: "Requires the `ai:estimate` scope, which no other scope implies — every call " +
				"spends the operator's AI budget, so it must be granted deliberately. The account's " +
				"daily AI limit applies here exactly as it does in the app, as does a per-account " +
				"rate limit matching the app's own estimate endpoint — this is not a cheaper path " +
				"to the provider. Returns 404 when no AI provider is configured. This is the one " +
				"`POST` that does not honour `Idempotency-Key`: sending the header returns 400 " +
				"rather than being ignored, so a caller is never left believing a retry is safe " +
				"when it is not.",
			Tags: []string{"AI"}, Scope: service.ScopeAIEstimate,
			Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeAIEstimate}}},
			RequestBody: &RequestBody{Required: true, Content: jsonBody(ref("EstimateInput"))},
			Responses: merge(map[string]*Response{
				"200": ok200("The estimate.", ref("Estimate")),
				"400": respRef("BadRequest"), "404": respRef("NotFound"),
				"413": {Description: "The image exceeds the 10 MB limit.", Content: problemBody()},
				"429": {
					Description: "Rate limited, or the account's daily AI allowance is used up " +
						"(type `.../problems/ai-daily-limit`).",
					Content: problemBody(),
					Headers: map[string]Header{
						"Retry-After": {Description: "Seconds to wait before retrying.", Schema: integer("")},
					},
				},
			}, errs(nil)),
		}},

		"/plan": {Get: &Operation{
			OperationID: "getPlan", Summary: "The weight-loss plan",
			Description: "Read-only. Unlike the app's own plan endpoint, this one never writes — a `plan:read` token cannot change state, so a goal that has been reached is reported but not transitioned.",
			Tags:        []string{"Plan"}, Scope: service.ScopePlanRead,
			Security:  []SecurityRequirement{{"bearerAuth": {service.ScopePlanRead}}},
			Responses: merge(map[string]*Response{"200": ok200("The plan.", ref("Plan"))}, errs(nil)),
		}},
	}
}

// merge combines response maps; the first argument wins on collision.
func merge(primary, fallback map[string]*Response) map[string]*Response {
	out := map[string]*Response{}
	for k, v := range fallback {
		out[k] = v
	}
	for k, v := range primary {
		out[k] = v
	}
	return out
}
