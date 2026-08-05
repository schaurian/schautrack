package openapi

import (
	"fmt"
	"sort"

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
hours.

## Rate limits

Two limits apply: one per IP address and one per token. Exceeding either
returns ` + "`429`" + ` with a ` + "`Retry-After`" + ` header giving the number of
seconds until the window reopens. Honour it rather than retrying blindly.`

// Build assembles the OpenAPI document. version is the running build version,
// surfaced so a reader can tell which deployment served the spec.
func Build(version string) *Document {
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
		Servers: []Server{
			{URL: "https://schautrack.com/api/v1", Description: "Production"},
			{URL: "https://staging.schautrack.com/api/v1", Description: "Staging"},
		},
		Tags: []Tag{
			{Name: "Account", Description: "Who the token belongs to and what it may do."},
			{Name: "Entries", Description: "Calorie entries and their macros."},
			{Name: "Weight", Description: "Daily weight readings."},
			{Name: "Todos", Description: "Recurring todos and their completions."},
			{Name: "Saved foods", Description: "Reusable quick-add foods."},
			{Name: "Notes", Description: "One free-text note per day."},
			{Name: "Plan", Description: "The weight-loss plan and its projections."},
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

// idempotencyParam documents the opt-in retry-safety header on the two
// endpoints that create something.
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

	return map[string]*Schema{
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
			"unit":       {Type: "string", Enum: []any{"kg", "lb"}, Description: "The account's weight unit. Readings are stored as entered and never converted."},
			"created_at": dateTime("When first recorded (UTC)."),
			"updated_at": dateTime("When last changed (UTC)."),
		}, "date", "weight", "unit", "created_at", "updated_at"),
		"WeightInput": object("A weight reading.", map[string]*Schema{
			"weight": withRange(number("The reading, in the account's unit."), 0.01, 1500),
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
		"SavedFoodList": object("Saved foods, most-used first.", map[string]*Schema{
			"data": array(ref("SavedFood"), "The foods."),
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

		"Me": object("The authenticated account and token.", map[string]*Schema{
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
		}, "user", "token", "server"),

		"Plan": {
			Type: "object",
			Description: "The weight-loss plan: body metrics, active goal, computed budget, " +
				"projected curve, and trend analysis. Weight-valued fields are in the account's unit.",
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
	}
}

// mergeProps combines property maps. Later maps win on key collision.
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

		"/me": {Get: &Operation{
			OperationID: "getMe",
			Summary:     "The authenticated account and token",
			Description: "Requires a valid token but no particular scope — this is how a client discovers which scopes it holds.",
			Tags:        []string{"Account"},
			Responses:   merge(map[string]*Response{"200": ok200("The account, the token, and the server.", ref("Me"))}, errs(nil)),
		}},

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
				Description: "Idempotent: repeating the same request is harmless, which makes it safe for a scale integration to retry. Returns 201 the first time a date is written and 200 thereafter.",
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
			Parameters: []Parameter{dateParam},
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
				Description: "Most-used first, then most-recently-used.",
				Tags:        []string{"Saved foods"}, Scope: service.ScopeFoodsRead,
				Security:   []SecurityRequirement{{"bearerAuth": {service.ScopeFoodsRead}}},
				Parameters: []Parameter{limitParam},
				Responses: merge(map[string]*Response{
					"200": ok200("The saved foods.", ref("SavedFoodList")),
					"400": respRef("BadRequest"),
				}, errs(nil)),
			},
			Post: &Operation{
				OperationID: "createSavedFood", Summary: "Create a saved food",
				Tags: []string{"Saved foods"}, Scope: service.ScopeFoodsWrite,
				Security:    []SecurityRequirement{{"bearerAuth": {service.ScopeFoodsWrite}}},
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
				Parameters: []Parameter{dateParam},
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
