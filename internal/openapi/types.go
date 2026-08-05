// Package openapi builds Schautrack's OpenAPI 3.1 description of /api/v1.
//
// The document is constructed in Go rather than hand-written as YAML, for one
// reason: it can then be checked mechanically. TestV1RoutesMatchSpec compares
// Build().Operations() against a walk of the real chi router and fails if
// either side has an endpoint the other does not. A YAML file has no such
// coupling, which is precisely how the older hand-written docs/api-internal.md drifted
// away from the routes it claimed to describe.
//
// Everything downstream derives from this one object: the served
// GET /api/v1/openapi.json, the committed api/openapi.json, and the generated
// docs/api-v1.md.
package openapi

import "encoding/json"

// Document is an OpenAPI 3.1 document. Only the subset of the specification
// this API actually uses is modelled — an incomplete-but-honest struct beats a
// complete one with fields nobody sets.
type Document struct {
	OpenAPI    string                `json:"openapi"`
	Info       Info                  `json:"info"`
	Servers    []Server              `json:"servers,omitempty"`
	Tags       []Tag                 `json:"tags,omitempty"`
	Paths      map[string]*PathItem  `json:"paths"`
	Components Components            `json:"components"`
	Security   []SecurityRequirement `json:"security,omitempty"`
}

type Info struct {
	Title       string   `json:"title"`
	Version     string   `json:"version"`
	Summary     string   `json:"summary,omitempty"`
	Description string   `json:"description,omitempty"`
	License     *License `json:"license,omitempty"`
	Contact     *Contact `json:"contact,omitempty"`
}

type License struct {
	Name       string `json:"name"`
	Identifier string `json:"identifier,omitempty"`
}

type Contact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

type Server struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

type Tag struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Put    *Operation `json:"put,omitempty"`
	Patch  *Operation `json:"patch,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
}

// Operations returns the method/operation pairs present on this path item.
func (p *PathItem) Operations() map[string]*Operation {
	out := map[string]*Operation{}
	for method, op := range map[string]*Operation{
		"GET": p.Get, "POST": p.Post, "PUT": p.Put, "PATCH": p.Patch, "DELETE": p.Delete,
	} {
		if op != nil {
			out[method] = op
		}
	}
	return out
}

type Operation struct {
	OperationID string                `json:"operationId"`
	Summary     string                `json:"summary"`
	Description string                `json:"description,omitempty"`
	Tags        []string              `json:"tags,omitempty"`
	Parameters  []Parameter           `json:"parameters,omitempty"`
	RequestBody *RequestBody          `json:"requestBody,omitempty"`
	Responses   map[string]*Response  `json:"responses"`
	Security    []SecurityRequirement `json:"security,omitempty"`

	// Scope is not an OpenAPI field; it records which token scope guards this
	// operation so the parity test and the docs generator can both read it
	// from the same place. It is stripped from the marshalled document.
	Scope string `json:"-"`
}

type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Description string  `json:"description,omitempty"`
	Required    bool    `json:"required,omitempty"`
	Schema      *Schema `json:"schema"`
}

type RequestBody struct {
	Description string               `json:"description,omitempty"`
	Required    bool                 `json:"required,omitempty"`
	Content     map[string]MediaType `json:"content"`
}

type Response struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
	Headers     map[string]Header    `json:"headers,omitempty"`
}

type Header struct {
	Description string  `json:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}

type MediaType struct {
	Schema *Schema `json:"schema"`
}

type Components struct {
	Schemas         map[string]*Schema         `json:"schemas"`
	SecuritySchemes map[string]*SecurityScheme `json:"securitySchemes"`
	Responses       map[string]*Response       `json:"responses,omitempty"`
}

type SecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
	Description  string `json:"description,omitempty"`
}

// SecurityRequirement maps a security scheme name to the scopes it must carry.
type SecurityRequirement map[string][]string

// Schema is a JSON Schema 2020-12 subset. OpenAPI 3.1 uses JSON Schema
// directly, so nullability is expressed as a type union (["integer","null"])
// rather than the 3.0-era `nullable: true` keyword.
type Schema struct {
	Ref string `json:"$ref,omitempty"`

	Type        any      `json:"type,omitempty"` // string, or []string for unions
	Format      string   `json:"format,omitempty"`
	Description string   `json:"description,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Enum        []any    `json:"enum,omitempty"`
	Example     any      `json:"example,omitempty"`
	Default     any      `json:"default,omitempty"`
	Minimum     *float64 `json:"minimum,omitempty"`
	Maximum     *float64 `json:"maximum,omitempty"`
	MinLength   *int     `json:"minLength,omitempty"`
	MaxLength   *int     `json:"maxLength,omitempty"`

	Properties           map[string]*Schema `json:"properties,omitempty"`
	Required             []string           `json:"required,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
	AdditionalProperties any                `json:"additionalProperties,omitempty"`
}

// JSON renders the document as indented JSON. Go sorts map keys when
// marshalling, so the output is byte-stable across runs — which is what lets
// CI diff the committed api/openapi.json against a fresh build.
func (d *Document) JSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// --- Schema constructors --------------------------------------------------
//
// These exist to keep spec.go readable. Without them the document is an
// unbroken wall of struct literals and nobody reviews it.

func str(desc string) *Schema     { return &Schema{Type: "string", Description: desc} }
func integer(desc string) *Schema { return &Schema{Type: "integer", Description: desc} }
func number(desc string) *Schema  { return &Schema{Type: "number", Description: desc} }
func boolean(desc string) *Schema { return &Schema{Type: "boolean", Description: desc} }

// nullable wraps a schema's type in a union with "null".
func nullable(s *Schema) *Schema {
	if t, ok := s.Type.(string); ok {
		s.Type = []string{t, "null"}
	}
	return s
}

func nullInt(desc string) *Schema { return nullable(integer(desc)) }
func nullStr(desc string) *Schema { return nullable(str(desc)) }

// dateStr is a YYYY-MM-DD calendar date.
func dateStr(desc string) *Schema {
	s := str(desc)
	s.Format = "date"
	s.Pattern = `^\d{4}-\d{2}-\d{2}$`
	s.Example = "2026-08-05"
	return s
}

// dateTime is an RFC 3339 timestamp.
func dateTime(desc string) *Schema {
	s := str(desc)
	s.Format = "date-time"
	return s
}

func ref(name string) *Schema { return &Schema{Ref: "#/components/schemas/" + name} }

func array(items *Schema, desc string) *Schema {
	return &Schema{Type: "array", Items: items, Description: desc}
}

// object builds an object schema. required names properties that are always
// present in a response, or mandatory in a request body.
func object(desc string, props map[string]*Schema, required ...string) *Schema {
	return &Schema{Type: "object", Description: desc, Properties: props, Required: required}
}

func withRange(s *Schema, min, max float64) *Schema {
	s.Minimum, s.Maximum = &min, &max
	return s
}

// jsonBody is the request/response content map for application/json.
func jsonBody(s *Schema) map[string]MediaType {
	return map[string]MediaType{"application/json": {Schema: s}}
}

// problemBody is the content map for an RFC 9457 error response.
func problemBody() map[string]MediaType {
	return map[string]MediaType{"application/problem+json": {Schema: ref("Problem")}}
}
