package openapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Validate checks a decoded JSON value against a schema from this document.
//
// This exists to close a hole in TestV1RoutesMatchSpec: that test proves the
// route table and the spec agree on which endpoints exist, but says nothing
// about what they return. Renaming a field on a response struct would leave
// every test green while the published document quietly described a shape the
// server no longer sends.
//
// It is a targeted validator, not a general JSON Schema implementation. It
// covers exactly the constructs schemas() actually uses — $ref, type (including
// ["x","null"] unions), properties, required, items, enum, and numeric bounds —
// and deliberately nothing else. A general validator would mean a new
// dependency and a second, subtly different interpretation of the same
// document; this one walks the very structs the document is built from, so the
// two cannot disagree.
//
// Unknown properties are an ERROR, not a warning. A response carrying a field
// the spec omits is undocumented API surface: clients start depending on it,
// and it becomes a de facto contract nobody wrote down.
func (d *Document) Validate(schemaName string, value any) error {
	s, ok := d.Components.Schemas[schemaName]
	if !ok {
		return fmt.Errorf("no schema named %q in the document", schemaName)
	}
	var errs []string
	d.validate(s, value, schemaName, &errs)
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return fmt.Errorf("%s does not match its schema:\n  - %s", schemaName, strings.Join(errs, "\n  - "))
}

// ValidateJSON is Validate over raw JSON bytes.
func (d *Document) ValidateJSON(schemaName string, raw []byte) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("%s: body is not valid JSON: %w", schemaName, err)
	}
	return d.Validate(schemaName, v)
}

// resolve follows a $ref to the schema it names.
func (d *Document) resolve(s *Schema) *Schema {
	if s == nil || s.Ref == "" {
		return s
	}
	name, ok := strings.CutPrefix(s.Ref, "#/components/schemas/")
	if !ok {
		return s
	}
	return d.Components.Schemas[name]
}

// typeNames returns a schema's declared types, normalising the string and
// []string forms OpenAPI 3.1 allows.
func typeNames(s *Schema) []string {
	switch t := s.Type.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	}
	return nil
}

func (d *Document) validate(s *Schema, v any, path string, errs *[]string) {
	s = d.resolve(s)
	if s == nil {
		return
	}

	types := typeNames(s)

	if v == nil {
		// A free-form schema (no declared type) accepts anything, null
		// included. Otherwise null is only valid for an explicit union.
		if len(types) > 0 && !contains(types, "null") {
			*errs = append(*errs, fmt.Sprintf("%s: is null, but the spec declares %s", path, strings.Join(types, "|")))
		}
		return
	}

	if len(types) == 0 {
		return // free-form (e.g. the Plan schema)
	}

	switch actual := v.(type) {
	case map[string]any:
		if !contains(types, "object") {
			*errs = append(*errs, fmt.Sprintf("%s: is an object, but the spec declares %s", path, strings.Join(types, "|")))
			return
		}
		d.validateObject(s, actual, path, errs)

	case []any:
		if !contains(types, "array") {
			*errs = append(*errs, fmt.Sprintf("%s: is an array, but the spec declares %s", path, strings.Join(types, "|")))
			return
		}
		for i, item := range actual {
			d.validate(s.Items, item, fmt.Sprintf("%s[%d]", path, i), errs)
		}

	case string:
		if !contains(types, "string") {
			*errs = append(*errs, fmt.Sprintf("%s: is a string, but the spec declares %s", path, strings.Join(types, "|")))
			return
		}
		d.validateEnum(s, actual, path, errs)

	case bool:
		if !contains(types, "boolean") {
			*errs = append(*errs, fmt.Sprintf("%s: is a boolean, but the spec declares %s", path, strings.Join(types, "|")))
		}

	case float64:
		// encoding/json decodes every JSON number as float64, so "integer"
		// has to be checked by value rather than by Go type.
		isInt := actual == float64(int64(actual))
		switch {
		case contains(types, "number"):
		case contains(types, "integer") && isInt:
		case contains(types, "integer"):
			*errs = append(*errs, fmt.Sprintf("%s: is %v, but the spec declares integer", path, actual))
			return
		default:
			*errs = append(*errs, fmt.Sprintf("%s: is a number, but the spec declares %s", path, strings.Join(types, "|")))
			return
		}
		if s.Minimum != nil && actual < *s.Minimum {
			*errs = append(*errs, fmt.Sprintf("%s: %v is below the documented minimum %v", path, actual, *s.Minimum))
		}
		if s.Maximum != nil && actual > *s.Maximum {
			*errs = append(*errs, fmt.Sprintf("%s: %v is above the documented maximum %v", path, actual, *s.Maximum))
		}

	default:
		*errs = append(*errs, fmt.Sprintf("%s: unexpected value of Go type %T", path, v))
	}
}

func (d *Document) validateObject(s *Schema, obj map[string]any, path string, errs *[]string) {
	for _, name := range s.Required {
		if _, present := obj[name]; !present {
			*errs = append(*errs, fmt.Sprintf("%s.%s: required by the spec but absent from the response", path, name))
		}
	}

	// additionalProperties: true marks a deliberately free-form object (Plan),
	// where extra keys are the whole point.
	freeForm := s.AdditionalProperties == true

	for key, val := range obj {
		prop, declared := s.Properties[key]
		if !declared {
			if !freeForm {
				*errs = append(*errs, fmt.Sprintf("%s.%s: present in the response but undocumented", path, key))
			}
			continue
		}
		d.validate(prop, val, path+"."+key, errs)
	}
}

func (d *Document) validateEnum(s *Schema, actual string, path string, errs *[]string) {
	if len(s.Enum) == 0 {
		return
	}
	for _, allowed := range s.Enum {
		if allowed == actual {
			return
		}
	}
	*errs = append(*errs, fmt.Sprintf("%s: %q is not one of the documented values %v", path, actual, s.Enum))
}
