package handler

import (
	"testing"
)

func TestBodyBool(t *testing.T) {
	tests := []struct {
		name string
		body map[string]any
		key  string
		want bool
	}{
		{"true bool", map[string]any{"enabled": true}, "enabled", true},
		{"false bool", map[string]any{"enabled": false}, "enabled", false},
		{"string on", map[string]any{"enabled": "on"}, "enabled", true},
		{"string true", map[string]any{"enabled": "true"}, "enabled", true},
		{"string false", map[string]any{"enabled": "false"}, "enabled", false},
		{"string off", map[string]any{"enabled": "off"}, "enabled", false},
		{"missing key", map[string]any{}, "enabled", false},
		{"nil value", map[string]any{"enabled": nil}, "enabled", false},
		{"number value", map[string]any{"enabled": 1}, "enabled", false},
		{"empty string", map[string]any{"enabled": ""}, "enabled", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bodyBool(tt.body, tt.key)
			if got != tt.want {
				t.Errorf("bodyBool(%v, %q) = %v, want %v", tt.body, tt.key, got, tt.want)
			}
		})
	}
}

func TestParseMacroInputFromBody(t *testing.T) {
	tests := []struct {
		name string
		body map[string]any
		key  string
		want *int
	}{
		{"float64 value", map[string]any{"goal": float64(2000)}, "goal", intP(2000)},
		{"float64 zero", map[string]any{"goal": float64(0)}, "goal", intP(0)},
		{"string value", map[string]any{"goal": "1500"}, "goal", intP(1500)},
		{"string zero", map[string]any{"goal": "0"}, "goal", intP(0)},
		{"negative float64", map[string]any{"goal": float64(-1)}, "goal", nil},
		{"negative string", map[string]any{"goal": "-5"}, "goal", nil},
		{"missing key", map[string]any{}, "goal", nil},
		{"nil value", map[string]any{"goal": nil}, "goal", nil},
		{"non-numeric string", map[string]any{"goal": "abc"}, "goal", nil},
		{"bool value", map[string]any{"goal": true}, "goal", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMacroInputFromBody(tt.body, tt.key)
			if (got == nil) != (tt.want == nil) {
				t.Errorf("parseMacroInputFromBody() = %v, want %v", got, tt.want)
			} else if got != nil && *got != *tt.want {
				t.Errorf("parseMacroInputFromBody() = %d, want %d", *got, *tt.want)
			}
		})
	}
}

func TestEncodeBase64(t *testing.T) {
	tests := []struct {
		input []byte
		want  string
	}{
		{[]byte("hello"), "aGVsbG8="},
		{[]byte(""), ""},
		{[]byte{0, 1, 2, 3}, "AAECAw=="},
	}
	for _, tt := range tests {
		got := encodeBase64(tt.input)
		if got != tt.want {
			t.Errorf("encodeBase64(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func intP(n int) *int { return &n }
