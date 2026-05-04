package service

import (
	"strings"
	"testing"
)

func TestValidateMealTemplateName(t *testing.T) {
	tests := []struct {
		raw, wantName, wantErr string
	}{
		{"  Breakfast  ", "Breakfast", ""},
		{"", "", "Name is required"},
		{"   ", "", "Name is required"},
		{strings.Repeat("a", 100), strings.Repeat("a", 100), ""},
		{strings.Repeat("a", 101), "", "Name is too long"},
		{"Müsli-Bowl 🥣", "Müsli-Bowl 🥣", ""},
	}
	for _, tt := range tests {
		name, errMsg := ValidateMealTemplateName(tt.raw)
		if name != tt.wantName || errMsg != tt.wantErr {
			t.Errorf("ValidateMealTemplateName(%q) = (%q, %q), want (%q, %q)",
				tt.raw, name, errMsg, tt.wantName, tt.wantErr)
		}
	}
}

func TestValidateMealTemplateAmount(t *testing.T) {
	tests := []struct {
		amount  int
		wantErr bool
	}{
		{0, false},
		{500, false},
		{-9999, false},
		{9999, false},
		{10000, true},
		{-10000, true},
	}
	for _, tt := range tests {
		err := ValidateMealTemplateAmount(tt.amount)
		if (err != "") != tt.wantErr {
			t.Errorf("ValidateMealTemplateAmount(%d) err=%q, wantErr=%v", tt.amount, err, tt.wantErr)
		}
	}
}

func TestValidateMealTemplateMacro(t *testing.T) {
	tests := []struct {
		v       int
		wantErr bool
	}{
		{0, false},
		{500, false},
		{999, false},
		{1000, true},
		{-1, true},
	}
	for _, tt := range tests {
		err := ValidateMealTemplateMacro(tt.v)
		if (err != "") != tt.wantErr {
			t.Errorf("ValidateMealTemplateMacro(%d) err=%q, wantErr=%v", tt.v, err, tt.wantErr)
		}
	}
}

func TestValidateMealTemplateItem(t *testing.T) {
	tests := []struct {
		name    string
		input   MealTemplateItemInput
		wantErr bool
	}{
		{
			"valid calories only",
			MealTemplateItemInput{EntryName: "Oatmeal", Amount: 300},
			false,
		},
		{
			"valid macros only",
			MealTemplateItemInput{Amount: 0, Macros: map[string]int{"protein": 20}},
			false,
		},
		{
			"zero-amount no macros no name rejected",
			MealTemplateItemInput{Amount: 0, Macros: map[string]int{}},
			true,
		},
		{
			"calories out of range",
			MealTemplateItemInput{Amount: 10001},
			true,
		},
		{
			"macro out of range",
			MealTemplateItemInput{Amount: 100, Macros: map[string]int{"protein": 1000}},
			true,
		},
		{
			"macro negative",
			MealTemplateItemInput{Amount: 100, Macros: map[string]int{"fat": -5}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateMealTemplateItem(tt.input)
			if (err != "") != tt.wantErr {
				t.Errorf("got err=%q, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMealTemplateInput(t *testing.T) {
	validItem := MealTemplateItemInput{EntryName: "Bread", Amount: 200}

	t.Run("happy path", func(t *testing.T) {
		in := MealTemplateInput{
			Name:       " Breakfast ",
			IsFavorite: true,
			Items:      []MealTemplateItemInput{validItem, validItem},
		}
		cleaned, err := ValidateMealTemplateInput(in)
		if err != "" {
			t.Fatalf("unexpected error: %s", err)
		}
		if cleaned.Name != "Breakfast" {
			t.Errorf("name not trimmed: %q", cleaned.Name)
		}
		if !cleaned.IsFavorite {
			t.Errorf("is_favorite lost")
		}
		if len(cleaned.Items) != 2 {
			t.Errorf("items count = %d, want 2", len(cleaned.Items))
		}
	})

	t.Run("no items rejected", func(t *testing.T) {
		in := MealTemplateInput{Name: "Empty", Items: nil}
		if _, err := ValidateMealTemplateInput(in); err == "" {
			t.Fatal("expected error for empty items")
		}
	})

	t.Run("too many items rejected", func(t *testing.T) {
		items := make([]MealTemplateItemInput, MaxMealTemplateItems+1)
		for i := range items {
			items[i] = validItem
		}
		in := MealTemplateInput{Name: "Big", Items: items}
		if _, err := ValidateMealTemplateInput(in); err == "" {
			t.Fatal("expected error for too many items")
		}
	})

	t.Run("invalid name propagates", func(t *testing.T) {
		in := MealTemplateInput{Name: "   ", Items: []MealTemplateItemInput{validItem}}
		if _, err := ValidateMealTemplateInput(in); err == "" {
			t.Fatal("expected error for empty name")
		}
	})

	t.Run("invalid item propagates", func(t *testing.T) {
		bad := MealTemplateItemInput{Amount: 20000}
		in := MealTemplateInput{Name: "Bad", Items: []MealTemplateItemInput{bad}}
		if _, err := ValidateMealTemplateInput(in); err == "" {
			t.Fatal("expected error for out-of-range amount")
		}
	})
}
