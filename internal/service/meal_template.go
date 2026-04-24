package service

import (
	"strings"
	"unicode/utf8"
)

// Meal template limits.
const (
	MaxMealTemplates     = 200
	MaxMealTemplateItems = 50
	MaxTemplateNameRunes = 100
	MaxTemplateAmount    = 9999
	MaxTemplateMacro     = 999
)

// MealTemplateItemInput is the validated form of a single item in a template.
type MealTemplateItemInput struct {
	EntryName string         // trimmed; may be empty
	Amount    int            // calories; -9999..9999
	Macros    map[string]int // keys: protein/carbs/fat/fiber/sugar; each 0..999
}

// MealTemplateInput is the validated form of a template write.
type MealTemplateInput struct {
	Name       string
	IsFavorite bool
	Items      []MealTemplateItemInput
}

// ValidateMealTemplateName returns the trimmed name or an error message.
func ValidateMealTemplateName(raw string) (string, string) {
	n := strings.TrimSpace(raw)
	if n == "" {
		return "", "Name is required"
	}
	if utf8.RuneCountInString(n) > MaxTemplateNameRunes {
		return "", "Name is too long"
	}
	return n, ""
}

// ValidateMealTemplateAmount validates a template item amount.
func ValidateMealTemplateAmount(amount int) string {
	if amount < -MaxTemplateAmount || amount > MaxTemplateAmount {
		return "Calories must be between -9999 and 9999"
	}
	return ""
}

// ValidateMealTemplateMacro checks one macro value.
func ValidateMealTemplateMacro(value int) string {
	if value < 0 || value > MaxTemplateMacro {
		return "Macro values must be between 0 and 999"
	}
	return ""
}

// ValidateMealTemplateItem validates one item and returns a cleaned copy or an error message.
func ValidateMealTemplateItem(item MealTemplateItemInput) (MealTemplateItemInput, string) {
	cleaned := MealTemplateItemInput{
		EntryName: strings.TrimSpace(item.EntryName),
		Amount:    item.Amount,
		Macros:    map[string]int{},
	}
	if utf8.RuneCountInString(cleaned.EntryName) > 120 {
		// Match the 120-char cap used by calorie_entries (see entries_crud.CreateEntry).
		runes := []rune(cleaned.EntryName)
		cleaned.EntryName = string(runes[:120])
	}
	if msg := ValidateMealTemplateAmount(cleaned.Amount); msg != "" {
		return cleaned, msg
	}
	hasMacro := false
	for _, key := range MacroKeys {
		v, ok := item.Macros[key]
		if !ok {
			continue
		}
		if msg := ValidateMealTemplateMacro(v); msg != "" {
			return cleaned, msg
		}
		cleaned.Macros[key] = v
		hasMacro = true
	}
	if cleaned.Amount == 0 && !hasMacro && cleaned.EntryName == "" {
		return cleaned, "Each item needs a name, calories, or macros"
	}
	return cleaned, ""
}

// ValidateMealTemplateInput runs full validation on the template and all items.
// Returns the cleaned input or an error message.
func ValidateMealTemplateInput(in MealTemplateInput) (MealTemplateInput, string) {
	name, msg := ValidateMealTemplateName(in.Name)
	if msg != "" {
		return in, msg
	}
	if len(in.Items) == 0 {
		return in, "Template needs at least one item"
	}
	if len(in.Items) > MaxMealTemplateItems {
		return in, "Too many items (max 50)"
	}
	cleaned := MealTemplateInput{
		Name:       name,
		IsFavorite: in.IsFavorite,
		Items:      make([]MealTemplateItemInput, 0, len(in.Items)),
	}
	for _, item := range in.Items {
		ci, msg := ValidateMealTemplateItem(item)
		if msg != "" {
			return in, msg
		}
		cleaned.Items = append(cleaned.Items, ci)
	}
	return cleaned, ""
}
