package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/config"
)

var barcodeRe = regexp.MustCompile(`^\d{8,13}$`)

func Barcode(cfg *config.Config) http.HandlerFunc {
	userAgent := fmt.Sprintf("Schautrack/%s (%s)", cfg.BuildVersion, orDefault(cfg.SupportEmail, "noreply@schautrack.app"))

	return func(w http.ResponseWriter, r *http.Request) {
		code := chi.URLParam(r, "code")
		if !barcodeRe.MatchString(code) {
			ErrorJSON(w, http.StatusBadRequest, "Invalid barcode format.")
			return
		}

		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequestWithContext(r.Context(), "GET",
			fmt.Sprintf("https://world.openfoodfacts.org/api/v2/product/%s?fields=product_name,nutriments,serving_quantity,serving_size", code), nil)
		if err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Failed to create request.")
			return
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := client.Do(req)
		if err != nil {
			ErrorJSON(w, http.StatusGatewayTimeout, "Food database request timed out.")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			ErrorJSON(w, http.StatusBadGateway, "Failed to reach food database.")
			return
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var data struct {
			Status  int `json:"status"`
			Product struct {
				Name            string         `json:"product_name"`
				Nutriments      map[string]any `json:"nutriments"`
				ServingSize     string         `json:"serving_size"`
				ServingQuantity any            `json:"serving_quantity"`
			} `json:"product"`
		}
		if err := json.Unmarshal(body, &data); err != nil || data.Status != 1 {
			JSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Product not found."})
			return
		}

		p := data.Product
		n := p.Nutriments
		round := func(v any) *int {
			switch val := v.(type) {
			case float64:
				r := int(math.Round(val))
				return &r
			}
			return nil
		}

		cals := round(n["energy-kcal_100g"])
		name := p.Name
		if name == "" {
			name = "Unknown product"
		}
		if len(name) > 120 {
			name = name[:120]
		}

		if cals == nil {
			JSON(w, http.StatusOK, map[string]any{
				"ok": true, "name": name, "caloriesPer100g": nil,
				"macrosPer100g": map[string]any{}, "servingSize": nil,
				"servingQuantity": nil, "note": "No calorie data available for this product.",
			})
			return
		}

		macroMap := map[string]string{
			"protein": "proteins_100g", "carbs": "carbohydrates_100g",
			"fat": "fat_100g", "fiber": "fiber_100g", "sugar": "sugars_100g",
		}
		macros := map[string]any{}
		for key, field := range macroMap {
			if v, ok := n[field].(float64); ok {
				macros[key] = math.Round(v*10) / 10
			}
		}

		var servingQuantity *float64
		if sq, ok := p.ServingQuantity.(float64); ok && sq > 0 {
			servingQuantity = &sq
		}

		var servingSize *string
		if p.ServingSize != "" {
			servingSize = &p.ServingSize
		}

		JSON(w, http.StatusOK, map[string]any{
			"ok": true, "name": name, "caloriesPer100g": cals,
			"macrosPer100g": macros, "servingSize": servingSize,
			"servingQuantity": servingQuantity,
		})
	}
}

func orDefault(s, def string) string {
	if s != "" {
		return s
	}
	return def
}
