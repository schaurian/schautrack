package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/service"
)

type AIHandler struct {
	Pool     *pgxpool.Pool
	Cfg      *config.Config
	Settings *database.SettingsCache
}

var imageDataRe = regexp.MustCompile(`^data:image/\w+;base64,`)

func (h *AIHandler) Estimate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Image   string `json:"image"`
		Context string `json:"context"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	if body.Image == "" || !imageDataRe.MatchString(body.Image) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid image data")
		return
	}
	if len(body.Image) > 14*1024*1024 {
		ErrorJSON(w, http.StatusRequestEntityTooLarge, "Image too large. Maximum size is 10MB.")
		return
	}

	user := middleware.GetCurrentUser(r)
	ctx := r.Context()

	globalProvider := h.Settings.GetEffectiveSetting(ctx, "ai_provider", os.Getenv("AI_PROVIDER"))
	globalKey := h.Settings.GetEffectiveSetting(ctx, "ai_key", os.Getenv("AI_KEY"))
	globalEndpoint := h.Settings.GetEffectiveSetting(ctx, "ai_endpoint", os.Getenv("AI_ENDPOINT"))
	globalModel := h.Settings.GetEffectiveSetting(ctx, "ai_model", os.Getenv("AI_MODEL"))

	// Priority: env/admin setting > user preference
	var provider string
	if globalProvider.Value != nil && *globalProvider.Value != "" {
		provider = *globalProvider.Value
	} else if user.PreferredAIProvider != "" {
		provider = user.PreferredAIProvider
	}
	if provider == "" {
		ErrorJSON(w, http.StatusBadRequest, "No AI provider configured.")
		return
	}
	if provider != "openai" && provider != "claude" && provider != "ollama" {
		ErrorJSON(w, http.StatusBadRequest, "Invalid provider")
		return
	}

	var apiKey string
	var endpoint string
	usingGlobalKey := false
	hasGlobalConfig := (globalKey.Value != nil && *globalKey.Value != "") ||
		(globalProvider.Value != nil && *globalProvider.Value != "")

	// When global AI config is set, ignore user's personal key/endpoint/model.
	// Users can only bring their own key when nothing is configured globally.
	if hasGlobalConfig {
		if globalKey.Value != nil {
			apiKey = *globalKey.Value
			usingGlobalKey = true
		}
		if globalEndpoint.Value != nil {
			endpoint = *globalEndpoint.Value
		}
	} else {
		if user.AIKey != nil && *user.AIKey != "" {
			apiKey = service.DecryptApiKey(*user.AIKey, h.Cfg.AIKeyEncryptSecret)
		}
	}

	if (provider == "openai" || provider == "claude") && apiKey == "" {
		ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("%s requires an API key.", provider))
		return
	}
	if provider == "ollama" {
		if endpoint == "" {
			ErrorJSON(w, http.StatusBadRequest, "Ollama requires AI_ENDPOINT to be configured.")
			return
		}
		if apiKey == "" {
			apiKey = "ollama"
			usingGlobalKey = true
		}
	}

	// Rate limiting
	usageToday, _ := service.GetAIUsageToday(ctx, h.Pool, user.ID)
	if usingGlobalKey {
		dailyLimitSetting := h.Settings.GetEffectiveSetting(ctx, "ai_daily_limit", os.Getenv("AI_DAILY_LIMIT"))
		if dailyLimitSetting.Value != nil {
			if limit, err := strconv.Atoi(*dailyLimitSetting.Value); err == nil && limit > 0 && usageToday >= limit {
				JSON(w, http.StatusTooManyRequests, map[string]any{
					"ok": false, "error": fmt.Sprintf("Daily limit reached (%d requests).", limit),
					"limitReached": true, "limit": limit, "used": usageToday,
				})
				return
			}
		}
	} else if user.AIDailyLimit != nil && *user.AIDailyLimit > 0 && usageToday >= *user.AIDailyLimit {
		JSON(w, http.StatusTooManyRequests, map[string]any{
			"ok": false, "error": fmt.Sprintf("Daily limit reached (%d requests).", *user.AIDailyLimit),
			"limitReached": true, "limit": *user.AIDailyLimit, "used": usageToday,
		})
		return
	}

	// Extract base64 data and media type
	base64Data := imageDataRe.ReplaceAllString(body.Image, "")
	mediaType := "image/jpeg"
	if m := regexp.MustCompile(`^data:(image/\w+);base64,`).FindStringSubmatch(body.Image); len(m) > 1 {
		mediaType = m[1]
	}

	// Model: global config > user preference
	var customModel string
	if hasGlobalConfig && globalModel.Value != nil && *globalModel.Value != "" {
		customModel = *globalModel.Value
	} else if !hasGlobalConfig && user.AIModel != nil && *user.AIModel != "" {
		customModel = *user.AIModel
	} else if globalModel.Value != nil {
		customModel = *globalModel.Value
	}
	if (provider == "openai" || provider == "claude") && customModel == "" {
		ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("%s requires AI_MODEL to be configured.", provider))
		return
	}

	// Build prompt
	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)
	enabledMacros := service.GetEnabledMacros(mu)
	requestedMacros := map[string]bool{"protein": true, "carbs": true, "fat": true}
	for _, k := range enabledMacros {
		requestedMacros[k] = true
	}
	var macroList []string
	for k := range requestedMacros {
		macroList = append(macroList, k)
	}

	contextHint := ""
	if body.Context != "" {
		contextHint = fmt.Sprintf("\n\nUser provided context: \"%s\"", body.Context)
	}
	prompt := fmt.Sprintf(`Analyze this food image and estimate the calories.%s

Also estimate these macros (in grams, as whole numbers): %s.

Respond in JSON format with these fields:
- calories: estimated total calories (number, must be > 0 if food is detected)
- food: brief description of the food items (string, max 50 chars)
- confidence: your confidence level ("high", "medium", or "low")
- macros: object with estimated values in grams for: %s

If you cannot identify any food in the image, set calories to 0 and food to "No food detected".

Only respond with the JSON object, no other text.`,
		contextHint, strings.Join(macroList, ", "), strings.Join(macroList, ", "))

	result, err := service.CallAIProvider(provider, apiKey, endpoint, base64Data, mediaType, prompt, customModel)
	if err != nil {
		if err.Error() == "NO_FOOD_DETECTED" {
			JSON(w, http.StatusBadRequest, map[string]any{
				"ok": false, "error": "Could not identify food in the image.",
				"code": "NO_FOOD",
			})
			return
		}
		ErrorJSON(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Increment usage
	if usingGlobalKey || (user.AIDailyLimit != nil && *user.AIDailyLimit > 0) {
		service.IncrementAIUsage(ctx, h.Pool, user.ID)
	}

	// Compute calories from macros
	p := result.Macros["protein"]
	c := result.Macros["carbs"]
	f := result.Macros["fat"]
	macroCalories := p*4 + c*4 + f*9
	calories := result.Calories
	if macroCalories > 0 {
		calories = macroCalories
	}

	// Filter macros to enabled only
	var macros map[string]any
	if len(enabledMacros) > 0 {
		macros = map[string]any{}
		for _, k := range enabledMacros {
			macros[k] = result.Macros[k]
		}
	}

	JSON(w, http.StatusOK, map[string]any{
		"ok": true, "calories": calories, "food": result.Food,
		"confidence": result.Confidence, "macros": macros,
	})
}

// Suppress unused imports
var _ = json.Marshal
