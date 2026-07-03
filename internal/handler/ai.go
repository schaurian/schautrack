package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

var (
	imageDataRe      = regexp.MustCompile(`^data:image/\w+;base64,`)
	imageMediaTypeRe = regexp.MustCompile(`^data:(image/\w+);base64,`)
)

const (
	// maxImageBase64Bytes is the largest accepted base64 image payload:
	// 14MB of base64 is roughly 10MB of raw image data (~1.37x blowup).
	maxImageBase64Bytes = 14 * 1024 * 1024
	// maxAIRequestBytes bounds the AI estimate JSON body. It must fit the
	// 14MB base64 image plus JSON overhead and matches the global 15MB
	// body cap set in cmd/server/main.go.
	maxAIRequestBytes = 15 << 20
)

// aiConfigInputs are the effective global (admin panel / env) and user-level
// AI settings feeding resolveAIConfig. UserKey must already be decrypted.
type aiConfigInputs struct {
	GlobalKey      string
	GlobalEndpoint string
	GlobalModel    string
	UserKey        string
	UserModel      string
}

// resolvedAIConfig is the credential set to use for an AI call.
type resolvedAIConfig struct {
	APIKey         string
	Endpoint       string
	Model          string
	UsingGlobalKey bool
}

// resolveAIConfig implements the documented three-tier key hierarchy: a
// global admin key takes precedence and pins endpoint and model to the global
// config; otherwise the user's personal key applies, with global settings
// filling any gaps. Only a global KEY disables personal keys — a provider-only
// global config must NOT block users from using their own saved key.
func resolveAIConfig(in aiConfigInputs) resolvedAIConfig {
	if in.GlobalKey != "" {
		return resolvedAIConfig{
			APIKey:         in.GlobalKey,
			Endpoint:       in.GlobalEndpoint,
			Model:          in.GlobalModel,
			UsingGlobalKey: true,
		}
	}
	model := in.UserModel
	if model == "" {
		model = in.GlobalModel
	}
	return resolvedAIConfig{
		APIKey:   in.UserKey,
		Endpoint: in.GlobalEndpoint,
		Model:    model,
	}
}

// aiClientErrorMessage maps an AI provider failure to a safe client-facing
// message. It must never include the raw upstream response body or the
// (possibly internal) endpoint URL — those are logged server-side instead.
func aiClientErrorMessage(err error) string {
	var provErr *service.AIProviderError
	if errors.As(err, &provErr) {
		switch provErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "The AI provider rejected the configured API key."
		case http.StatusTooManyRequests:
			return "The AI provider is rate limiting requests. Please try again later."
		}
	}
	return "AI estimation failed, please try again."
}

func settingValue(s database.SettingResult) string {
	if s.Value == nil {
		return ""
	}
	return *s.Value
}

func (h *AIHandler) Estimate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Image   string `json:"image"`
		Context string `json:"context"`
	}
	if err := ReadJSONLimit(w, r, &body, maxAIRequestBytes); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			ErrorJSON(w, http.StatusRequestEntityTooLarge, "Image too large. Maximum size is 10MB.")
			return
		}
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	if body.Image == "" || !imageDataRe.MatchString(body.Image) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid image data")
		return
	}
	if len(body.Image) > maxImageBase64Bytes {
		ErrorJSON(w, http.StatusRequestEntityTooLarge, "Image too large. Maximum size is 10MB.")
		return
	}

	user := middleware.GetCurrentUser(r)
	ctx := r.Context()

	globalProvider := h.Settings.GetEffectiveSetting(ctx, "ai_provider", os.Getenv("AI_PROVIDER"))
	globalKey := h.Settings.GetEffectiveSetting(ctx, "ai_key", os.Getenv("AI_KEY"))
	globalEndpoint := h.Settings.GetEffectiveSetting(ctx, "ai_endpoint", os.Getenv("AI_ENDPOINT"))
	globalModel := h.Settings.GetEffectiveSetting(ctx, "ai_model", os.Getenv("AI_MODEL"))

	// Provider priority: env/admin setting > user preference
	var provider string
	if globalProvider.Value != nil && *globalProvider.Value != "" {
		provider = *globalProvider.Value
	} else if user.PreferredAIProvider != nil && *user.PreferredAIProvider != "" {
		provider = *user.PreferredAIProvider
	}
	if provider == "" {
		ErrorJSON(w, http.StatusBadRequest, "No AI provider configured.")
		return
	}
	if provider != "openai" && provider != "claude" && provider != "ollama" {
		ErrorJSON(w, http.StatusBadRequest, "Invalid provider")
		return
	}

	// Only decrypt the personal key when no global key overrides it.
	globalKeyVal := settingValue(globalKey)
	var userKey string
	if globalKeyVal == "" && user.AIKey != nil && *user.AIKey != "" {
		userKey = service.DecryptApiKey(*user.AIKey, h.Cfg.AIKeyEncryptSecret)
	}

	cfg := resolveAIConfig(aiConfigInputs{
		GlobalKey:      globalKeyVal,
		GlobalEndpoint: settingValue(globalEndpoint),
		GlobalModel:    settingValue(globalModel),
		UserKey:        userKey,
		UserModel:      derefString(user.AIModel),
	})
	apiKey, endpoint, customModel, usingGlobalKey := cfg.APIKey, cfg.Endpoint, cfg.Model, cfg.UsingGlobalKey

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
	if (provider == "openai" || provider == "claude") && customModel == "" {
		ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("%s requires AI_MODEL to be configured.", provider))
		return
	}

	// Extract base64 data and media type
	base64Data := imageDataRe.ReplaceAllString(body.Image, "")
	mediaType := "image/jpeg"
	if m := imageMediaTypeRe.FindStringSubmatch(body.Image); len(m) > 1 {
		mediaType = m[1]
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

	// Resolve the applicable daily limit (0 = unlimited).
	dailyLimit := 0
	if usingGlobalKey {
		dailyLimitSetting := h.Settings.GetEffectiveSetting(ctx, "ai_daily_limit", os.Getenv("AI_DAILY_LIMIT"))
		if dailyLimitSetting.Value != nil {
			if limit, err := strconv.Atoi(*dailyLimitSetting.Value); err == nil && limit > 0 {
				dailyLimit = limit
			}
		}
	} else if user.AIDailyLimit != nil && *user.AIDailyLimit > 0 {
		dailyLimit = *user.AIDailyLimit
	}

	// Reserve the usage slot atomically BEFORE calling the provider so
	// concurrent requests cannot all pass a stale pre-increment check.
	// A reservation that yields no estimation is released again below.
	trackUsage := usingGlobalKey || (user.AIDailyLimit != nil && *user.AIDailyLimit > 0)
	reserved := false
	if trackUsage {
		count, err := service.ReserveAIUsage(ctx, h.Pool, user.ID)
		if err != nil {
			// Fail closed: without a usage count we must not hand out
			// unmetered AI calls.
			slog.Error("failed to reserve AI usage", "error", err, "userID", user.ID)
			ErrorJSON(w, http.StatusInternalServerError, "AI estimation failed, please try again.")
			return
		}
		reserved = true
		if dailyLimit > 0 && count > dailyLimit {
			service.ReleaseAIUsage(context.WithoutCancel(ctx), h.Pool, user.ID)
			JSON(w, http.StatusTooManyRequests, map[string]any{
				"ok": false, "error": fmt.Sprintf("Daily limit reached (%d requests).", dailyLimit),
				"limitReached": true, "limit": dailyLimit, "used": count - 1,
			})
			return
		}
	}

	result, err := service.CallAIProvider(ctx, provider, apiKey, endpoint, base64Data, mediaType, prompt, customModel)
	if err != nil {
		if reserved {
			// No estimation happened — hand the slot back. Use a
			// non-cancelable context so an aborted request still releases.
			service.ReleaseAIUsage(context.WithoutCancel(ctx), h.Pool, user.ID)
		}
		if err.Error() == "NO_FOOD_DETECTED" {
			JSON(w, http.StatusBadRequest, map[string]any{
				"ok": false, "error": "Could not identify food in the image.",
				"code": "NO_FOOD",
			})
			return
		}
		slog.Error("AI estimation failed", "provider", provider, "userID", user.ID, "error", err)
		ErrorJSON(w, http.StatusInternalServerError, aiClientErrorMessage(err))
		return
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

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
