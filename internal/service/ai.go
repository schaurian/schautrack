package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EncryptApiKey encrypts using AES-256-GCM, returning "iv:tag:ciphertext" in base64.
func EncryptApiKey(plaintext, secretHex string) string {
	if secretHex == "" || plaintext == "" {
		return ""
	}
	key, err := hexDecode(secretHex)
	if err != nil || len(key) != 32 {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	iv := make([]byte, aesGCM.NonceSize())
	rand.Read(iv)
	ciphertext := aesGCM.Seal(nil, iv, []byte(plaintext), nil)
	// GCM appends the tag to the ciphertext — split them
	tagSize := aesGCM.Overhead()
	encrypted := ciphertext[:len(ciphertext)-tagSize]
	tag := ciphertext[len(ciphertext)-tagSize:]
	return base64.StdEncoding.EncodeToString(iv) + ":" +
		base64.StdEncoding.EncodeToString(tag) + ":" +
		base64.StdEncoding.EncodeToString(encrypted)
}

// DecryptApiKey decrypts "iv:tag:ciphertext" base64 format.
func DecryptApiKey(ciphertext, secretHex string) string {
	if secretHex == "" || ciphertext == "" {
		return ""
	}
	parts := strings.SplitN(ciphertext, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	key, err := hexDecode(secretHex)
	if err != nil || len(key) != 32 {
		return ""
	}
	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	tag, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	encrypted, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	// Reconstruct ciphertext with tag appended (as GCM expects)
	combined := append(encrypted, tag...)
	plaintext, err := aesGCM.Open(nil, iv, combined, nil)
	if err != nil {
		return ""
	}
	return string(plaintext)
}

type AIResult struct {
	Calories   int               `json:"calories"`
	Food       string            `json:"food"`
	Confidence string            `json:"confidence"`
	Macros     map[string]int    `json:"macros"`
}

// CallAIProvider calls the configured AI provider with an image and prompt.
func CallAIProvider(provider, apiKey, endpoint, base64Data, mediaType, prompt, model string) (*AIResult, error) {
	timeout := 30 * time.Second
	if provider == "ollama" {
		timeout = 60 * time.Second
	}

	var reqBody []byte
	var url string
	var headers map[string]string

	switch provider {
	case "openai":
		if endpoint == "" {
			endpoint = "https://api.openai.com/v1"
		}
		url = strings.TrimRight(endpoint, "/") + "/chat/completions"
		headers = map[string]string{"Authorization": "Bearer " + apiKey}
		body := map[string]any{
			"model": model,
			"messages": []map[string]any{{
				"role": "user",
				"content": []map[string]any{
					{"type": "text", "text": prompt},
					{"type": "image_url", "image_url": map[string]any{"url": "data:" + mediaType + ";base64," + base64Data, "detail": "low"}},
				},
			}},
			"max_tokens": 1000,
		}
		reqBody, _ = json.Marshal(body)

	case "claude":
		if endpoint == "" {
			endpoint = "https://api.anthropic.com/v1"
		}
		url = strings.TrimRight(endpoint, "/") + "/messages"
		headers = map[string]string{
			"x-api-key":         apiKey,
			"anthropic-version": "2023-06-01",
		}
		body := map[string]any{
			"model":      model,
			"max_tokens": 1000,
			"messages": []map[string]any{{
				"role": "user",
				"content": []map[string]any{
					{"type": "image", "source": map[string]any{"type": "base64", "media_type": mediaType, "data": base64Data}},
					{"type": "text", "text": prompt},
				},
			}},
		}
		reqBody, _ = json.Marshal(body)

	case "ollama":
		url = strings.TrimRight(endpoint, "/") + "/chat/completions"
		headers = map[string]string{}
		if apiKey != "" && apiKey != "ollama" {
			headers["Authorization"] = "Bearer " + apiKey
		}
		body := map[string]any{
			"model": model,
			"messages": []map[string]any{{
				"role": "user",
				"content": []map[string]any{
					{"type": "text", "text": prompt},
					{"type": "image_url", "image_url": map[string]any{"url": "data:" + mediaType + ";base64," + base64Data}},
				},
			}},
		}
		reqBody, _ = json.Marshal(body)

	default:
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}

	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AI request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read AI response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("AI provider returned %d: %s", resp.StatusCode, string(respBody))
	}

	return parseAIResponse(provider, respBody)
}

func parseAIResponse(provider string, body []byte) (*AIResult, error) {
	var content string

	if provider == "claude" {
		var resp struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse Claude response")
		}
		if len(resp.Content) > 0 {
			content = resp.Content[0].Text
		}
	} else {
		var resp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse AI response")
		}
		if len(resp.Choices) > 0 {
			content = resp.Choices[0].Message.Content
		}
	}

	if content == "" {
		return nil, fmt.Errorf("empty AI response")
	}

	// Extract JSON from response
	content = strings.TrimSpace(content)
	if idx := strings.Index(content, "{"); idx >= 0 {
		if end := strings.LastIndex(content, "}"); end > idx {
			content = content[idx : end+1]
		}
	}

	var result AIResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse AI JSON: %w", err)
	}

	if result.Calories == 0 && result.Food == "No food detected" {
		return nil, fmt.Errorf("NO_FOOD_DETECTED")
	}

	return &result, nil
}

func GetAIUsageToday(ctx context.Context, pool *pgxpool.Pool, userID int) (int, error) {
	var count int
	err := pool.QueryRow(ctx,
		"SELECT COALESCE(request_count, 0) FROM ai_usage WHERE user_id = $1 AND usage_date = CURRENT_DATE",
		userID).Scan(&count)
	if err != nil {
		return 0, nil
	}
	return count, nil
}

func IncrementAIUsage(ctx context.Context, pool *pgxpool.Pool, userID int) {
	if _, err := pool.Exec(ctx, `
		INSERT INTO ai_usage (user_id, usage_date, request_count)
		VALUES ($1, CURRENT_DATE, 1)
		ON CONFLICT (user_id, usage_date) DO UPDATE SET request_count = ai_usage.request_count + 1`,
		userID); err != nil {
		slog.Error("failed to increment AI usage", "error", err, "userID", userID)
	}
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("invalid hex length")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi := unhex(s[2*i])
		lo := unhex(s[2*i+1])
		if hi == 0xFF || lo == 0xFF {
			return nil, fmt.Errorf("invalid hex char")
		}
		b[i] = hi<<4 | lo
	}
	return b, nil
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0xFF
}

