package service

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type CaptchaResult struct {
	Text string `json:"-"`
	Data string `json:"data"` // SVG string
}

const captchaChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"

// GenerateCaptcha creates an SVG captcha image with random text.
func GenerateCaptcha() CaptchaResult {
	text := randomString(5)
	svg := renderCaptchaSVG(text)
	return CaptchaResult{Text: text, Data: svg}
}

// VerifyCaptcha compares the session answer with the user answer (case-insensitive).
// When CAPTCHA_BYPASS=true (E2E test mode), any non-empty answer passes.
func VerifyCaptcha(sessionAnswer, userAnswer string) bool {
	if sessionAnswer == "" || userAnswer == "" {
		return false
	}
	if os.Getenv("CAPTCHA_BYPASS") == "true" {
		return true
	}
	return strings.EqualFold(
		strings.TrimSpace(sessionAnswer),
		strings.TrimSpace(userAnswer),
	)
}

func randomString(n int) string {
	result := make([]byte, n)
	for i := range result {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(captchaChars))))
		result[i] = captchaChars[idx.Int64()]
	}
	return string(result)
}

func renderCaptchaSVG(text string) string {
	width := 150
	height := 50
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">`, width, height))
	sb.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="#1a1a2e"/>`, width, height))

	// Draw noise lines
	colors := []string{"#4a4a6a", "#3a3a5a", "#5a5a7a", "#2a2a4a"}
	for i := 0; i < 4; i++ {
		x1 := randInt(0, width)
		y1 := randInt(0, height)
		x2 := randInt(0, width)
		y2 := randInt(0, height)
		sb.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1"/>`,
			x1, y1, x2, y2, colors[i%len(colors)]))
	}

	// Draw characters
	charColors := []string{"#e2e8f0", "#93c5fd", "#c4b5fd", "#fca5a5", "#86efac"}
	spacing := width / (len(text) + 1)
	for i, ch := range text {
		x := spacing * (i + 1)
		y := 30 + randInt(-5, 5)
		fontSize := 24 + randInt(-4, 4)
		rotate := randInt(-15, 15)
		color := charColors[i%len(charColors)]
		sb.WriteString(fmt.Sprintf(
			`<text x="%d" y="%d" font-family="monospace" font-size="%d" fill="%s" transform="rotate(%d,%d,%d)" text-anchor="middle">%c</text>`,
			x, y, fontSize, color, rotate, x, y, ch))
	}

	sb.WriteString(`</svg>`)
	return sb.String()
}

func randInt(min, max int) int {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + int(n.Int64())
}
