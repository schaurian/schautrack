package service

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
)

type CaptchaResult struct {
	// Text is the session secret. It bundles both challenge answers as
	// "<svgAnswer>|<altAnswer>" so either the visual or the non-visual answer
	// is accepted. It is never sent to the client.
	Text string `json:"-"`
	Data string `json:"data"` // SVG string (visual challenge)
	// Question is a plain-text arithmetic challenge shown alongside the SVG as
	// a non-visual alternative for users who cannot see the image (WCAG 1.1.1).
	Question string `json:"question"`
}

const captchaChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"

// numberWords maps small integers to their English spelling so the non-visual
// challenge reads naturally to a screen reader ("What is four plus three?").
var numberWords = []string{
	"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
	"ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
	"seventeen", "eighteen",
}

func numberWord(n int) string {
	if n >= 0 && n < len(numberWords) {
		return numberWords[n]
	}
	return strconv.Itoa(n)
}

// GenerateCaptcha creates a visual SVG captcha plus a non-visual text challenge.
// Both answers are bundled into the session secret (Text) and VerifyCaptcha
// accepts either, so blind users who cannot read the distorted SVG can solve
// the spoken-word arithmetic question instead.
func GenerateCaptcha() CaptchaResult {
	text := randomString(5)
	svg := renderCaptchaSVG(text)
	question, altAnswer := generateAltChallenge()
	return CaptchaResult{
		Text:     text + "|" + altAnswer,
		Data:     svg,
		Question: question,
	}
}

// generateAltChallenge builds a simple "What is A plus B?" question with the
// operands spelled out, returning the question text and the numeric answer.
func generateAltChallenge() (question, answer string) {
	a := randInt(1, 10)
	b := randInt(1, 10)
	question = fmt.Sprintf("What is %s plus %s?", numberWord(a), numberWord(b))
	return question, strconv.Itoa(a + b)
}

// VerifyCaptcha reports whether userAnswer solves either challenge encoded in
// the session secret: the visual SVG text (case-insensitive) or the non-visual
// arithmetic answer (accepted as digits "7" or the spelled word "seven").
// When CAPTCHA_BYPASS=true (E2E test mode), any non-empty answer passes.
func VerifyCaptcha(sessionAnswer, userAnswer string) bool {
	if sessionAnswer == "" || userAnswer == "" {
		return false
	}
	if os.Getenv("CAPTCHA_BYPASS") == "true" {
		return true
	}
	svgAnswer, altAnswer := splitCaptchaToken(sessionAnswer)
	if strings.EqualFold(strings.TrimSpace(svgAnswer), strings.TrimSpace(userAnswer)) {
		return true
	}
	return altAnswer != "" && matchesAltAnswer(altAnswer, userAnswer)
}

// splitCaptchaToken separates the bundled session secret into its visual and
// non-visual answers. Tokens issued before the non-visual challenge existed
// carry no separator and are treated as visual-only.
func splitCaptchaToken(token string) (svgAnswer, altAnswer string) {
	if i := strings.IndexByte(token, '|'); i >= 0 {
		return token[:i], token[i+1:]
	}
	return token, ""
}

// matchesAltAnswer accepts the arithmetic answer either as digits ("7") or as
// the spelled-out word ("seven"), case-insensitively.
func matchesAltAnswer(altAnswer, userAnswer string) bool {
	u := strings.TrimSpace(userAnswer)
	if u == "" {
		return false
	}
	if u == strings.TrimSpace(altAnswer) {
		return true
	}
	if n, err := strconv.Atoi(strings.TrimSpace(altAnswer)); err == nil {
		return strings.EqualFold(u, numberWord(n))
	}
	return false
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
