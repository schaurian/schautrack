package handler

import (
	"schautrack/internal/service"
	"schautrack/internal/session"
)

// Session keys holding the answer to the captcha each flow has in flight.
//
// Every flow owns its own key. They used to share one ("captchaAnswer"), so a
// challenge issued by one flow gated another: abandoning registration at its
// captcha step left an answer in the session, and the next login — which had
// shown no captcha at all — was rejected with "Invalid captcha." and then
// demanded one. The reverse also held: a captcha solved for login or for the
// forgot-password page satisfied the registration step. A flow must only
// require, and only accept, a challenge it issued itself.
const (
	loginCaptchaKey    = "loginCaptchaAnswer"
	registerCaptchaKey = "registerCaptchaAnswer"
	resetCaptchaKey    = "resetCaptchaAnswer"
	resendCaptchaKey   = "resendCaptchaAnswer"
)

// issueCaptcha generates a challenge and stores its answer under the given
// flow's session key, replacing that flow's previous challenge only.
func issueCaptcha(sess *session.Session, key string) service.CaptchaResult {
	c := service.GenerateCaptcha()
	sess.Set(key, c.Text)
	return c
}
