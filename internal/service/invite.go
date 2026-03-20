package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateInviteCode returns a random URL-safe string.
func GenerateInviteCode() string {
	b := make([]byte, 18)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// SendInviteEmail sends an invitation email to the given address.
func (es *EmailService) SendInviteEmail(email, code, baseURL string) error {
	inviteLink := fmt.Sprintf("%s/register?invite=%s", baseURL, code)
	subject := "You're Invited to Schautrack"
	text := fmt.Sprintf("You've been invited to join Schautrack!\n\nUse this link to register:\n%s\n\nOr enter this invite code manually: %s", inviteLink, code)
	html := fmt.Sprintf(`<p>You've been invited to join Schautrack!</p><p><a href="%s">Click here to register</a></p><p>Or enter this invite code manually: <strong>%s</strong></p>`, inviteLink, code)
	return es.SendEmail(email, subject, text, html)
}
