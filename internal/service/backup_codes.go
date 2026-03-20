package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
)

const BackupCodeCount = 8

// GenerateBackupCodes generates 8 random 8-digit codes.
func GenerateBackupCodes() []string {
	codes := make([]string, BackupCodeCount)
	for i := range codes {
		n, _ := rand.Int(rand.Reader, big.NewInt(90000000))
		codes[i] = fmt.Sprintf("%08d", n.Int64()+10000000)
	}
	return codes
}

// HashBackupCode returns the SHA-256 hash of a backup code.
func HashBackupCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// VerifyBackupCode compares a code against a hash using constant-time comparison.
func VerifyBackupCode(code, hash string) bool {
	codeHash := HashBackupCode(code)
	return subtle.ConstantTimeCompare([]byte(codeHash), []byte(hash)) == 1
}
