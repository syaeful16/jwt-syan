package jwt_test

import (
	"testing"
	"time"

	jwtlib "github.com/syaeful16/jwt-syan"
)

const secretKey = "test-secret"

func TestGenerateAndVerifyToken(t *testing.T) {
	claims := map[string]interface{}{
		"user_id": "12345",
		"role":    "admin",
		"email":   "user@example.com",
	}

	token, err := jwtlib.GenerateToken(secretKey, time.Minute*5, claims)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	parsedClaims, err := jwtlib.VerifyToken(secretKey, token)
	if err != nil {
		t.Fatalf("Failed to verify token: %v", err)
	}

	for k, v := range claims {
		if parsedClaims[k] != v {
			t.Errorf("Expected claim %q to be %v, got %v", k, v, parsedClaims[k])
		}
	}
}

func TestExpiredToken(t *testing.T) {
	claims := map[string]interface{}{
		"role": "expired",
	}

	token, err := jwtlib.GenerateToken(secretKey, -1*time.Minute, claims) // expired
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	_, err = jwtlib.VerifyToken(secretKey, token)
	if err == nil {
		t.Error("Expected error for expired token, got nil")
	}
}

func TestInvalidSignature(t *testing.T) {
	claims := map[string]interface{}{
		"admin": true,
	}

	token, err := jwtlib.GenerateToken("wrong-secret", time.Minute*5, claims)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = jwtlib.VerifyToken(secretKey, token) // verifying with different secret
	if err == nil {
		t.Error("Expected error for invalid signature, got nil")
	}
}

func TestMalformedToken(t *testing.T) {
	_, err := jwtlib.VerifyToken(secretKey, "not.a.valid.token")
	if err == nil {
		t.Error("Expected error for malformed token, got nil")
	}
}
