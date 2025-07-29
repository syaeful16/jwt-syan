package main

import (
	"fmt"
	"time"

	jwt "github.com/syaeful16/jwt-syan"
)

func main() {
	secret := "your-256-bit-secret"

	claims := map[string]interface{}{
		"user_id": 12345,
		"role":    "admin",
		"email":   "user@example.com",
	}

	token, err := jwt.GenerateToken(secret, time.Minute*10, claims)
	if err != nil {
		panic(err)
	}

	fmt.Println("Generated Token:", token)

	parsedClaims, err := jwt.VerifyToken(secret, token)
	if err != nil {
		panic(err)
	}

	fmt.Println("Verified Claims:")
	for k, v := range parsedClaims {
		fmt.Printf("%s: %v\n", k, v)
	}
}
