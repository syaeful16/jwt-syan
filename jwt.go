package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken(secretKey string, duration time.Duration, customClaims map[string]interface{}) (string, error) {
	claims := jwt.MapClaims{}
	for k, v := range customClaims {
		claims[k] = v
	}

	timeNow := time.Now()

	claims["exp"] = timeNow.Add(duration).Unix()
	claims["iat"] = timeNow.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secretKey))
}

func VerifyToken(secretKey string, tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrInvalidKey
	}

	return claims, nil
}
