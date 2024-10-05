package jwt

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func CreateAccessToken(login string) (string, error) {
	claims := jwt.MapClaims{
		"login": login,
		"exp":   time.Now().Add(time.Minute * 15).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("SECRET")))
}

func CreateRefreshToken(login string) (string, error) {
	claims := jwt.MapClaims{
		"login": login,
		"exp":   time.Now().Add(time.Hour * 24 * 7).Unix(), // 7 дней
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("SECRET")))
}

func ValidateToken(tokenString string, secret string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
}

func GetClaims(token *jwt.Token) (jwt.MapClaims, error) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}
