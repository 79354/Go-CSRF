package models

import(
	"time"
	"csrf/randomstrings"
	jwt "github.com/golang-jwt/jwt"
)

type User struct{
	Username, PasswordHash, role string
}

type TokenClaims struct{
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const(
	RefreshTokenValidTime = time.Hour*72
	AuthTokenValidTime    = time.Minute*15
)

func GenerateCSRFSecret()(string, error){
	return randomstrings.GenerateRandomString(32)
}